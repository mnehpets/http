package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
	"golang.org/x/oauth2"
)

func TestAuthHandler_Login(t *testing.T) {
	// Setup keys and state manager
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()

	// Setup fake provider endpoint
	// Setup fake provider endpoint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock Token Endpoint
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "mock_access_token", "token_type": "Bearer", "expires_in": 3600}`))
			return
		}
		// Mock Auth Endpoint (just for URL construction check)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conf := &oauth2.Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  srv.URL + "/auth",
			TokenURL: srv.URL + "/token",
		},
		Scopes: []string{"openid"},
	}
	reg.RegisterOAuth2Provider("test-provider", conf)

	// Create Handler
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Test Login Redirect
	w := httptest.NewRecorder()
	// Base64url encode app_data since it's now expected to be base64url encoded
	appDataValue := base64.RawURLEncoding.EncodeToString([]byte("123"))
	r := httptest.NewRequest("GET", "/auth/login/test-provider?next=/dashboard&app_data="+appDataValue, nil)
	h.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, srv.URL+"/auth") {
		t.Errorf("expected redirect to provider auth, got %s", loc)
	}
	if !strings.Contains(loc, "state=") {
		t.Error("expected state param")
	}

	// Capture cookie for callback
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no state cookie set")
	}

	// Extract state from location
	// Location: .../auth?client_id=...&state=XXX&...
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")

	// 2. Test Callback
	// Mock result endpoint
	var resultCalled bool
	h.result = func(w http.ResponseWriter, r *http.Request, result *AuthResult) (endpoint.Renderer, error) {
		resultCalled = true
		if result.ProviderID != "test-provider" {
			t.Errorf("expected provider test-provider, got %s", result.ProviderID)
		}
		if result.Error != nil {
			t.Errorf("expected no error, got %v", result.Error)
		}
		if string(result.AuthParams.AppData) != "123" {
			t.Errorf("expected app_data 123, got %s", string(result.AuthParams.AppData))
		}
		if result.Token.AccessToken != "mock_access_token" {
			t.Errorf("expected access token mock_access_token, got %s", result.Token.AccessToken)
		}
		return &endpoint.RedirectRenderer{URL: "/dashboard", Status: http.StatusFound}, nil
	}

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/test-provider?code=mock_code&state="+state, nil)
	r2.AddCookie(cookies[0]) // Add state cookie
	h.ServeHTTP(w2, r2)

	if w2.Result().StatusCode != http.StatusFound {
		t.Errorf("callback failed: %v", w2.Result().Status)
	}
	if !resultCalled {
		t.Error("result endpoint not called")
	}
}

func TestAuthHandler_OpenRedirect(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider", TokenURL: "http://provider"}})

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		nextURL string
	}{
		{"protocol-relative", "//evil.com"},
		{"absolute http", "http://evil.com"},
		{"absolute https", "https://evil.com"},
		{"scheme attack", "javascript:alert(1)"},
		{"backslash", "/\\evil.com"},
		{"empty", ""},
		{"no leading slash", "evil.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/auth/login/test?next_url="+url.QueryEscape(tc.nextURL), nil)
			h.ServeHTTP(w, r)

			c := w.Result().Cookies()[0]
			var states AuthStateMap
			_ = cookie.Decode(c, &states)
			for _, s := range states {
				if s.AuthParams.NextURL != "/" {
					t.Errorf("next_url %q: expected NextURL sanitized to '/', got %q", tc.nextURL, s.AuthParams.NextURL)
				}
			}
		})
	}
}

func TestAuthHandler_Callback_Errors(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{}) // Register dummy provider
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Provider Error
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/test?error=access_denied&error_description=user_denied", nil)
	h.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for provider error, got %d", w.Result().StatusCode)
	}

	// 2. Invalid State (missing cookie)
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/test?state=missing", nil)
	h.ServeHTTP(w2, r2)
	if w2.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid state, got %d", w2.Result().StatusCode)
	}
}

func TestAuthHandler_ProviderError(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})

	var capturedResult *AuthResult
	resultEndpoint := func(w http.ResponseWriter, r *http.Request, result *AuthResult) (endpoint.Renderer, error) {
		capturedResult = result
		return &endpoint.NoContentRenderer{Status: http.StatusBadRequest}, nil
	}

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth", WithResultEndpoint(resultEndpoint))
	if err != nil {
		t.Fatal(err)
	}

	// Set up valid state in cookie
	authState := AuthState{
		AuthParams: AuthParams{NextURL: "/"},
	}
	c, _ := cookie.Encode(AuthStateMap{"test_state": authState}, 3600)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/test?state=test_state&error=access_denied&error_description=user_denied", nil)
	r.AddCookie(c)
	h.ServeHTTP(w, r)

	if capturedResult == nil {
		t.Fatal("expected result endpoint to be called")
	}

	if capturedResult.Error == nil {
		t.Fatal("expected error in result")
	}

	// Check that AuthParams was passed even for error case
	if capturedResult.AuthParams == nil {
		t.Fatal("expected AuthParams in result for error case")
	}
	if capturedResult.AuthParams.NextURL != "/" {
		t.Errorf("expected NextURL to be '/', got %q", capturedResult.AuthParams.NextURL)
	}

	var providerErr *ProviderError
	if !errors.As(capturedResult.Error, &providerErr) {
		t.Fatalf("expected error to be of type *ProviderError, got %T", capturedResult.Error)
	}

	if providerErr.Code != "access_denied" {
		t.Errorf("expected code access_denied, got %s", providerErr.Code)
	}
	if providerErr.Description != "user_denied" {
		t.Errorf("expected description user_denied, got %s", providerErr.Description)
	}
}

func TestAuthHandler_StateEviction(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider"}})

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	// Initiate 4 logins
	var cookies []*http.Cookie
	lastCookie := &http.Cookie{}

	for i := range 4 {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/login/test", nil)
		if i > 0 {
			r.AddCookie(lastCookie)
		}
		h.ServeHTTP(w, r)
		lastCookie = w.Result().Cookies()[0]
		cookies = append(cookies, lastCookie)
	}

	// Decode final cookie
	var states AuthStateMap
	_ = cookie.Decode(lastCookie, &states)
	if len(states) != 3 {
		t.Errorf("expected 3 states (max), got %d", len(states))
	}
}

func TestAuthHandler_StateExpiry(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	// Manually create expired state in cookie
	expiredState := AuthState{
		AuthParams: AuthParams{NextURL: "/"},
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}
	states := AuthStateMap{"expired_state": expiredState}
	c, _ := cookie.Encode(states, 3600)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/test?state=expired_state&code=123", nil)
	r.AddCookie(c)

	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for expired state, got %d", w.Result().StatusCode)
	}
}

func TestAuthHandler_OIDCNonceMismatch(t *testing.T) {
	// 1. Setup Mock OIDC Server
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, (&jose.SignerOptions{}).WithType("JWT"))

	var oidcServer *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := oidcServer.URL
		if r.URL.Path == "/.well-known/openid-configuration" {
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"jwks_uri":                              issuer + "/keys",
				"authorization_endpoint":                issuer + "/auth",
				"token_endpoint":                        issuer + "/token",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
			return
		}
		if r.URL.Path == "/keys" {
			jwk := jose.JSONWebKey{Key: &privKey.PublicKey, Use: "sig", Algorithm: "RS256", KeyID: "test-key"}
			jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
			json.NewEncoder(w).Encode(jwks)
			return
		}
		if r.URL.Path == "/token" {
			// Return ID Token with WRONG nonce
			claims := jwt.Claims{
				Subject:   "user123",
				Issuer:    issuer,
				Audience:  jwt.Audience{"client-id"},
				Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			}
			// Add nonce
			rawJWT, _ := jwt.Signed(signer).Claims(claims).Claims(map[string]any{"nonce": "WRONG_NONCE"}).Serialize()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "token",
				"id_token":     rawJWT,
				"token_type":   "Bearer",
			})
			return
		}
	})
	oidcServer = httptest.NewServer(handler)
	defer oidcServer.Close()

	ctx := context.Background()
	reg := NewRegistry()
	err := reg.RegisterOIDCProvider(ctx, "oidc-test", oidcServer.URL, "client-id", "secret", []string{"openid"}, "http://example.com/callback")
	if err != nil {
		t.Fatalf("failed to register OIDC provider: %v", err)
	}

	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Setup Cookie with expected nonce
	expectedNonce := "EXPECTED_NONCE"
	state := "state123"
	authState := AuthState{
		AuthParams: AuthParams{NextURL: "/"},
		Nonce:      expectedNonce,
	}
	c, _ := cookie.Encode(AuthStateMap{state: authState}, 3600)

	// 2. Call Callback
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/oidc-test?state="+state+"&code=foo", nil)
	r.AddCookie(c)

	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for nonce mismatch, got %d", w.Result().StatusCode)
	}
	body := w.Body.String()
	if !strings.Contains(body, "nonce mismatch") {
		t.Errorf("expected 'nonce mismatch' error, got %s", body)
	}
}

func TestAuthHandler_PreAuthFailure(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})

	// Pre-auth hook that fails
	failPreAuth := func(ctx context.Context, w http.ResponseWriter, r *http.Request, params AuthParams) (AuthParams, error) {
		return params, endpoint.Error(http.StatusForbidden, "blocked by pre-auth", nil)
	}

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth", WithPreAuthHook(failPreAuth))
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test", nil)
	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestAuthHandler_SuccessHookFailure(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()

	// Mock Provider
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "token", "token_type": "Bearer"}`))
			return
		}
	}))
	defer srv.Close()

	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token"}})

	// Result endpoint that fails for success case
	resultEndpoint := func(w http.ResponseWriter, r *http.Request, result *AuthResult) (endpoint.Renderer, error) {
		if result.Error != nil {
			return nil, result.Error
		}
		return nil, endpoint.Error(http.StatusTeapot, "simulated failure", nil)
	}

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth", WithResultEndpoint(resultEndpoint))
	if err != nil {
		t.Fatal(err)
	}

	// Setup valid state
	state := "state123"
	authState := AuthState{
		AuthParams: AuthParams{NextURL: "/"},
	}
	c, _ := cookie.Encode(AuthStateMap{state: authState}, 3600)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/callback/test?state="+state+"&code=foo", nil)
	r.AddCookie(c)

	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusTeapot {
		t.Errorf("expected 418, got %d", w.Result().StatusCode)
	}
}

func TestAuthHandler_PKCEGeneration(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	// PKCE enabled by default in RegisterOAuth2Provider
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth"}})

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test", nil)
	h.ServeHTTP(w, r)

	loc := w.Result().Header.Get("Location")
	if !strings.Contains(loc, "code_challenge=") {
		t.Error("expected code_challenge in auth URL")
	}
	if !strings.Contains(loc, "code_challenge_method=S256") {
		t.Error("expected S256 challenge method")
	}

	// Verify Verifier is stored in cookie
	c := w.Result().Cookies()[0]
	var states AuthStateMap
	_ = cookie.Decode(c, &states)
	for _, s := range states {
		if s.PKCEVerifier == "" {
			t.Error("expected PKCE verifier stored in state")
		}
	}
}

func TestAuthHandler_CookieSecurity(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}

	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})
	// Set non-default values to ensure options are being applied
	h, err := NewHandler(reg, "auth-state", "1", keys, "https://example.com", "/auth",
		WithCookieOptions(
			middleware.WithPath("/custom-path"),
			middleware.WithDomain("custom.example.com"),
			middleware.WithSecure(false),
			middleware.WithSameSite(http.SameSiteStrictMode),
		),
	)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test", nil)
	h.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookies")
	}
	c := cookies[0]

	if c.Path != "/custom-path" {
		t.Errorf("expected Path=/custom-path, got %q", c.Path)
	}
	if c.Domain != "custom.example.com" {
		t.Errorf("expected Domain=custom.example.com, got %q", c.Domain)
	}
	if c.Secure {
		t.Error("expected non-Secure cookie")
	}
	if !c.HttpOnly {
		t.Error("expected HttpOnly cookie")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("expected SameSite=Strict")
	}
}

func TestAuthHandler_UnknownProvider(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Login with unknown provider
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/unknown", nil)
	h.ServeHTTP(w, r)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("login: expected 404 for unknown provider, got %d", w.Result().StatusCode)
	}

	// 2. Callback with unknown provider
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/unknown?state=foo&code=bar", nil)
	h.ServeHTTP(w2, r2)
	// Note: It might fail validation before provider check if we're not careful,
	// but provider check should happen early.
	// Actually, looking at handler.go:
	// handleCallback checks Error param first, then Provider existence.
	if w2.Result().StatusCode != http.StatusNotFound {
		t.Errorf("callback: expected 404 for unknown provider, got %d", w2.Result().StatusCode)
	}
}

func TestAuthHandler_AppDataPersistence(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token": "token", "token_type": "Bearer"}`))
	}))
	defer srv.Close()

	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: srv.URL}})

	var capturedResult *AuthResult
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth", WithResultEndpoint(func(w http.ResponseWriter, r *http.Request, result *AuthResult) (endpoint.Renderer, error) {
		capturedResult = result
		return &endpoint.RedirectRenderer{URL: "/"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	// Complex app data
	complexData := "user_id=123&role=admin with spaces/and/slashes"

	// 1. Login
	w := httptest.NewRecorder()
	// Base64url encode the app_data in the query since it's now expected to be base64url encoded
	u := url.Values{}
	u.Set("app_data", base64.RawURLEncoding.EncodeToString([]byte(complexData)))
	r := httptest.NewRequest("GET", "/auth/login/test?"+u.Encode(), nil)
	h.ServeHTTP(w, r)

	// Extract state
	c := w.Result().Cookies()[0]
	loc := w.Result().Header.Get("Location")
	locURL, _ := url.Parse(loc)
	state := locURL.Query().Get("state")

	// 2. Callback
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/test?code=foo&state="+state, nil)
	r2.AddCookie(c)
	h.ServeHTTP(w2, r2)

	if capturedResult == nil {
		t.Fatal("expected result endpoint to be called")
	}
	if string(capturedResult.AuthParams.AppData) != complexData {
		t.Errorf("AppData mismatch.\nExpected: %q\nGot:      %q", complexData, string(capturedResult.AuthParams.AppData))
	}
}

func TestAuthHandler_PKCE_Disabled(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()

	conf := &oauth2.Config{
		Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth", TokenURL: "http://provider/token"},
	}
	p := NewProvider("no-pkce", conf, nil, nil)
	p.SetPKCE(false)
	reg.Register(p)

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/no-pkce", nil)
	h.ServeHTTP(w, r)

	loc := w.Result().Header.Get("Location")
	if strings.Contains(loc, "code_challenge") {
		t.Error("expected no code_challenge when PKCE is disabled")
	}
}

// TestAuthHandler_Login_StateKey_SkipsPreAuthHook verifies that when a valid state_key is
// provided to the login endpoint, the preAuthHook is not invoked (case 1). The params were
// already validated when the state was saved; running the hook again on the same request
// would be incorrect and could break flows where the hook uses request-scoped context.
func TestAuthHandler_Login_StateKey_SkipsPreAuthHook(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth"}})

	// A hook that always fails — if the login handler calls it, the request will fail.
	failHook := func(ctx context.Context, w http.ResponseWriter, r *http.Request, params AuthParams) (AuthParams, error) {
		return params, errors.New("preAuthHook must not be called for a pre-saved state")
	}
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth", WithPreAuthHook(failHook))
	if err != nil {
		t.Fatal(err)
	}

	// Inject a pre-saved state directly into the cookie, bypassing PrepareAuth (which would
	// also invoke the hook). This simulates a state that was already validated and stored.
	stateKey := "pre-saved-key"
	c, _ := cookie.Encode(AuthStateMap{stateKey: AuthState{
		AuthParams: AuthParams{NextURL: "/protected"},
		ExpiresAt:  time.Now().Add(time.Hour),
	}}, 3600)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test?state_key="+stateKey, nil)
	r.AddCookie(c)
	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusFound {
		t.Errorf("expected 302 (preAuthHook should not have been called), got %d: %s",
			w.Result().StatusCode, w.Body.String())
	}
}

// TestAuthHandler_Callback_StateReplay verifies that a state is consumed after a successful
// callback. A second callback using the updated response cookie (with the state removed)
// must fail, preventing replay attacks.
func TestAuthHandler_Callback_StateReplay(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "tok", "token_type": "Bearer"}`))
		}
	}))
	defer srv.Close()

	reg.RegisterOAuth2Provider("test", &oauth2.Config{
		Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token"},
	})
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	stateKey := "state123"
	c, _ := cookie.Encode(AuthStateMap{stateKey: AuthState{
		AuthParams: AuthParams{NextURL: "/"},
		ExpiresAt:  time.Now().Add(time.Hour),
	}}, 3600)

	// First callback — succeeds and consumes the state.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/auth/callback/test?code=foo&state="+stateKey, nil)
	r1.AddCookie(c)
	h.ServeHTTP(w1, r1)

	if w1.Result().StatusCode != http.StatusFound {
		t.Fatalf("first callback: expected 302, got %d", w1.Result().StatusCode)
	}

	// Second callback: simulate browser behaviour — forward the response cookies from the
	// first callback (which have the state removed or the cookie cleared entirely).
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/test?code=foo&state="+stateKey, nil)
	for _, rc := range w1.Result().Cookies() {
		if rc.MaxAge >= 0 { // skip "delete" cookies (MaxAge == -1)
			r2.AddCookie(rc)
		}
	}
	h.ServeHTTP(w2, r2)

	if w2.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("replay: expected 400, got %d", w2.Result().StatusCode)
	}
}

// TestAuthHandler_OIDC_Success verifies the happy path for an OIDC provider:
// login generates a nonce, the provider returns a token with the matching nonce,
// and the callback succeeds with a populated IDToken in the result.
func TestAuthHandler_OIDC_Success(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, (&jose.SignerOptions{}).WithType("JWT"))

	// nonce is populated after the login step so the mock token endpoint can use it.
	var nonce string

	var oidcServer *httptest.Server
	oidcServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := oidcServer.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer,
				"jwks_uri":                              issuer + "/keys",
				"authorization_endpoint":                issuer + "/auth",
				"token_endpoint":                        issuer + "/token",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{Key: &privKey.PublicKey, Use: "sig", Algorithm: "RS256", KeyID: "test-key"},
			}}
			json.NewEncoder(w).Encode(jwks)
		case "/token":
			claims := jwt.Claims{
				Subject:   "user123",
				Issuer:    issuer,
				Audience:  jwt.Audience{"client-id"},
				Expiry:    jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			}
			rawJWT, _ := jwt.Signed(signer).Claims(claims).Claims(map[string]any{"nonce": nonce}).Serialize()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "tok",
				"id_token":     rawJWT,
				"token_type":   "Bearer",
			})
		}
	}))
	defer oidcServer.Close()

	ctx := context.Background()
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	if err := reg.RegisterOIDCProvider(ctx, "oidc", oidcServer.URL, "client-id", "secret", []string{"openid"}, "http://example.com/callback"); err != nil {
		t.Fatalf("failed to register OIDC provider: %v", err)
	}

	var capturedResult *AuthResult
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth",
		WithResultEndpoint(func(w http.ResponseWriter, r *http.Request, result *AuthResult) (endpoint.Renderer, error) {
			capturedResult = result
			return &endpoint.RedirectRenderer{URL: "/", Status: http.StatusFound}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Login — generates and stores the nonce.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/auth/login/oidc", nil)
	h.ServeHTTP(w1, r1)

	if w1.Result().StatusCode != http.StatusFound {
		t.Fatalf("login: expected 302, got %d", w1.Result().StatusCode)
	}

	// Decode the state cookie to extract the nonce so the mock token endpoint can use it.
	loginCookie := w1.Result().Cookies()[0]
	var states AuthStateMap
	if err := cookie.Decode(loginCookie, &states); err != nil {
		t.Fatal(err)
	}
	loc := w1.Result().Header.Get("Location")
	stateKey, _ := url.Parse(loc)
	for k, s := range states {
		if k == stateKey.Query().Get("state") {
			nonce = s.Nonce
		}
	}
	if nonce == "" {
		t.Fatal("nonce not found in state cookie")
	}

	// Callback with a token whose nonce matches.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/callback/oidc?code=foo&state="+stateKey.Query().Get("state"), nil)
	r2.AddCookie(loginCookie)
	h.ServeHTTP(w2, r2)

	if w2.Result().StatusCode != http.StatusFound {
		t.Fatalf("callback: expected 302, got %d: %s", w2.Result().StatusCode, w2.Body.String())
	}
	if capturedResult == nil {
		t.Fatal("result endpoint not called")
	}
	if capturedResult.Error != nil {
		t.Fatalf("unexpected error: %v", capturedResult.Error)
	}
	if capturedResult.IDToken == nil {
		t.Error("expected IDToken in result")
	}
	if capturedResult.IDToken.Subject != "user123" {
		t.Errorf("expected subject user123, got %q", capturedResult.IDToken.Subject)
	}
}

// TestAuthHandler_PrepareAuth verifies the full PrepareAuth flow:
// PrepareAuth saves AuthParams → login endpoint loads them via state_key →
// callback receives the original AuthParams in the result.
func TestAuthHandler_PrepareAuth(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token": "tok", "token_type": "Bearer"}`))
		}
	}))
	defer srv.Close()

	reg.RegisterOAuth2Provider("test", &oauth2.Config{
		Endpoint: oauth2.Endpoint{AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token"},
	})

	var capturedResult *AuthResult
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth",
		WithResultEndpoint(func(w http.ResponseWriter, r *http.Request, result *AuthResult) (endpoint.Renderer, error) {
			capturedResult = result
			return &endpoint.RedirectRenderer{URL: "/"}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Protected route calls PrepareAuth and redirects to login.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/protected", nil)
	stateKey, err := h.PrepareAuth(w1, r1, AuthParams{NextURL: "/protected", AppData: []byte("ctx")})
	if err != nil {
		t.Fatal(err)
	}
	if stateKey == "" {
		t.Fatal("expected non-empty stateKey")
	}

	// 2. Login endpoint loads the pre-saved state via state_key.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/login/test?state_key="+stateKey, nil)
	r2.AddCookie(w1.Result().Cookies()[0])
	h.ServeHTTP(w2, r2)

	if w2.Result().StatusCode != http.StatusFound {
		t.Fatalf("login: expected 302, got %d: %s", w2.Result().StatusCode, w2.Body.String())
	}
	loc := w2.Result().Header.Get("Location")
	if !strings.Contains(loc, srv.URL+"/auth") {
		t.Errorf("expected redirect to provider auth endpoint, got %s", loc)
	}
	u, _ := url.Parse(loc)
	state := u.Query().Get("state")

	// 3. OAuth callback — cookie from the login response contains the enriched state.
	w3 := httptest.NewRecorder()
	r3 := httptest.NewRequest("GET", "/auth/callback/test?code=foo&state="+state, nil)
	r3.AddCookie(w2.Result().Cookies()[0])
	h.ServeHTTP(w3, r3)

	if capturedResult == nil {
		t.Fatal("result endpoint not called")
	}
	if capturedResult.Error != nil {
		t.Fatalf("unexpected error in result: %v", capturedResult.Error)
	}
	if capturedResult.AuthParams.NextURL != "/protected" {
		t.Errorf("expected NextURL /protected, got %q", capturedResult.AuthParams.NextURL)
	}
	if string(capturedResult.AuthParams.AppData) != "ctx" {
		t.Errorf("expected AppData %q, got %q", "ctx", capturedResult.AuthParams.AppData)
	}
}

// TestAuthHandler_PrepareAuth_SkipsPreAuthHook verifies that PrepareAuth does NOT invoke
// the preAuthHook. On the PrepareAuth path, the caller constructs AuthParams in server-side
// code and is solely responsible for validation. The hook is intentionally bypassed so that
// hook logic written for the query-string path does not interfere.
func TestAuthHandler_PrepareAuth_SkipsPreAuthHook(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{})

	// A hook that fails unconditionally — if PrepareAuth calls it, the call will fail.
	failHook := func(ctx context.Context, w http.ResponseWriter, r *http.Request, params AuthParams) (AuthParams, error) {
		return params, errors.New("preAuthHook must not be called from PrepareAuth")
	}
	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth", WithPreAuthHook(failHook))
	if err != nil {
		t.Fatal(err)
	}

	// PrepareAuth with params already validated by the caller.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	stateKey, err := h.PrepareAuth(w, r, AuthParams{NextURL: "/dashboard"})
	if err != nil {
		t.Fatalf("PrepareAuth should not invoke the preAuthHook, got error: %v", err)
	}

	// Params are stored as-is — no hook transformation.
	c := w.Result().Cookies()[0]
	var states AuthStateMap
	if err := cookie.Decode(c, &states); err != nil {
		t.Fatal(err)
	}
	s, ok := states[stateKey]
	if !ok {
		t.Fatal("state not found in cookie")
	}
	if s.AuthParams.NextURL != "/dashboard" {
		t.Errorf("expected NextURL '/dashboard' (unmodified), got %q", s.AuthParams.NextURL)
	}
}

// TestAuthHandler_Login_InvalidStateKey verifies that an unrecognised state_key falls
// back gracefully (case 2): the login still proceeds with empty AuthParams rather than
// returning an error, so a stale or replayed state_key cannot block authentication.
func TestAuthHandler_Login_InvalidStateKey(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	cookie, _ := middleware.NewSecureCookie("auth-state", "1", keys)
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth"}})

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test?state_key=doesnotexist", nil)
	h.ServeHTTP(w, r)

	if w.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected 302 fallback redirect, got %d", w.Result().StatusCode)
	}

	// The new state should have no AppData — no state from the bogus state_key leaked through.
	// NextURL will be "/" because the defaultPreAuthHook normalises an empty URL to "/".
	c := w.Result().Cookies()[0]
	var states AuthStateMap
	if err := cookie.Decode(c, &states); err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		if len(s.AuthParams.AppData) != 0 {
			t.Errorf("expected no AppData in fallback state, got %q", s.AuthParams.AppData)
		}
	}
}

func TestAuthHandler_AppDataMaxLength(t *testing.T) {
	keys := map[string][]byte{"1": make([]byte, 32)}
	reg := NewRegistry()
	reg.RegisterOAuth2Provider("test", &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "http://provider/auth"}})

	h, err := NewHandler(reg, "auth-state", "1", keys, "http://example.com", "/auth")
	if err != nil {
		t.Fatal(err)
	}

	// Test with exactly 512 bytes - should pass
	okData := make([]byte, 512)
	for i := range okData {
		okData[i] = 'A'
	}
	okEncoded := base64.RawURLEncoding.EncodeToString(okData)

	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "/auth/login/test?app_data="+okEncoded, nil)
	h.ServeHTTP(w1, r1)

	if w1.Result().StatusCode != http.StatusFound {
		t.Errorf("expected 302 for 512 bytes, got %d: %s", w1.Result().StatusCode, w1.Body.String())
	}

	// Test with 513 bytes - should fail due to exceeding 512-byte limit
	// Note: 513 bytes encodes to 684 chars, which exceeds maxLength of 683
	// So this will fail at the decoder level with a generic "Bad Request" error
	longData := make([]byte, 513)
	for i := range longData {
		longData[i] = 'A'
	}
	longEncoded := base64.RawURLEncoding.EncodeToString(longData)

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/login/test?app_data="+longEncoded, nil)
	h.ServeHTTP(w2, r2)

	// Should fail because it exceeds 512 bytes (fails at decoder or handler level)
	if w2.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for 513 bytes, got %d", w2.Result().StatusCode)
	}
}
