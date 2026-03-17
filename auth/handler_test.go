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

	// Attempt open redirect
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/login/test?next_url=//evil.com", nil)
	h.ServeHTTP(w, r)

	// Check cookie state
	c := w.Result().Cookies()[0]
	var states AuthStateMap
	_ = cookie.Decode(c, &states)
	// Iterate to find the single state
	for _, s := range states {
		if s.AuthParams.NextURL != "/" {
			t.Errorf("expected NextURL to be '/', got %q", s.AuthParams.NextURL)
		}
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

	for i := 0; i < 4; i++ {
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
			json.NewEncoder(w).Encode(map[string]interface{}{
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
			rawJWT, _ := jwt.Signed(signer).Claims(claims).Claims(map[string]interface{}{"nonce": "WRONG_NONCE"}).Serialize()

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
	failPreAuth := func(ctx context.Context, w http.ResponseWriter, r *http.Request, pid string, params AuthParams) (AuthParams, error) {
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
