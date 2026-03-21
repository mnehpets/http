package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
	"golang.org/x/oauth2"
)

// PreAuthHook is an optional hook invoked on the query-string login path only
// (i.e. GET /auth/login/{provider}?next_url=...&app_data=...). It receives the
// user-supplied AuthParams and returns a (possibly modified) copy.
//
// Use it to validate or re-encode params that arrive as raw query parameters —
// for example, to enforce that NextURL is a local path, or to decrypt an
// encrypted AppData payload.
//
// The hook is NOT called on the PrepareAuth path. When using PrepareAuth, the
// caller constructs AuthParams directly in server-side code and is responsible
// for ensuring they are valid and safe before passing them in.
type PreAuthHook func(ctx context.Context, w http.ResponseWriter, r *http.Request, params AuthParams) (AuthParams, error)

// maxAppDataBytes is the maximum allowed size of AppData after base64url decoding.
const maxAppDataBytes = 512

// ProviderError represents an error returned by the identity provider.
type ProviderError struct {
	Code        string
	Description string
}

func (e *ProviderError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("provider error: %s (description: %s)", e.Code, e.Description)
	}
	return fmt.Sprintf("provider error: %s", e.Code)
}

// AuthParams contains parameters for initiating an OAuth flow.
// It is used for both LoginParams and AuthState to ensure consistency.
type AuthParams struct {
	NextURL string `query:"next_url" cbor:"1,keyasint,omitempty"`
	// AppData is base64url-encoded in query params and limited to 512 bytes when decoded.
	// maxLength of 683 corresponds to the base64url-encoded length of 512 bytes (512 * 4/3 ≈ 683).
	AppData []byte `query:"app_data,base64url" cbor:"2,keyasint,omitempty" maxLength:"683"`
}

// AuthResult contains the result of an OAuth authentication request.
// For success, Token and IDToken are filled and Error is nil.
// For failure, Token and IDToken are nil and Error indicates the failure.
type AuthResult struct {
	ProviderID string
	Token      *oauth2.Token
	IDToken    *oidc.IDToken
	AuthParams *AuthParams
	Error      error
}

// ResultEndpoint is invoked after an OAuth callback, for both success and failure cases.
type ResultEndpoint endpoint.EndpointFunc[*AuthResult]

// defaultPreAuthHook is the default implementation.
// It ensures the NextURL is a safe relative path to prevent open redirects.
func defaultPreAuthHook(ctx context.Context, w http.ResponseWriter, r *http.Request, params AuthParams) (AuthParams, error) {
	params.NextURL = ValidateNextURLIsLocal(params.NextURL)
	return params, nil
}

// defaultResultEndpoint is the default implementation that handles both success and failure.
// For success, it redirects to NextURL. For failure, it returns the error.
func defaultResultEndpoint(w http.ResponseWriter, r *http.Request, result *AuthResult) (endpoint.Renderer, error) {
	if result.Error != nil {
		return nil, result.Error
	}
	return &endpoint.RedirectRenderer{URL: result.AuthParams.NextURL, Status: http.StatusFound}, nil
}

// AuthHandler implements the OAuth flow orchestration.
type AuthHandler struct {
	mux       *http.ServeMux
	registry  *Registry
	publicURL string
	basePath  string

	// State Management
	cookie middleware.SecureCookie

	preAuth PreAuthHook
	result  ResultEndpoint

	// processors are the middleware processors to run for each endpoint
	processors []endpoint.Processor

	// cookieOptions are used to configure the secure cookie
	cookieOptions []middleware.SecureCookieOption
}

// Option configures the AuthHandler.
type Option func(*AuthHandler)

// WithProcessors adds middleware processors to the auth endpoints.
func WithProcessors(p ...endpoint.Processor) Option {
	return func(ah *AuthHandler) {
		ah.processors = append(ah.processors, p...)
	}
}

// WithCookieOptions configures the auth cookie attributes.
func WithCookieOptions(opts ...middleware.SecureCookieOption) Option {
	return func(ah *AuthHandler) {
		ah.cookieOptions = append(ah.cookieOptions, opts...)
	}
}

// WithPreAuthHook sets the PreAuthHook.
func WithPreAuthHook(h PreAuthHook) Option {
	return func(ah *AuthHandler) {
		ah.preAuth = h
	}
}

// WithResultEndpoint sets the ResultEndpoint.
func WithResultEndpoint(h ResultEndpoint) Option {
	return func(ah *AuthHandler) {
		ah.result = h
	}
}

// maxStates is the maximum number of concurrent auth states per user-agent.
// This prevents cookie bloat and limits the potential for state replay attacks.
const maxStates = 3

// authStateTTL is the duration for which an auth state is valid.
const authStateTTL = time.Hour

// NewHandler creates a new AuthHandler.
// publicURL should be the base public URL of the application (e.g., "https://example.com").
// basePath is the path where this handler is mounted (e.g., "/auth").
func NewHandler(registry *Registry, cookieName, keyID string, keys map[string][]byte, publicURL, basePath string, opts ...Option) (*AuthHandler, error) {
	h := &AuthHandler{
		mux:       http.NewServeMux(),
		registry:  registry,
		publicURL: strings.TrimRight(publicURL, "/"),
		basePath:  basePath,
		preAuth:   defaultPreAuthHook,
		result:    defaultResultEndpoint,
	}
	for _, opt := range opts {
		opt(h)
	}

	cookie, err := middleware.NewSecureCookie(cookieName, keyID, keys, h.cookieOptions...)
	if err != nil {
		return nil, err
	}
	h.cookie = cookie

	// Ensure leading slash for basePath
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	// Endpoint for /prefix/login/{provider}
	//
	// Three cases are handled, in order of precedence:
	//
	//  1. state_key present and valid: AuthParams were saved by PrepareAuth (which ran the
	//     preAuthHook) and are loaded from the secure cookie. The preAuthHook is not
	//     invoked again.
	//
	//  2. state_key present but invalid/expired: falls back to case 3 with empty AuthParams.
	//     A stale or replayed state_key cannot prevent the user from authenticating.
	//
	//  3. No state_key: AuthParams are read from the query string (next_url, app_data) and
	//     passed through the preAuthHook for validation.
	h.mux.HandleFunc("GET "+path.Join(basePath, "login", "{provider}"), endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, params LoginParams) (endpoint.Renderer, error) {
		ctx := r.Context()
		providerID := params.ProviderID

		p, ok := h.registry.Get(providerID)
		if !ok {
			return nil, endpoint.Error(http.StatusNotFound, "provider not found", nil)
		}

		var stateKey string
		var authState AuthState

		if params.StateKey != "" {
			// Cases 1 & 2: state_key provided.
			savedState, err := h.getState(r, params.StateKey)
			if err == nil {
				// Case 1: valid pre-saved state from PrepareAuth.
				stateKey = params.StateKey
				authState = savedState
			} else {
				// Case 2: invalid or expired state_key — fall back to empty params.
				authState.AuthParams, err = h.preAuth(ctx, w, r, AuthParams{})
				if err != nil {
					return h.result(w, r, &AuthResult{
						ProviderID: providerID,
						AuthParams: &authState.AuthParams,
						Error:      endpoint.Error(http.StatusBadRequest, "pre-auth failed", err),
					})
				}
				stateKey, err = generateRandomToken()
				if err != nil {
					return h.result(w, r, &AuthResult{
						ProviderID: providerID,
						AuthParams: &authState.AuthParams,
						Error:      endpoint.Error(http.StatusInternalServerError, "failed to generate state", err),
					})
				}
			}
		} else {
			// Case 3: no state_key — read AuthParams from query string, run preAuthHook.
			var err error
			authState.AuthParams, err = h.preAuth(ctx, w, r, params.AuthParams)
			if err != nil {
				return h.result(w, r, &AuthResult{
					ProviderID: providerID,
					AuthParams: &authState.AuthParams,
					Error:      endpoint.Error(http.StatusBadRequest, "pre-auth failed", err),
				})
			}
			if len(authState.AuthParams.AppData) > maxAppDataBytes {
				return h.result(w, r, &AuthResult{
					ProviderID: providerID,
					AuthParams: &authState.AuthParams,
					Error:      endpoint.Error(http.StatusBadRequest, fmt.Sprintf("app_data exceeds maximum length of %d bytes", maxAppDataBytes), nil),
				})
			}
			stateKey, err = generateRandomToken()
			if err != nil {
				return h.result(w, r, &AuthResult{
					ProviderID: providerID,
					AuthParams: &authState.AuthParams,
					Error:      endpoint.Error(http.StatusInternalServerError, "failed to generate state", err),
				})
			}
		}

		return h.beginFlow(w, r, providerID, p, stateKey, authState)
	}, h.processors...))

	h.mux.HandleFunc("GET "+path.Join(basePath, "callback", "{provider}"), endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, params CallbackParams) (endpoint.Renderer, error) {
		ctx := r.Context()
		providerID := params.ProviderID

		p, ok := h.registry.Get(providerID)
		if !ok {
			return nil, endpoint.Error(http.StatusNotFound, "provider not found", nil)
		}

		// Retrieve state then clear it from cookie, result callback happens no more than once per request.
		authState, err := h.popState(w, r, params.State)
		if err != nil {
			// Without valid state, we can't pass AuthParams to the result callback.
			return h.result(w, r, &AuthResult{
				ProviderID: providerID,
				Error:      endpoint.Error(http.StatusBadRequest, "invalid state", err),
			})
		}

		// Check for provider error
		if params.Error != "" {
			err := &ProviderError{Code: params.Error, Description: params.ErrorDesc}
			return h.result(w, r, &AuthResult{
				ProviderID: providerID,
				AuthParams: &authState.AuthParams,
				Error:      endpoint.Error(http.StatusBadRequest, "provider returned error", err),
			})
		}

		// Prepare Exchange options
		opts := []oauth2.AuthCodeOption{}
		if authState.PKCEVerifier != "" {
			opts = append(opts, oauth2.SetAuthURLParam("code_verifier", authState.PKCEVerifier))
		}

		// Exchange code
		// Clone config to set RedirectURL (must match what was sent in login)
		conf := *p.config
		conf.RedirectURL = h.constructCallbackURL(providerID)

		token, err := conf.Exchange(ctx, params.Code, opts...)
		if err != nil {
			return h.result(w, r, &AuthResult{
				ProviderID: providerID,
				AuthParams: &authState.AuthParams,
				Error:      endpoint.Error(http.StatusInternalServerError, "token exchange failed", err),
			})
		}

		// OIDC Validation
		var idToken *oidc.IDToken
		if p.oidcProvider != nil {
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				err := fmt.Errorf("no id_token returned")
				return h.result(w, r, &AuthResult{
					ProviderID: providerID,
					AuthParams: &authState.AuthParams,
					Error:      endpoint.Error(http.StatusInternalServerError, "no id_token returned", err),
				})
			}

			verifier := p.verifier
			idToken, err = verifier.Verify(ctx, rawIDToken)
			if err != nil {
				return h.result(w, r, &AuthResult{
					ProviderID: providerID,
					AuthParams: &authState.AuthParams,
					Error:      endpoint.Error(http.StatusInternalServerError, "id_token verification failed", err),
				})
			}

			// Verify Nonce
			if authState.Nonce != "" {
				if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(authState.Nonce)) != 1 {
					err := fmt.Errorf("nonce mismatch")
					return h.result(w, r, &AuthResult{
						ProviderID: providerID,
						AuthParams: &authState.AuthParams,
						Error:      endpoint.Error(http.StatusBadRequest, "nonce mismatch", err),
					})
				}
			}
		}

		// Success
		return h.result(w, r, &AuthResult{
			ProviderID: providerID,
			Token:      token,
			IDToken:    idToken,
			AuthParams: &authState.AuthParams,
		})
	}, h.processors...))

	return h, nil
}

func (h *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// PrepareAuth stores the provided AuthParams in the secure cookie and returns an opaque
// stateKey. Pass the stateKey as the state_key query parameter to a login endpoint to
// resume the flow, e.g. /auth/login/google?state_key=<stateKey>.
//
// # Two paths into the login flow
//
// There are two ways to initiate an OAuth login:
//
// Query-string path — the user (or a link) navigates directly to the login endpoint
// with next_url and app_data as query parameters:
//
//	GET /auth/login/google?next_url=/dashboard&app_data=<encoded>
//
// Because these values are user-controlled, the preAuthHook is invoked to validate
// and re-encode them before they are stored. The default hook rejects open redirects.
//
// PrepareAuth path — server-side code constructs AuthParams and calls PrepareAuth
// before redirecting the user:
//
//	stateKey, err := authHandler.PrepareAuth(w, r, AuthParams{NextURL: r.URL.RequestURI()})
//	// redirect to /auth/login/google?state_key=<stateKey>
//
// Because the params originate from trusted server-side code, the preAuthHook is NOT
// invoked. The caller is responsible for ensuring the params are valid and safe. At
// minimum, NextURL must be a safe local path — use ValidateNextURLIsLocal if the value
// derives from user input (e.g. the request URL):
//
//	params.NextURL = auth.ValidateNextURLIsLocal(r.URL.RequestURI())
//
// AppData must be constructed entirely by the server; never let a user supply raw
// AppData on the PrepareAuth path.
//
// # Why use PrepareAuth
//
// Use PrepareAuth when the handler's immediate next action is to redirect the user to
// a login URL — for example, a protected route that has determined the user is not
// authenticated and will redirect unconditionally. Each call writes an entry to the
// secure cookie, so it must not be called speculatively.
//
// Use the query-string path when the caller may or may not redirect to login, or when
// the login link is constructed ahead of time (e.g. a static "Login" button in a page
// template). In that case, next_url and app_data travel as query parameters and are
// validated by the preAuthHook when the login endpoint is hit.
//
// # Typical flow
//
//  1. Protected route detects the user is unauthenticated.
//  2. Calls PrepareAuth with AuthParams{NextURL: r.URL.RequestURI()}.
//  3. For a known provider, redirects to the login endpoint:
//     /auth/login/google?state_key=<stateKey>
//  4. For a provider chooser, redirects to the app's chooser page:
//     /app/chooser?state_key=<stateKey>
//     The chooser page embeds provider-specific login links, each carrying the same
//     stateKey: /auth/login/google?state_key=<stateKey>, etc.
//  5. The login endpoint loads the pre-saved AuthParams from the cookie, generates
//     PKCE/nonce, and redirects the user to the OAuth provider.
//  6. The OAuth callback verifies PKCE/nonce, and on success the result endpoint
//     redirects to the saved NextURL.
func (h *AuthHandler) PrepareAuth(w http.ResponseWriter, r *http.Request, params AuthParams) (string, error) {
	stateKey, err := generateRandomToken()
	if err != nil {
		return "", err
	}
	if err := h.addState(w, r, stateKey, AuthState{AuthParams: params}); err != nil {
		return "", err
	}
	return stateKey, nil
}

// Internal State Management Methods

func (h *AuthHandler) addState(w http.ResponseWriter, r *http.Request, stateKey string, authState AuthState) error {
	// Read existing cookie
	c, _ := r.Cookie(h.cookie.Name())
	var states AuthStateMap
	var err error

	if c != nil {
		err = h.cookie.Decode(c, &states)
		if err != nil {
			states = make(AuthStateMap)
		}
	} else {
		states = make(AuthStateMap)
	}

	// 1. Cleanup expired states
	now := time.Now()
	for k, v := range states {
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) {
			delete(states, k)
		}
	}

	// 2. Evict if still full
	if len(states) >= maxStates {
		var oldestKey string
		var oldestTime time.Time

		for k, v := range states {
			if oldestKey == "" || v.ExpiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.ExpiresAt
			}
		}
		if oldestKey != "" {
			delete(states, oldestKey)
		}
	}

	// 3. Add new state
	authState.ExpiresAt = now.Add(authStateTTL)
	states[stateKey] = authState

	// Encode and set cookie
	newCookie, err := h.cookie.Encode(states, int(authStateTTL.Seconds()))
	if err != nil {
		return err
	}
	http.SetCookie(w, newCookie)
	return nil
}

func (h *AuthHandler) popState(w http.ResponseWriter, r *http.Request, stateKey string) (AuthState, error) {
	states, err := h.loadStates(r)
	if err != nil {
		return AuthState{}, err
	}

	authState, ok := states[stateKey]
	if !ok {
		return AuthState{}, errors.New("state not found")
	}

	// Check expiry
	if !authState.ExpiresAt.IsZero() && time.Now().After(authState.ExpiresAt) {
		// Even if found, it's expired. Remove it and fail.
		delete(states, stateKey)
		// Update cookie (cleanup)
		h.updateCookie(w, states)
		return AuthState{}, errors.New("state expired")
	}

	// Remove the state
	delete(states, stateKey)

	// Update the cookie
	if err := h.updateCookie(w, states); err != nil {
		return AuthState{}, err
	}

	return authState, nil
}

func (h *AuthHandler) updateCookie(w http.ResponseWriter, states AuthStateMap) error {
	if len(states) == 0 {
		http.SetCookie(w, h.cookie.Clear())
		return nil
	}
	newCookie, err := h.cookie.Encode(states, int(authStateTTL.Seconds()))
	if err != nil {
		return err
	}
	http.SetCookie(w, newCookie)
	return nil
}

// loadStates decodes the AuthStateMap from the request's auth cookie.
// Returns an error if the cookie is absent or cannot be decoded.
func (h *AuthHandler) loadStates(r *http.Request) (AuthStateMap, error) {
	c, err := r.Cookie(h.cookie.Name())
	if err != nil {
		return nil, err
	}
	var states AuthStateMap
	if err := h.cookie.Decode(c, &states); err != nil {
		return nil, err
	}
	return states, nil
}

// getState reads an AuthState from the cookie by key without removing it.
// Returns an error if the cookie is missing, the key is not found, or the state has expired.
func (h *AuthHandler) getState(r *http.Request, stateKey string) (AuthState, error) {
	states, err := h.loadStates(r)
	if err != nil {
		return AuthState{}, err
	}
	authState, ok := states[stateKey]
	if !ok {
		return AuthState{}, errors.New("state not found")
	}
	if !authState.ExpiresAt.IsZero() && time.Now().After(authState.ExpiresAt) {
		return AuthState{}, errors.New("state expired")
	}
	return authState, nil
}

// beginFlow completes an OAuth initiation after the auth state and stateKey have been
// determined. It generates PKCE and nonce values (when required by the provider), stores
// the completed state in the secure cookie (overwriting any existing entry for stateKey),
// and returns a redirect to the OAuth provider's authorization endpoint.
//
// stateKey is passed as the OAuth "state" parameter. The actual auth state (PKCE verifier,
// nonce, AuthParams) is stored in the secure cookie keyed by stateKey — it is not encoded
// into the state value itself.
func (h *AuthHandler) beginFlow(w http.ResponseWriter, r *http.Request, providerID string, p *Provider, stateKey string, authState AuthState) (endpoint.Renderer, error) {
	// PKCE
	var codeChallenge string
	if p.usePKCE {
		verifier, challenge, err := generatePKCE()
		if err != nil {
			return h.result(w, r, &AuthResult{
				ProviderID: providerID,
				AuthParams: &authState.AuthParams,
				Error:      endpoint.Error(http.StatusInternalServerError, "failed to generate PKCE", err),
			})
		}
		authState.PKCEVerifier = verifier
		codeChallenge = challenge
	}

	// OIDC Nonce
	var nonce string
	if p.oidcProvider != nil {
		var err error
		nonce, err = generateRandomToken()
		if err != nil {
			return h.result(w, r, &AuthResult{
				ProviderID: providerID,
				AuthParams: &authState.AuthParams,
				Error:      endpoint.Error(http.StatusInternalServerError, "failed to generate nonce", err),
			})
		}
		authState.Nonce = nonce
	}

	// Store completed state. If stateKey was created by PrepareAuth, this overwrites the
	// partial entry (AuthParams only) with the full state (AuthParams + PKCEVerifier + Nonce).
	if err := h.addState(w, r, stateKey, authState); err != nil {
		return h.result(w, r, &AuthResult{
			ProviderID: providerID,
			AuthParams: &authState.AuthParams,
			Error:      endpoint.Error(http.StatusInternalServerError, "failed to save state", err),
		})
	}

	// Build redirect URL. Clone config to set RedirectURL per-request.
	conf := *p.config
	conf.RedirectURL = h.constructCallbackURL(providerID)

	opts := []oauth2.AuthCodeOption{}
	if p.usePKCE {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", codeChallenge))
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	if nonce != "" {
		opts = append(opts, oidc.Nonce(nonce))
	}

	redirectURL := conf.AuthCodeURL(stateKey, opts...)
	return &endpoint.RedirectRenderer{URL: redirectURL, Status: http.StatusFound}, nil
}

func (h *AuthHandler) constructCallbackURL(providerID string) string {
	u, err := url.Parse(h.publicURL)
	if err != nil {
		// Fallback, though this shouldn't happen if publicURL is valid
		return h.publicURL + path.Join(h.basePath, "callback", providerID)
	}
	u.Path = path.Join(u.Path, h.basePath, "callback", providerID)
	return u.String()
}

type LoginParams struct {
	ProviderID string `path:"provider"`
	// StateKey is an opaque token created by PrepareAuth. When present, the login handler
	// loads the pre-saved AuthParams from the secure cookie rather than reading them from
	// the query string.
	StateKey string `query:"state_key"`
	AuthParams
}

type CallbackParams struct {
	ProviderID string `path:"provider"`
	State      string `query:"state"`
	Code       string `query:"code"`
	Error      string `query:"error"`
	ErrorDesc  string `query:"error_description"`
}
