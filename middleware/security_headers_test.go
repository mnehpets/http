package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mnehpets/http/endpoint"
)

func TestNewSecurityHeadersProcessor(t *testing.T) {
	p := NewSecurityHeadersProcessor()
	if p.HSTS == nil {
		t.Fatal("HSTS should be configured by default")
	}
	if p.HSTS.MaxAge != 31536000 {
		t.Errorf("HSTS MaxAge: got %d, want %d", p.HSTS.MaxAge, 31536000)
	}
	if !p.HSTS.IncludeSubDomains {
		t.Error("HSTS IncludeSubDomains should be true by default")
	}
	if p.HSTS.Preload {
		t.Error("HSTS Preload should be false by default")
	}
	if p.ReferrerPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("ReferrerPolicy: got %q, want %q", p.ReferrerPolicy, "strict-origin-when-cross-origin")
	}
	if p.FrameOptions != "DENY" {
		t.Errorf("FrameOptions: got %q, want %q", p.FrameOptions, "DENY")
	}
	if !p.ContentTypeOptions {
		t.Error("ContentTypeOptions should be true by default")
	}
	if p.CORS != nil {
		t.Error("CORS should be nil by default")
	}
	if p.ContentSecurityPolicy != "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests" {
		t.Errorf("ContentSecurityPolicy default incorrect: got %q", p.ContentSecurityPolicy)
	}
	if p.CrossOriginOpenerPolicy != "same-origin" {
		t.Errorf("CrossOriginOpenerPolicy default incorrect: got %q", p.CrossOriginOpenerPolicy)
	}
	if p.CrossOriginEmbedderPolicy != "require-corp" {
		t.Errorf("CrossOriginEmbedderPolicy default incorrect: got %q", p.CrossOriginEmbedderPolicy)
	}
	if p.CrossOriginResourcePolicy != "same-origin" {
		t.Errorf("CrossOriginResourcePolicy default incorrect: got %q", p.CrossOriginResourcePolicy)
	}
}

func TestNewAPISecurityHeadersProcessor(t *testing.T) {
	p := NewAPISecurityHeadersProcessor()
	if p.ReferrerPolicy != "no-referrer" {
		t.Errorf("ReferrerPolicy: got %q, want %q", p.ReferrerPolicy, "no-referrer")
	}
	if p.ContentSecurityPolicy != "default-src 'none'; frame-ancestors 'none'" {
		t.Errorf("ContentSecurityPolicy default incorrect: got %q", p.ContentSecurityPolicy)
	}
	// Verify common defaults with Web processor
	if p.HSTS == nil || p.HSTS.MaxAge != 31536000 {
		t.Error("HSTS should be configured same as Web default")
	}
	if p.CrossOriginOpenerPolicy != "same-origin" {
		t.Errorf("CrossOriginOpenerPolicy default incorrect: got %q", p.CrossOriginOpenerPolicy)
	}
}

func TestSecurityHeadersProcessor_DefaultHeaders(t *testing.T) {
	p := NewSecurityHeadersProcessor()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		nextCalled = true
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}

	// Check HSTS header
	hsts := w.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("HSTS header: got %q, want to contain 'max-age=31536000'", hsts)
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS header: got %q, want to contain 'includeSubDomains'", hsts)
	}
	if strings.Contains(hsts, "preload") {
		t.Errorf("HSTS header: got %q, should not contain 'preload'", hsts)
	}

	// Check Referrer-Policy header
	refPolicy := w.Header().Get("Referrer-Policy")
	if refPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy: got %q, want %q", refPolicy, "strict-origin-when-cross-origin")
	}

	// Check X-Frame-Options header
	frameOpts := w.Header().Get("X-Frame-Options")
	if frameOpts != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want %q", frameOpts, "DENY")
	}

	// Check X-Content-Type-Options header
	contentTypeOpts := w.Header().Get("X-Content-Type-Options")
	if contentTypeOpts != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want %q", contentTypeOpts, "nosniff")
	}

	// Check Content-Security-Policy header
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("Content-Security-Policy: got %q, want to contain 'default-src 'self''", csp)
	}

	// Check Cross-Origin headers
	if w.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" {
		t.Error("Cross-Origin-Opener-Policy not set correctly")
	}
	if w.Header().Get("Cross-Origin-Embedder-Policy") != "require-corp" {
		t.Error("Cross-Origin-Embedder-Policy not set correctly")
	}
	if w.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Error("Cross-Origin-Resource-Policy not set correctly")
	}

	// Check that CORS headers are not set
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("Access-Control-Allow-Origin should not be set by default")
	}
}

func TestSecurityHeadersProcessor_CustomHSTS(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithHSTS(7776000, false, true))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	hsts := w.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=7776000") {
		t.Errorf("HSTS header: got %q, want to contain 'max-age=7776000'", hsts)
	}
	if strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS header: got %q, should not contain 'includeSubDomains'", hsts)
	}
	if !strings.Contains(hsts, "preload") {
		t.Errorf("HSTS header: got %q, want to contain 'preload'", hsts)
	}
}

func TestSecurityHeadersProcessor_DisableHSTS(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithoutHSTS())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("Strict-Transport-Security should not be set when HSTS is disabled")
	}
}

func TestSecurityHeadersProcessor_CustomCSP(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCSP("default-src https:"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	p.Process(w, r, func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) { return nil, nil })

	if got := w.Header().Get("Content-Security-Policy"); got != "default-src https:" {
		t.Errorf("Content-Security-Policy: got %q, want %q", got, "default-src https:")
	}
}

func TestSecurityHeadersProcessor_CustomCrossOriginPolicies(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCrossOriginPolicies("unsafe-none", "credentialless", "cross-origin"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	p.Process(w, r, func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) { return nil, nil })

	if got := w.Header().Get("Cross-Origin-Opener-Policy"); got != "unsafe-none" {
		t.Errorf("COOP: got %q, want %q", got, "unsafe-none")
	}
	if got := w.Header().Get("Cross-Origin-Embedder-Policy"); got != "credentialless" {
		t.Errorf("COEP: got %q, want %q", got, "credentialless")
	}
	if got := w.Header().Get("Cross-Origin-Resource-Policy"); got != "cross-origin" {
		t.Errorf("CORP: got %q, want %q", got, "cross-origin")
	}
}

func TestSecurityHeadersProcessor_CustomReferrerPolicy(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithReferrerPolicy("no-referrer"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	refPolicy := w.Header().Get("Referrer-Policy")
	if refPolicy != "no-referrer" {
		t.Errorf("Referrer-Policy: got %q, want %q", refPolicy, "no-referrer")
	}
}

func TestSecurityHeadersProcessor_CustomFrameOptions(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithFrameOptions("SAMEORIGIN"))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	frameOpts := w.Header().Get("X-Frame-Options")
	if frameOpts != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options: got %q, want %q", frameOpts, "SAMEORIGIN")
	}
}

func TestSecurityHeadersProcessor_DisableContentTypeOptions(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithContentTypeOptions(false))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	if w.Header().Get("X-Content-Type-Options") != "" {
		t.Error("X-Content-Type-Options should not be set when disabled")
	}
}

func TestSecurityHeadersProcessor_CORS_SimpleOrigin(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         3600,
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin: got %q, want %q", origin, "https://example.com")
	}

	// For simple (non-preflight) requests, methods and headers should NOT be set
	methods := w.Header().Get("Access-Control-Allow-Methods")
	if methods != "" {
		t.Errorf("Access-Control-Allow-Methods should not be set for simple requests, got %q", methods)
	}

	headers := w.Header().Get("Access-Control-Allow-Headers")
	if headers != "" {
		t.Errorf("Access-Control-Allow-Headers should not be set for simple requests, got %q", headers)
	}
}

func TestSecurityHeadersProcessor_CORS_Wildcard(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET"},
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://anysite.com")

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "*" {
		t.Errorf("Access-Control-Allow-Origin: got %q, want %q", origin, "*")
	}
}

func TestSecurityHeadersProcessor_CORS_WildcardWithCredentials(t *testing.T) {
	// Security test: Wildcard with credentials should not set wildcard origin
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET"},
		AllowCredentials: true,
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://anysite.com")

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "" {
		t.Errorf("Access-Control-Allow-Origin should not be set when using wildcard with credentials, got %q", origin)
	}
}

func TestSecurityHeadersProcessor_CORS_UnauthorizedOrigin(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET"},
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://evil.com")

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "" {
		t.Errorf("Access-Control-Allow-Origin should not be set for unauthorized origin, got %q", origin)
	}
}

func TestSecurityHeadersProcessor_CORS_NoOriginHeader(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET"},
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	// Test case with no Origin header to verify CORS headers are not set when
	// there is no cross-origin request (per CORS spec).

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// CORS headers should NOT be set when there's no Origin header
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "" {
		t.Errorf("Access-Control-Allow-Origin should not be set without Origin header, got %q", origin)
	}
}

func TestSecurityHeadersProcessor_CORS_Credentials(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins:   []string{"https://example.com"},
		AllowedMethods:   []string{"GET"},
		AllowCredentials: true,
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	credentials := w.Header().Get("Access-Control-Allow-Credentials")
	if credentials != "true" {
		t.Errorf("Access-Control-Allow-Credentials: got %q, want %q", credentials, "true")
	}
}

func TestSecurityHeadersProcessor_CORS_PreflightShortCircuit(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         7200,
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/", nil)
	r.Header.Set("Origin", "https://example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")

	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		nextCalled = true
		return nil, nil
	}

	renderer, err := p.Process(w, r, next)

	if err != nil {
		t.Fatalf("Process returned unexpected error for preflight: %v", err)
	}
	if renderer == nil {
		t.Fatal("Process should return a renderer for preflight short-circuit")
	}
	if nextCalled {
		t.Error("next should NOT be called for valid CORS preflight")
	}

	// Verify Headers
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin: got %q, want %q", origin, "https://example.com")
	}
	maxAge := w.Header().Get("Access-Control-Max-Age")
	if maxAge != "7200" {
		t.Errorf("Access-Control-Max-Age: got %q, want %q", maxAge, "7200")
	}
}

func TestSecurityHeadersProcessor_CORS_NormalOptions_PassThrough(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/", nil)
	r.Header.Set("Origin", "https://example.com")
	// No Access-Control-Request-Method header -> Not a preflight

	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		nextCalled = true
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	if !nextCalled {
		t.Error("next SHOULD be called for regular OPTIONS request")
	}

	// Standard CORS headers should still be set because it has an Origin
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("Access-Control-Allow-Origin should be set")
	}
}

func TestSecurityHeadersProcessor_CORS_ExposedHeaders(t *testing.T) {
	p := NewSecurityHeadersProcessor(WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		ExposedHeaders: []string{"X-Custom-Header", "X-Another-Header"},
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	exposed := w.Header().Get("Access-Control-Expose-Headers")
	if exposed != "X-Custom-Header, X-Another-Header" {
		t.Errorf("Access-Control-Expose-Headers: got %q, want %q", exposed, "X-Custom-Header, X-Another-Header")
	}
}

func TestSecurityHeadersProcessor_AllHeadersCombined(t *testing.T) {
	p := NewSecurityHeadersProcessor(
		WithHSTS(7776000, true, false),
		WithReferrerPolicy("same-origin"),
		WithFrameOptions("SAMEORIGIN"),
		WithContentTypeOptions(true),
		WithCORS(&CORSConfig{
			AllowedOrigins:   []string{"https://example.com"},
			AllowedMethods:   []string{"GET", "POST", "PUT"},
			AllowedHeaders:   []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
			MaxAge:           3600,
		}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return nil, nil
	}

	_, err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// Verify all headers are set correctly
	if !strings.Contains(w.Header().Get("Strict-Transport-Security"), "max-age=7776000") {
		t.Error("HSTS header not set correctly")
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Error("Referrer-Policy not set correctly")
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("X-Frame-Options not set correctly")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options not set correctly")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("Access-Control-Allow-Origin not set correctly")
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("Access-Control-Allow-Credentials not set correctly")
	}
}

func TestFormatHSTS(t *testing.T) {
	tests := []struct {
		name   string
		config *HSTSConfig
		want   string
	}{
		{
			name:   "nil config",
			config: nil,
			want:   "",
		},
		{
			name:   "zero max age",
			config: &HSTSConfig{MaxAge: 0},
			want:   "",
		},
		{
			name:   "basic config",
			config: &HSTSConfig{MaxAge: 3600},
			want:   "max-age=3600",
		},
		{
			name:   "with subdomains",
			config: &HSTSConfig{MaxAge: 3600, IncludeSubDomains: true},
			want:   "max-age=3600; includeSubDomains",
		},
		{
			name:   "with preload",
			config: &HSTSConfig{MaxAge: 3600, Preload: true},
			want:   "max-age=3600; preload",
		},
		{
			name:   "all options",
			config: &HSTSConfig{MaxAge: 31536000, IncludeSubDomains: true, Preload: true},
			want:   "max-age=31536000; includeSubDomains; preload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatHSTS(tt.config)
			if got != tt.want {
				t.Errorf("formatHSTS() = %q, want %q", got, tt.want)
			}
		})
	}
}
