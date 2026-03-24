package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/mnehpets/http/endpoint"
)

// SecurityHeadersProcessor is a middleware that sets recommended security headers.
//
// Default configuration for NewSecurityHeadersProcessor (web content):
//   - HSTS: max-age=31536000; includeSubDomains (1 year, with subdomains)
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - X-Frame-Options: DENY
//   - X-Content-Type-Options: nosniff
//   - Content-Security-Policy: default-src 'self'; ... (and other defaults)
//   - Cross-Origin Policies: COOP=same-origin, COEP=require-corp, CORP=same-origin
//
// Default configuration for NewAPISecurityHeadersProcessor (APIs):
//   - Similar to above but with stricter CSP (default-src 'none') and no-referrer.
//
// For cross-origin scenarios, configure CORS options via CORSConfig.
// This middleware automatically handles CORS preflight (OPTIONS) requests.
type SecurityHeadersProcessor struct {
	// HSTS configures the Strict-Transport-Security header.
	// Set to nil to disable. Default: max-age=31536000; includeSubDomains
	HSTS *HSTSConfig

	// ReferrerPolicy sets the Referrer-Policy header.
	// Set to empty string to disable. Default: strict-origin-when-cross-origin
	ReferrerPolicy string

	// FrameOptions sets the X-Frame-Options header.
	// Set to empty string to disable. Default: DENY
	// Common values: DENY, SAMEORIGIN, or empty to disable
	FrameOptions string

	// ContentTypeOptions sets the X-Content-Type-Options header.
	// Set to false to disable. Default: true (nosniff)
	ContentTypeOptions bool

	// ContentSecurityPolicy sets the Content-Security-Policy header.
	// Set to empty string to disable.
	ContentSecurityPolicy string

	// CrossOriginOpenerPolicy sets the Cross-Origin-Opener-Policy header.
	// Set to empty string to disable.
	CrossOriginOpenerPolicy string

	// CrossOriginEmbedderPolicy sets the Cross-Origin-Embedder-Policy header.
	// Set to empty string to disable.
	CrossOriginEmbedderPolicy string

	// CrossOriginResourcePolicy sets the Cross-Origin-Resource-Policy header.
	// Set to empty string to disable.
	CrossOriginResourcePolicy string

	// CORS configures Cross-Origin Resource Sharing headers.
	// Set to nil to disable CORS headers.
	CORS *CORSConfig
}

// HSTSConfig configures HTTP Strict Transport Security.
type HSTSConfig struct {
	// MaxAge specifies the duration (in seconds) that the browser should remember
	// that a site is only to be accessed using HTTPS.
	// Default: 31536000 (1 year)
	MaxAge int

	// IncludeSubDomains indicates whether HSTS applies to subdomains.
	// Default: true
	IncludeSubDomains bool

	// Preload indicates whether the site should be included in browsers' HSTS preload lists.
	// Only use if you've submitted your domain to the HSTS preload list.
	// Default: false
	Preload bool
}

// CORSConfig configures Cross-Origin Resource Sharing headers.
type CORSConfig struct {
	// AllowedOrigins specifies allowed origins for CORS requests.
	// Use "*" to allow any origin (not recommended for production).
	// Use specific origins like "https://example.com" for better security.
	// Default: nil (no CORS headers)
	AllowedOrigins []string

	// AllowedMethods specifies allowed HTTP methods for CORS requests.
	// Default: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
	AllowedMethods []string

	// AllowedHeaders specifies allowed headers for CORS requests.
	// Default: ["Accept", "Content-Type", "Authorization"]
	AllowedHeaders []string

	// ExposedHeaders specifies headers that are safe to expose to the API.
	// Default: nil
	ExposedHeaders []string

	// AllowCredentials indicates whether credentials (cookies, auth headers) can be sent.
	// Default: false
	AllowCredentials bool

	// MaxAge indicates how long (in seconds) preflight request results can be cached.
	// Default: 3600 (1 hour)
	MaxAge int
}

// SecurityHeadersOption is a functional option for configuring SecurityHeadersProcessor.
type SecurityHeadersOption func(*SecurityHeadersProcessor)

// NewSecurityHeadersProcessor creates a SecurityHeadersProcessor with recommended defaults for web content.
func NewSecurityHeadersProcessor(opts ...SecurityHeadersOption) *SecurityHeadersProcessor {
	p := &SecurityHeadersProcessor{
		HSTS: &HSTSConfig{
			MaxAge:            31536000, // 1 year
			IncludeSubDomains: true,
			Preload:           false,
		},
		ReferrerPolicy:            "strict-origin-when-cross-origin",
		FrameOptions:              "DENY",
		ContentTypeOptions:        true,
		ContentSecurityPolicy:     "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginResourcePolicy: "same-origin",
		CORS:                      nil, // No CORS by default
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// NewAPISecurityHeadersProcessor creates a SecurityHeadersProcessor with defaults for APIs.
func NewAPISecurityHeadersProcessor(opts ...SecurityHeadersOption) *SecurityHeadersProcessor {
	p := &SecurityHeadersProcessor{
		HSTS: &HSTSConfig{
			MaxAge:            31536000, // 1 year
			IncludeSubDomains: true,
			Preload:           false,
		},
		ReferrerPolicy:            "no-referrer",
		FrameOptions:              "DENY",
		ContentTypeOptions:        true,
		ContentSecurityPolicy:     "default-src 'none'; frame-ancestors 'none'",
		CrossOriginOpenerPolicy:   "same-origin",
		CrossOriginEmbedderPolicy: "require-corp",
		CrossOriginResourcePolicy: "same-origin",
		CORS:                      nil,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

// WithHSTS configures HSTS settings.
func WithHSTS(maxAge int, includeSubDomains, preload bool) SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.HSTS = &HSTSConfig{
			MaxAge:            maxAge,
			IncludeSubDomains: includeSubDomains,
			Preload:           preload,
		}
	}
}

// WithoutHSTS disables HSTS headers.
func WithoutHSTS() SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.HSTS = nil
	}
}

// WithReferrerPolicy sets the Referrer-Policy header.
// Common values: no-referrer, no-referrer-when-downgrade, origin,
// origin-when-cross-origin, same-origin, strict-origin,
// strict-origin-when-cross-origin, unsafe-url
func WithReferrerPolicy(policy string) SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.ReferrerPolicy = policy
	}
}

// WithFrameOptions sets the X-Frame-Options header.
// Common values: DENY, SAMEORIGIN
func WithFrameOptions(options string) SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.FrameOptions = options
	}
}

// WithContentTypeOptions enables or disables X-Content-Type-Options: nosniff.
func WithContentTypeOptions(enabled bool) SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.ContentTypeOptions = enabled
	}
}

// WithCSP sets the Content-Security-Policy header.
func WithCSP(policy string) SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.ContentSecurityPolicy = policy
	}
}

// WithCrossOriginPolicies sets COOP, COEP, and CORP headers.
func WithCrossOriginPolicies(opener, embedder, resource string) SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.CrossOriginOpenerPolicy = opener
		p.CrossOriginEmbedderPolicy = embedder
		p.CrossOriginResourcePolicy = resource
	}
}

// WithCORS configures CORS headers for cross-origin access.
func WithCORS(config *CORSConfig) SecurityHeadersOption {
	return func(p *SecurityHeadersProcessor) {
		p.CORS = config
	}
}

// Process implements endpoint.Processor.
func (p *SecurityHeadersProcessor) Process(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (endpoint.Renderer, error)) (endpoint.Renderer, error) {
	// Set HSTS header
	if p.HSTS != nil {
		hsts := formatHSTS(p.HSTS)
		if hsts != "" {
			w.Header().Set("Strict-Transport-Security", hsts)
		}
	}

	// Set Referrer-Policy header
	if p.ReferrerPolicy != "" {
		w.Header().Set("Referrer-Policy", p.ReferrerPolicy)
	}

	// Set X-Frame-Options header
	if p.FrameOptions != "" {
		w.Header().Set("X-Frame-Options", p.FrameOptions)
	}

	// Set X-Content-Type-Options header
	if p.ContentTypeOptions {
		w.Header().Set("X-Content-Type-Options", "nosniff")
	}

	// Set Content-Security-Policy header
	if p.ContentSecurityPolicy != "" {
		w.Header().Set("Content-Security-Policy", p.ContentSecurityPolicy)
	}

	// Set Cross-Origin policies
	if p.CrossOriginOpenerPolicy != "" {
		w.Header().Set("Cross-Origin-Opener-Policy", p.CrossOriginOpenerPolicy)
	}
	if p.CrossOriginEmbedderPolicy != "" {
		w.Header().Set("Cross-Origin-Embedder-Policy", p.CrossOriginEmbedderPolicy)
	}
	if p.CrossOriginResourcePolicy != "" {
		w.Header().Set("Cross-Origin-Resource-Policy", p.CrossOriginResourcePolicy)
	}

	// Set CORS headers
	if p.CORS != nil {
		setCORSHeaders(w, r, p.CORS)

		// Short-circuit CORS Preflight requests.
		// A preflight request is an OPTIONS request with an Origin and Access-Control-Request-Method.
		if r.Method == http.MethodOptions &&
			r.Header.Get("Origin") != "" &&
			r.Header.Get("Access-Control-Request-Method") != "" {
			return &endpoint.NoContentRenderer{Status: http.StatusNoContent}, nil
		}
	}

	return next(w, r)
}

// formatHSTS formats the HSTS header value.
func formatHSTS(config *HSTSConfig) string {
	if config == nil || config.MaxAge <= 0 {
		return ""
	}

	var parts []string
	parts = append(parts, "max-age="+strconv.Itoa(config.MaxAge))

	if config.IncludeSubDomains {
		parts = append(parts, "includeSubDomains")
	}

	if config.Preload {
		parts = append(parts, "preload")
	}

	return strings.Join(parts, "; ")
}

// setCORSHeaders sets CORS headers based on the configuration.
func setCORSHeaders(w http.ResponseWriter, r *http.Request, config *CORSConfig) {
	if config == nil {
		return
	}

	// CORS headers should only be set when there's an actual cross-origin request
	// (Origin header present, per CORS spec). Without an Origin header, this is not
	// a cross-origin request and CORS headers are not needed.
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	// Set Access-Control-Allow-Origin
	if len(config.AllowedOrigins) > 0 {
		// Check if origin is allowed
		for _, allowed := range config.AllowedOrigins {
			if allowed == "*" {
				// Security: Never set wildcard origin with credentials - this would
				// expose credentials to all origins, violating the CORS security model.
				// The CORS spec explicitly forbids '*' with credentials.
				if config.AllowCredentials {
					// Skip wildcard when credentials are enabled
					continue
				}
				w.Header().Set("Access-Control-Allow-Origin", "*")
				break
			} else if allowed == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
	}

	// Set Access-Control-Allow-Credentials
	if config.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Set Access-Control-Expose-Headers (for simple requests)
	if len(config.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(config.ExposedHeaders, ", "))
	}

	// Preflight-specific headers (only for OPTIONS requests)
	if r.Method == "OPTIONS" {
		// Set Access-Control-Allow-Methods
		if len(config.AllowedMethods) > 0 {
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		}

		// Set Access-Control-Allow-Headers
		if len(config.AllowedHeaders) > 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		}

		// Set Access-Control-Max-Age for preflight requests
		if config.MaxAge > 0 {
			w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
		}
	}
}

var _ endpoint.Processor = (*SecurityHeadersProcessor)(nil)
