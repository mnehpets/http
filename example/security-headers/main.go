package main

import (
	"log"
	"net/http"

	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
)

// PublicAPIEndpoint is a simple API endpoint that returns JSON.
func PublicAPIEndpoint(w http.ResponseWriter, r *http.Request, params struct{}) (endpoint.Renderer, error) {
	return &endpoint.JSONRenderer{
		Value: map[string]string{
			"message": "Hello from secure API!",
			"status":  "somewhat chill",
		},
	}, nil
}

func main() {
	// Create security headers processor with defaults optimized for APIs
	// (Strict CSP, no referrer, etc.)
	apiSecurity := middleware.NewAPISecurityHeadersProcessor()

	// Create security headers processor with CORS enabled for cross-origin access
	// We start with API defaults and add CORS configuration.
	corsSecurity := middleware.NewAPISecurityHeadersProcessor(middleware.WithCORS(&middleware.CORSConfig{
		AllowedOrigins:   []string{"https://example.com", "https://app.example.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Authorization"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           3600,
	}))

	// Create a custom security configuration starting from Web defaults
	// (Allows same-origin scripts/styles, stricter referrer policy than API)
	customWebSecurity := middleware.NewSecurityHeadersProcessor(
		middleware.WithHSTS(7776000, true, false), // 90 days, with subdomains, no preload
		middleware.WithReferrerPolicy("same-origin"),
		middleware.WithFrameOptions("SAMEORIGIN"),
		middleware.WithCSP("default-src 'self'; img-src https:; script-src 'self' https://trusted.cdn.com"))

	// Create a wildcard CORS configuration for public APIs
	publicCORS := middleware.NewAPISecurityHeadersProcessor(middleware.WithCORS(&middleware.CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "OPTIONS"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         3600,
	}))

	mux := http.NewServeMux()

	// Endpoint with default API security headers
	mux.HandleFunc("GET /api/secure", endpoint.HandleFunc(PublicAPIEndpoint, apiSecurity))

	// Endpoint with CORS for specific origins (with preflight support)
	// Note: We still register OPTIONS to route the request, but the middleware handles the response.
	mux.HandleFunc("GET /api/cors", endpoint.HandleFunc(PublicAPIEndpoint, corsSecurity))
	mux.HandleFunc("OPTIONS /api/cors", endpoint.HandleFunc(PublicAPIEndpoint, corsSecurity))

	// Endpoint with custom security settings (simulating a web page/asset)
	mux.HandleFunc("GET /content/custom", endpoint.HandleFunc(PublicAPIEndpoint, customWebSecurity))

	// Public endpoint with wildcard CORS (with preflight support)
	mux.HandleFunc("GET /api/public", endpoint.HandleFunc(PublicAPIEndpoint, publicCORS))
	mux.HandleFunc("OPTIONS /api/public", endpoint.HandleFunc(PublicAPIEndpoint, publicCORS))

	log.Println("Server starting on :8080")
	log.Println("Try these endpoints:")
	log.Println("  - http://localhost:8080/api/secure      (API security defaults)")
	log.Println("  - http://localhost:8080/api/cors        (CORS enabled for specific origins)")
	log.Println("  - http://localhost:8080/content/custom  (Custom Web security: HSTS, CSP)")
	log.Println("  - http://localhost:8080/api/public      (Public API with wildcard CORS)")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
