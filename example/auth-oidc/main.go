package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"github.com/mnehpets/http/auth"
	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// HomeParams are the parameters for the home endpoint.
type HomeParams struct{}

// HomeData is the data passed to the template.
type HomeData struct {
	LoggedIn bool
	Username string
}

const homeTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Auth Example</title>
</head>
<body>
	<h1>Auth Example</h1>
	{{if .LoggedIn}}
		<p>Welcome, {{.Username}}!</p>
		<a href="/auth/logout?next_url=/home/">Logout</a>
	{{else}}
		<p>You are not logged in.</p>
		<ul>
			<li><a href="/auth/login/google?next_url=/home/">Login with Google</a></li>
			<li><a href="/auth/login/microsoft?next_url=/home/">Login with Microsoft</a></li>
			<li><a href="/auth/login/github?next_url=/home/">Login with GitHub</a></li>
		</ul>
	{{end}}
</body>
</html>
`

// HomeEndpoint handles requests to the root path.
func HomeEndpoint(w http.ResponseWriter, r *http.Request, params HomeParams) (endpoint.Renderer, error) {
	session, ok := middleware.SessionFromContext(r.Context())
	data := HomeData{}
	if ok {
		if username, loggedIn := session.Username(); loggedIn {
			data.LoggedIn = true
			data.Username = username
		}
	}

	tmpl, err := template.New("home").Parse(homeTemplate)
	if err != nil {
		return nil, endpoint.Error(http.StatusInternalServerError, "template error", err)
	}

	return &endpoint.HTMLTemplateRenderer{
		Template: tmpl,
		Values:   data,
	}, nil
}

func getGitHubEmail(ctx context.Context, token string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api returned %s", resp.Status)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("no primary verified email found")
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	baseURL := "http://localhost:8080"

	// 1. Setup Session Processor
	// For example purposes, we generate a random key. In production, this should be persisted.
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		log.Fatal(err)
	}

	// Using "OSS" as cookie name (default). Allow non-https cookies, for http://localhost:8080
	sessionProcessor, err := middleware.NewSessionProcessor(
		"key1",
		map[string][]byte{"key1": sessionKey},
		middleware.WithCookieOptions(
			middleware.WithSecure(false),
		),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Setup Auth Handler
	registry := auth.NewRegistry()
	ctx := context.Background()

	// Register Google
	if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
		if clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET"); clientSecret != "" {
			err = registry.RegisterOIDCProvider(ctx,
				"google",
				"https://accounts.google.com",
				clientID,
				clientSecret,
				[]string{oidc.ScopeOpenID, "profile", "email"},
				baseURL+"/auth/callback/google",
			)
			if err != nil {
				log.Printf("Failed to register Google provider: %v", err)
			} else {
				log.Println("Registered Google provider")
			}
		}
	}

	// Register Microsoft
	if clientID := os.Getenv("MICROSOFT_CLIENT_ID"); clientID != "" {
		if clientSecret := os.Getenv("MICROSOFT_CLIENT_SECRET"); clientSecret != "" {
			// Microsoft's OIDC discovery document at /common returns an issuer with the
			// literal placeholder "{tenantid}" rather than a real value. go-oidc's
			// discovery check would fail because that placeholder doesn't match the
			// /common URL we used. InsecureIssuerURLContext bypasses that check.
			//
			// For multi-tenant support, tokens from any Azure AD tenant are accepted.
			// Each token carries a per-tenant issuer such as:
			//   https://login.microsoftonline.com/<tenant-uuid>/v2.0
			// We skip the library's issuer check and validate the pattern ourselves
			// in the result callback below.
			//
			// A good discussion of the common OIDC pitfalls is here:
			// https://zitadel.com/blog/the-broken-promise-of-oidc
			ctx := oidc.InsecureIssuerURLContext(ctx, "https://login.microsoftonline.com/common/v2.0")
			err = registry.RegisterOIDCProvider(ctx,
				"microsoft",
				"https://login.microsoftonline.com/common/v2.0",
				clientID,
				clientSecret,
				[]string{oidc.ScopeOpenID, "profile", "email"},
				baseURL+"/auth/callback/microsoft",
				auth.WithSkipIssuerCheck(),
			)
			if err != nil {
				log.Printf("Failed to register Microsoft provider: %v", err)
			} else {
				log.Println("Registered Microsoft provider")
			}
		}
	}

	// Register GitHub
	if clientID := os.Getenv("GITHUB_CLIENT_ID"); clientID != "" {
		if clientSecret := os.Getenv("GITHUB_CLIENT_SECRET"); clientSecret != "" {
			registry.RegisterOAuth2Provider(
				"github",
				&oauth2.Config{
					ClientID:     clientID,
					ClientSecret: clientSecret,
					Endpoint:     endpoints.GitHub,
					RedirectURL:  baseURL + "/auth/callback/github",
					Scopes:       []string{"user:email"},
				},
			)
			log.Println("Registered GitHub provider")
		}
	}

	// Use "OSA" as cookie name (default).
	authHandler, err := auth.NewHandler(registry, auth.DefaultCookieName, "key1", map[string][]byte{"key1": sessionKey}, baseURL, "/auth",
		auth.WithCookieOptions(
			middleware.WithSecure(false),
		),
		auth.WithResultEndpoint(func(w http.ResponseWriter, r *http.Request, params *auth.AuthResult) (endpoint.Renderer, error) {
			if params.Error != nil {
				return nil, params.Error
			}

			session, ok := middleware.SessionFromContext(r.Context())
			if !ok {
				return nil, fmt.Errorf("session not found in context")
			}

			var email string
			var verified bool

			// For OIDC providers, we can get email from ID Token
			if params.IDToken != nil {
				// For Microsoft multi-tenant, we skipped the library's issuer check.
				// Per the Microsoft identity platform spec, the iss claim must equal
				// https://login.microsoftonline.com/{tid}/v2.0 where tid is the tenant
				// ID claim in the same token. We reconstruct the expected issuer from
				// tid and do an exact match, which also validates cross-claim consistency.
				// See: https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference
				if params.ProviderID == "microsoft" {
					var tidClaims struct {
						TenantID string `json:"tid"`
					}
					if err := params.IDToken.Claims(&tidClaims); err != nil || tidClaims.TenantID == "" {
						return nil, endpoint.Error(http.StatusUnauthorized, "missing tid claim in token", nil)
					}
					expectedIssuer := "https://login.microsoftonline.com/" + tidClaims.TenantID + "/v2.0"
					if params.IDToken.Issuer != expectedIssuer {
						return nil, endpoint.Error(http.StatusUnauthorized, "token issuer does not match tid claim", nil)
					}
				}

				email, verified = auth.GetVerifiedEmail(params.IDToken)
				// Quirk: Microsoft sometimes does not set email_verified even when it is verified
				// Instead, we'll check for the preferred_username claim
				if !verified && params.ProviderID == "microsoft" {
					var claims struct {
						Email          string `json:"email"`
						PreferredEmail string `json:"preferred_username"`
					}
					if err := params.IDToken.Claims(&claims); err == nil {
						verified = claims.PreferredEmail == claims.Email && claims.Email != ""
						if verified {
							email = claims.Email
						}
					}
				}
			} else if params.ProviderID == "github" {
				// Handle GitHub specific logic
				var err error
				email, err = getGitHubEmail(r.Context(), params.Token.AccessToken)
				if err != nil {
					return nil, endpoint.Error(http.StatusInternalServerError, "failed to get github email", err)
				}
				verified = true // If we got it from the API as verified
			}

			if email == "" || !verified {
				return nil, endpoint.Error(http.StatusUnauthorized, "email not verified or missing", nil)
			}
			fmt.Printf("Successful authenticated with provider %v, nextURL %v, verified email %v\n", params.ProviderID, params.AuthParams.NextURL, email)
			if err := session.Login(email); err != nil {
				return nil, endpoint.Error(http.StatusInternalServerError, "login failed", err)
			}

			// Redirect to NextURL or root
			target := params.AuthParams.NextURL
			if target == "" {
				target = "/"
			}
			return &endpoint.RedirectRenderer{URL: target, Status: http.StatusFound}, nil
		}),
		auth.WithProcessors(sessionProcessor),
	)
	if err != nil {
		log.Fatalf("Failed to create auth handler: %v", err)
	}

	// 3. Setup Router
	mux := http.NewServeMux()

	// Mount Auth Handler
	mux.Handle("/auth/", authHandler)

	// Mount Logout Handler
	mux.HandleFunc("/auth/logout", endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, params struct {
		NextURL string `query:"next_url"`
	}) (endpoint.Renderer, error) {
		session, ok := middleware.SessionFromContext(r.Context())
		if ok {
			session.Logout()
		}
		next := auth.ValidateNextURLIsLocal(params.NextURL)
		return &endpoint.RedirectRenderer{URL: next, Status: http.StatusFound}, nil
	}, sessionProcessor))

	// Mount Home Handler (using session middleware handled by root wrapper)
	mux.HandleFunc("/home/", endpoint.HandleFunc(HomeEndpoint, sessionProcessor))

	// Redirect "/" to "/home/"
	mux.HandleFunc("/{$}", endpoint.HandleFunc(func(w http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.RedirectRenderer{URL: "/home/", Status: http.StatusFound}, nil
	}))

	log.Println("Listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
