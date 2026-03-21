package auth

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

// AuthStateMap is the type stored in the cookie (state -> AuthState).
type AuthStateMap map[string]AuthState

// AuthState represents the state of an in-flight OAuth flow.
// It is stored in a secure cookie, keyed by the state parameter sent to the provider.
type AuthState struct {
	AuthParams AuthParams `cbor:"1,keyasint,omitempty"`

	// Nonce is the OIDC nonce sent to the provider (if OIDC is used).
	// It must be verified against the ID Token upon return.
	Nonce string `cbor:"2,keyasint,omitempty"`

	// PKCEVerifier is the code verifier for PKCE flows.
	PKCEVerifier string `cbor:"3,keyasint,omitempty"`

	// ExpiresAt is the timestamp when this state expires.
	ExpiresAt time.Time `cbor:"4,keyasint,omitempty"`
}

// stateLength is the number of random bytes used to generate the state parameter.
// 32 bytes provides 256 bits of entropy, which is sufficient to prevent collisions
// and brute-force attacks on the state parameter even with a large number of concurrent flows.
const stateLength = 32

// generateRandomToken creates a random, URL-safe token string.
// It is used for generating both the OAuth state key and the OIDC nonce.
func generateRandomToken() (string, error) {
	b := make([]byte, stateLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
