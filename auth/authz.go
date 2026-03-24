package auth

import (
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
)

// MatchEmailGlob is intended for applications that store the user's email address
// as the session username. It validates patterns at construction time and returns
// a match function that reports whether an email address matches any of the
// provided glob patterns.
// '@' is treated as a separator: wildcards, '?', and character ranges (including
// negated ranges) do not match '@'; only a literal '@' in a pattern matches '@'
// in the input.
// Returns an error if any pattern is malformed.
//
// Matching is case-sensitive. Callers are responsible for normalising case (e.g.
// strings.ToLower) before invoking the returned function if case-insensitive
// matching is required.
func MatchEmailGlob(patterns []string) (func(email string) bool, error) {
	if len(patterns) == 0 {
		return func(string) bool { return false }, nil
	}

	// Pre-process patterns: replace '@' with '/' so that path.Match treats '@'
	// as a separator, preventing wildcards and ranges from matching across it.
	// '/' is forbidden in patterns because it is used internally as the
	// separator substitution character; a pattern containing '/' would produce
	// ambiguous results.
	processed := make([]string, len(patterns))
	for i, p := range patterns {
		if strings.ContainsRune(p, '/') {
			return nil, fmt.Errorf("auth: pattern %q must not contain '/'", p)
		}
		pp := strings.ReplaceAll(p, "@", "/")
		if _, err := path.Match(pp, ""); err != nil {
			return nil, fmt.Errorf("auth: malformed pattern %q: %w", p, err)
		}
		processed[i] = pp
	}

	return func(email string) bool {
		// Structural check: exactly one '@', non-empty local part and domain.
		// Emails containing '/' are rejected because '/' is used internally as
		// the separator substitution character and would produce incorrect matches.
		// ('/' is technically valid in local parts per RFC 5321 but vanishingly
		// rare in practice.)
		at := strings.IndexByte(email, '@')
		if at <= 0 || at == len(email)-1 {
			return false
		}
		if strings.IndexByte(email[at+1:], '@') != -1 {
			return false
		}
		if strings.IndexByte(email, '/') != -1 {
			return false
		}

		transformed := strings.ReplaceAll(email, "@", "/")
		for _, p := range processed {
			if matched, _ := path.Match(p, transformed); matched {
				return true
			}
		}
		return false
	}, nil
}

// RequireUsernameMatchProcessor is a Processor that enforces username-based
// authorisation by checking the session username against a caller-supplied policy.
type RequireUsernameMatchProcessor struct {
	matchFn   func(username string) bool
	onFailure func(http.ResponseWriter, *http.Request) (endpoint.Renderer, error)
}

// NewRequireUsernameMatchProcessor returns a processor that reads the authenticated
// username from the session, calls matchFn, and on success returns next(w, r).
// On failure (not logged in, or matchFn returns false) it returns onFailure(w, r)
// without calling next. If no session is present in the context (indicating
// SessionProcessor is not installed), it returns a non-nil error.
// onFailure may return an endpoint.EndpointError to control the HTTP status code.
// Returns an error if matchFn or onFailure is nil.
//
// Note: matchFn receives the raw username string from the session without
// validation. Ensuring that only well-formed usernames are stored in the session
// is the application's responsibility.
func NewRequireUsernameMatchProcessor(
	matchFn func(username string) bool,
	onFailure func(http.ResponseWriter, *http.Request) (endpoint.Renderer, error),
) (*RequireUsernameMatchProcessor, error) {
	if matchFn == nil {
		return nil, errors.New("auth: matchFn must not be nil")
	}
	if onFailure == nil {
		return nil, errors.New("auth: onFailure must not be nil")
	}
	return &RequireUsernameMatchProcessor{matchFn: matchFn, onFailure: onFailure}, nil
}

// Process implements endpoint.Processor.
func (p *RequireUsernameMatchProcessor) Process(
	w http.ResponseWriter,
	r *http.Request,
	next func(http.ResponseWriter, *http.Request) (endpoint.Renderer, error),
) (endpoint.Renderer, error) {
	sess, ok := middleware.SessionFromContext(r.Context())
	if !ok {
		return nil, errors.New("auth: RequireUsernameMatchProcessor requires SessionProcessor to be installed")
	}
	username, loggedIn := sess.Username()
	if !loggedIn {
		return p.onFailure(w, r)
	}
	if !p.matchFn(username) {
		return p.onFailure(w, r)
	}
	return next(w, r)
}

var _ endpoint.Processor = (*RequireUsernameMatchProcessor)(nil)
