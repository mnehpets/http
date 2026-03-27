package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/middleware"
)

// mockSession is a minimal middleware.Session for use in tests.
type mockSession struct {
	username string
	loggedIn bool
}

func (m *mockSession) ID() string                     { return "test-id" }
func (m *mockSession) Username() (string, bool)       { return m.username, m.loggedIn }
func (m *mockSession) Login(username string) error    { m.username = username; m.loggedIn = true; return nil }
func (m *mockSession) Logout() error                  { m.username = ""; m.loggedIn = false; return nil }
func (m *mockSession) Expires() time.Time             { return time.Time{} }
func (m *mockSession) Get(key string, dest any) error          { return nil }
func (m *mockSession) Set(key string, value any) error         { return nil }
func (m *mockSession) Delete(key string)                       {}
func (m *mockSession) MaybeSetCookie(w http.ResponseWriter) {}

// injectSession wraps h, placing sess into the request context before serving.
func injectSession(h http.Handler, sess middleware.Session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(middleware.WithSession(r.Context(), sess))
		h.ServeHTTP(w, r)
	})
}

// --- MatchEmailGlob tests ---

func TestMatchEmailGlob_EmptyPatterns_NeverMatches(t *testing.T) {
	fn, err := MatchEmailGlob(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, email := range []string{"alice@example.com", "bob@other.org", ""} {
		if fn(email) {
			t.Errorf("expected false for %q with empty patterns, got true", email)
		}
	}
}

func TestMatchEmailGlob_MalformedPattern_ReturnsError(t *testing.T) {
	_, err := MatchEmailGlob([]string{"alice@[example.com"})
	if err == nil {
		t.Fatal("expected error for malformed pattern, got nil")
	}
}

func TestMatchEmailGlob_ExactMatch(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"alice@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@example.com") {
		t.Error("expected true for exact match")
	}
	if fn("bob@example.com") {
		t.Error("expected false for non-matching email")
	}
}

func TestMatchEmailGlob_LocalPartWildcard(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@example.com") {
		t.Error("expected true for alice@example.com")
	}
	if !fn("bob@example.com") {
		t.Error("expected true for bob@example.com")
	}
	// * must not span @
	if fn("alice@sub.example.com") {
		t.Error("expected false: * should not match across @")
	}
}

func TestMatchEmailGlob_SubdomainWildcard(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*@*.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@sub.example.com") {
		t.Error("expected true for alice@sub.example.com")
	}
	// The domain wildcard * also must not span further dots, so it won't
	// match a bare domain.
	if fn("alice@example.com") {
		t.Error("expected false for alice@example.com against *@*.example.com")
	}
}

func TestMatchEmailGlob_DomainWildcard(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"alice@*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@example.com") {
		t.Error("expected true for alice@example.com")
	}
	if !fn("alice@other.org") {
		t.Error("expected true for alice@other.org")
	}
	if fn("bob@example.com") {
		t.Error("expected false for bob@example.com")
	}
}

func TestMatchEmailGlob_StarAlone_NoMatch(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("alice@example.com") {
		t.Error("expected false: * alone cannot span @")
	}
	if fn("") {
		t.Error("expected false for empty string")
	}
}

func TestMatchEmailGlob_DoubleStar_SameAsStar(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"**"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ** has no special meaning; behaves like *, cannot span @.
	if fn("alice@example.com") {
		t.Error("expected false: ** should not match across @")
	}
	if fn("") {
		t.Error("expected false for empty string")
	}
}

func TestMatchEmailGlob_QuestionMark(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"ali?e@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@example.com") {
		t.Error("expected true for ali?e matching alice")
	}
	if fn("ali@e@example.com") {
		t.Error("expected false: ? should not match @")
	}
}

func TestMatchEmailGlob_CharacterRange(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"[ab]lice@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@example.com") {
		t.Error("expected true for alice")
	}
	if !fn("blice@example.com") {
		t.Error("expected true for blice")
	}
	if fn("clice@example.com") {
		t.Error("expected false for clice")
	}
}

func TestMatchEmailGlob_NegatedRange_DoesNotMatchSeparator(t *testing.T) {
	// [^x] should not match @.
	fn, err := MatchEmailGlob([]string{"[^x]lice@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@example.com") {
		t.Error("expected true for alice")
	}
	// An input contrived to put @ in the local part position would still fail
	// the structural check, so we verify via the structural path.
	if fn("@lice@example.com") {
		t.Error("expected false: empty local part fails structural check")
	}
}

func TestMatchEmailGlob_StructuralCheck_EmptyString(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*@*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("") {
		t.Error("expected false for empty string")
	}
}

func TestMatchEmailGlob_StructuralCheck_NoAt(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("alice") {
		t.Error("expected false for string with no @")
	}
}

func TestMatchEmailGlob_StructuralCheck_MultipleAt(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*@*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("a@b@c") {
		t.Error("expected false for string with multiple @")
	}
}

func TestMatchEmailGlob_StructuralCheck_EmptyLocalPart(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*@*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("@example.com") {
		t.Error("expected false for empty local part")
	}
}

func TestMatchEmailGlob_StructuralCheck_EmptyDomain(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"*@*"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("alice@") {
		t.Error("expected false for empty domain")
	}
}

func TestMatchEmailGlob_PatternWithSlash_ReturnsError(t *testing.T) {
	_, err := MatchEmailGlob([]string{"a/b@example.com"})
	if err == nil {
		t.Fatal("expected error for pattern containing '/'")
	}
}

func TestMatchEmailGlob_EmailWithSlash_NoMatch(t *testing.T) {
	// '/' is valid in email local parts per RFC 5321 but unsupported here.
	fn, err := MatchEmailGlob([]string{"*@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("a/b@example.com") {
		t.Error("expected false for email containing '/' (unsupported)")
	}
}

func TestMatchEmailGlob_CaseSensitive(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"alice@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fn("Alice@example.com") {
		t.Error("expected false: matching is case-sensitive")
	}
	if fn("alice@Example.com") {
		t.Error("expected false: matching is case-sensitive")
	}
}

func TestMatchEmailGlob_MultiplePatterns_MatchesAny(t *testing.T) {
	fn, err := MatchEmailGlob([]string{"alice@example.com", "*@other.org"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fn("alice@example.com") {
		t.Error("expected true via first pattern")
	}
	if !fn("bob@other.org") {
		t.Error("expected true via second pattern")
	}
	if fn("bob@example.com") {
		t.Error("expected false: matches neither pattern")
	}
}

// --- NewRequireUsernameMatchProcessor tests ---

func TestNewRequireUsernameMatchProcessor_NilMatchFn(t *testing.T) {
	_, err := NewRequireUsernameMatchProcessor(nil, func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
		return &endpoint.NoContentRenderer{Status: http.StatusUnauthorized}, nil
	})
	if err == nil {
		t.Fatal("expected error for nil matchFn")
	}
}

func TestNewRequireUsernameMatchProcessor_NilOnFailure(t *testing.T) {
	_, err := NewRequireUsernameMatchProcessor(func(string) bool { return true }, nil)
	if err == nil {
		t.Fatal("expected error for nil onFailure")
	}
}

func TestRequireUsernameMatchProcessor_NoSession_ReturnsError(t *testing.T) {
	proc, err := NewRequireUsernameMatchProcessor(
		func(string) bool { return true },
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			return &endpoint.NoContentRenderer{Status: http.StatusUnauthorized}, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.StringRenderer{Body: "ok"}, nil
	}, proc)

	// No session injected into context.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for missing SessionProcessor, got %d", rec.Code)
	}
}

func TestRequireUsernameMatchProcessor_NotLoggedIn_CallsOnFailure(t *testing.T) {
	onFailureCalled := false
	proc, err := NewRequireUsernameMatchProcessor(
		func(string) bool { return true },
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			onFailureCalled = true
			return &endpoint.NoContentRenderer{Status: http.StatusUnauthorized}, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	endpointCalled := false
	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		endpointCalled = true
		return &endpoint.StringRenderer{Body: "ok"}, nil
	}, proc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	injectSession(h, &mockSession{loggedIn: false}).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
	if !onFailureCalled {
		t.Error("expected onFailure to be called")
	}
	if endpointCalled {
		t.Error("expected endpoint not to be called")
	}
}

func TestRequireUsernameMatchProcessor_MatchFnFalse_CallsOnFailure(t *testing.T) {
	var receivedUsername string
	proc, err := NewRequireUsernameMatchProcessor(
		func(username string) bool {
			receivedUsername = username
			return false
		},
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			return &endpoint.NoContentRenderer{Status: http.StatusForbidden}, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	endpointCalled := false
	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		endpointCalled = true
		return &endpoint.StringRenderer{Body: "ok"}, nil
	}, proc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	injectSession(h, &mockSession{username: "alice@example.com", loggedIn: true}).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
	if receivedUsername != "alice@example.com" {
		t.Errorf("expected matchFn to receive %q, got %q", "alice@example.com", receivedUsername)
	}
	if endpointCalled {
		t.Error("expected endpoint not to be called")
	}
}

func TestRequireUsernameMatchProcessor_MatchFnTrue_CallsNext(t *testing.T) {
	proc, err := NewRequireUsernameMatchProcessor(
		func(string) bool { return true },
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			return &endpoint.NoContentRenderer{Status: http.StatusForbidden}, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.StringRenderer{Body: "welcome"}, nil
	}, proc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	injectSession(h, &mockSession{username: "alice@example.com", loggedIn: true}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "welcome" {
		t.Errorf("expected body %q, got %q", "welcome", got)
	}
}

func TestRequireUsernameMatchProcessor_EmptyUsername_PassedToMatchFn(t *testing.T) {
	var receivedUsername string
	proc, err := NewRequireUsernameMatchProcessor(
		func(username string) bool {
			receivedUsername = username
			return false
		},
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			return &endpoint.NoContentRenderer{Status: http.StatusForbidden}, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.StringRenderer{Body: "ok"}, nil
	}, proc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Session is logged in but username is the empty string.
	injectSession(h, &mockSession{username: "", loggedIn: true}).ServeHTTP(rec, req)

	if receivedUsername != "" {
		t.Errorf("expected matchFn to receive empty string, got %q", receivedUsername)
	}
}

func TestRequireUsernameMatchProcessor_OnFailureEndpointError_ControlsStatus(t *testing.T) {
	proc, err := NewRequireUsernameMatchProcessor(
		func(string) bool { return false },
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			return nil, endpoint.Error(http.StatusForbidden, "forbidden", nil)
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.StringRenderer{Body: "ok"}, nil
	}, proc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	injectSession(h, &mockSession{username: "alice@example.com", loggedIn: true}).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 from EndpointError, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "forbidden") {
		t.Errorf("expected body to contain %q, got %q", "forbidden", rec.Body.String())
	}
}

func TestRequireUsernameMatchProcessor_WithMatchEmailGlob(t *testing.T) {
	// Integration: MatchEmailGlob used as matchFn.
	matchFn, err := MatchEmailGlob([]string{"*@example.com"})
	if err != nil {
		t.Fatalf("MatchEmailGlob error: %v", err)
	}

	proc, err := NewRequireUsernameMatchProcessor(
		matchFn,
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			return &endpoint.NoContentRenderer{Status: http.StatusForbidden}, nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.StringRenderer{Body: "ok"}, nil
	}, proc)

	t.Run("matching domain passes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		injectSession(h, &mockSession{username: "alice@example.com", loggedIn: true}).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("non-matching domain blocked", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		injectSession(h, &mockSession{username: "alice@other.org", loggedIn: true}).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("not logged in blocked", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		injectSession(h, &mockSession{loggedIn: false}).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("no session is 500", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h.ServeHTTP(rec, req) // no session injected
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", rec.Code)
		}

		// Also verify this isn't an onFailure path — body should be the error text.
		if !strings.Contains(rec.Body.String(), "SessionProcessor") {
			t.Errorf("expected error message to mention SessionProcessor, got %q", rec.Body.String())
		}
	})
}

// Verify that the returned error from onFailure (not an EndpointError) propagates.
func TestRequireUsernameMatchProcessor_OnFailureError_Propagates(t *testing.T) {
	sentinel := errors.New("onFailure internal error")
	proc, err := NewRequireUsernameMatchProcessor(
		func(string) bool { return false },
		func(w http.ResponseWriter, r *http.Request) (endpoint.Renderer, error) {
			return nil, sentinel
		},
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}

	h := endpoint.Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.StringRenderer{Body: "ok"}, nil
	}, proc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	injectSession(h, &mockSession{username: "alice@example.com", loggedIn: true}).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for non-EndpointError from onFailure, got %d", rec.Code)
	}
}
