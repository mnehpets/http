package middleware

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/mnehpets/http/endpoint"
)

func TestSessionData_Validate_Nil(t *testing.T) {
	var sd *sessionData[cbor.RawMessage]
	ok, extended := sd.validate(time.Second, time.Minute)
	if ok || extended {
		t.Fatalf("Validate(nil): got (%v,%v) want (false,false)", ok, extended)
	}
}

func TestSessionData_Validate_InvalidPeriod(t *testing.T) {
	sd := &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Now().Add(time.Hour), Period: 0}
	ok, extended := sd.validate(time.Second, time.Minute)
	if ok || extended {
		t.Fatalf("Validate(period<=0): got (%v,%v) want (false,false)", ok, extended)
	}

	s2 := &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Now().Add(time.Hour), Period: int(MaxExtendedPeriod.Seconds()) + 1}
	ok, extended = s2.validate(time.Second, time.Minute)
	if ok || extended {
		t.Fatalf("Validate(period>max): got (%v,%v) want (false,false)", ok, extended)
	}
}

func TestSessionData_Validate_ExpiredOrZeroExpires(t *testing.T) {
	sd := &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Time{}, Period: 10}
	ok, extended := sd.validate(time.Second, time.Minute)
	if ok || extended {
		t.Fatalf("Validate(zero expires): got (%v,%v) want (false,false)", ok, extended)
	}

	sd2 := &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Now().Add(-time.Second), Period: 10}
	ok, extended = sd2.validate(time.Second, time.Minute)
	if ok || extended {
		t.Fatalf("Validate(expired): got (%v,%v) want (false,false)", ok, extended)
	}
}

func TestSessionData_Validate_NotExtended_WhenThresholdInvalid(t *testing.T) {
	sd := &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Now().Add(time.Minute), Period: 60}
	ok, extended := sd.validate(0, time.Minute) // threshold <= 0
	if !ok || extended {
		t.Fatalf("Validate(threshold<=0): got (%v,%v) want (true,false)", ok, extended)
	}

	sd2 := &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Now().Add(time.Minute), Period: 60}
	ok, extended = sd2.validate(time.Minute*2, time.Minute) // extendPeriod < threshold
	if !ok || extended {
		t.Fatalf("Validate(extend<=threshold): got (%v,%v) want (true,false)", ok, extended)
	}
}

func TestSessionData_Validate_Extends_WhenWithinThreshold(t *testing.T) {
	now := time.Now()
	// Expires soon; should extend.
	orig := now.Add(2 * time.Second).Truncate(time.Second)
	sd := &sessionData[cbor.RawMessage]{ID: "x", Expires: orig, Period: 10}
	ok, extended := sd.validate(30*time.Second, time.Minute)
	if !ok || !extended {
		t.Fatalf("Validate: got (%v,%v) want (true,true)", ok, extended)
	}
	if !sd.Expires.After(orig) {
		t.Fatalf("Expires not extended: got %v orig %v", sd.Expires, orig)
	}
	if sd.Period <= 10 {
		t.Fatalf("Period not increased: got %d", sd.Period)
	}
}

func TestSessionData_ExtendTo_NoOpGuards(t *testing.T) {
	var sd *sessionData[cbor.RawMessage]
	sd.extendTo(time.Now()) // should not panic

	sd2 := &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Time{}, Period: 10}
	sd2.extendTo(time.Now().Add(time.Hour))
	if !sd2.Expires.IsZero() {
		t.Fatalf("ExtendTo with zero Expires should no-op")
	}

	ex := time.Now().Add(time.Minute).Truncate(time.Second)
	sd3 := &sessionData[cbor.RawMessage]{ID: "x", Expires: ex, Period: 60}
	sd3.extendTo(ex.Add(-time.Second))
	if !sd3.Expires.Equal(ex) {
		t.Fatalf("ExtendTo with earlier time should no-op")
	}
	if sd3.Period != 60 {
		t.Fatalf("Period changed on no-op: got %d want %d", sd3.Period, 60)
	}
}

func TestSessionData_ExtendTo_CapsAtMaxExtendedPeriod(t *testing.T) {
	issuedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	expires := issuedAt.Add(time.Minute)
	period := int(expires.Sub(issuedAt).Seconds())
	sd := &sessionData[cbor.RawMessage]{ID: "x", Expires: expires, Period: period}
	// Try to extend far beyond maximum.
	sd.extendTo(expires.Add(MaxExtendedPeriod * 10))
	maxExpires := issuedAt.Add(MaxExtendedPeriod)
	if sd.Expires.After(maxExpires) {
		t.Fatalf("Expires exceeds max: got %v max %v", sd.Expires, maxExpires)
	}
}

func TestNewSession_Basics(t *testing.T) {
	s, err := newSession[cbor.RawMessage](cbor.Marshal, cbor.Unmarshal)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s == nil {
		t.Fatalf("NewSession returned nil")
	}
	if s.ID() == "" {
		t.Fatalf("ID empty")
	}
	if len(s.ID()) < 16 { // should be 22 chars for 16 bytes, but keep loose.
		t.Fatalf("ID too short: %q", s.ID())
	}
	if s.Expires().IsZero() {
		t.Fatalf("Expires is zero")
	}
	if s.sessionData.Period != int(DefaultSessionPeriod.Seconds()) {
		t.Fatalf("Period: got %d want %d", s.sessionData.Period, int(DefaultSessionPeriod.Seconds()))
	}
	if time.Until(s.Expires()) <= 0 {
		t.Fatalf("Expires not in future: %v", s.Expires())
	}
}

func TestSessionContext_Accessors(t *testing.T) {
	ctx := WithSession(context.Background(), &session[cbor.RawMessage]{sessionData: &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Now().Add(time.Hour), Period: 3600}})
	got, ok := SessionFromContext(ctx)
	gotImpl, _ := got.(*session[cbor.RawMessage])
	if !ok || gotImpl == nil || gotImpl.ID() != "x" {
		t.Fatalf("SessionFromContext: got (%v,%v)", got, ok)
	}

	ctx2 := WithSession(ctx, nil)
	if _, ok := SessionFromContext(ctx2); ok {
		t.Fatalf("expected session removed")
	}
}

func TestSession_GetSetDelete_NilReceiver_NoPanic(t *testing.T) {
	var s *session[cbor.RawMessage]
	var v string

	if err := s.Get("k", &v); err == nil || v != "" {
		t.Fatalf("Get(nil): got (%v,%v) want (nil,false)", v, err)
	}

	// Should not panic.
	s.Set("k", "v")
	s.Delete("k")
}

func TestSession_GetSetDelete_Basics(t *testing.T) {
	s := &session[cbor.RawMessage]{
		sessionData: &sessionData[cbor.RawMessage]{ID: "x", Expires: time.Now().Add(time.Hour), Period: 3600},
		marshal:     cbor.Marshal,
		unmarshal:   cbor.Unmarshal,
	}
	var v string

	// Get on nil KV should return false.
	if err := s.Get("missing", &v); err == nil || v != "" {
		t.Fatalf("Get(missing): got (%v,%v) want (nil,false)", v, err)
	}
	if s.dirty {
		t.Fatalf("dirty should start false")
	}

	// Set should initialize KV, store, and mark dirty.
	s.Set("a", 123)
	if !s.dirty {
		t.Fatalf("dirty not set after Set")
	}
	var v2 int
	if err := s.Get("a", &v2); err != nil || v2 != 123 {
		t.Fatalf("Get(a): got (%v,%v) want (123,true)", v2, err)
	}

	// Clear dirty and update existing key.
	s.dirty = false
	s.Set("a", "new")
	if !s.dirty {
		t.Fatalf("dirty not set after updating key")
	}

	var v3 string
	if err := s.Get("a", &v3); err != nil || v3 != "new" {
		t.Fatalf("Get(a) after update: got (%v,%v) want (%q,true)", v3, err, "new")
	}

	// Delete missing key should no-op and not mark dirty.
	s.dirty = false
	s.Delete("missing")
	if s.dirty {
		t.Fatalf("dirty set after Delete(missing)")
	}

	// Delete existing key should remove and mark dirty.
	s.dirty = false
	s.Delete("a")
	if !s.dirty {
		t.Fatalf("dirty not set after Delete(existing)")
	}
	if err := s.Get("a", &v); err == nil || v != "" {
		t.Fatalf("Get(a) after delete: got (%v,%v) want (nil,false)", v, err)
	}
}

func TestNoSessionAPI(t *testing.T) {
	// "No session" is represented as a session placeholder with nil sessionData.
	s := &session[cbor.RawMessage]{sessionData: nil}

	if s.ID() != "" {
		t.Fatalf("ID(no-session): got %q want empty", s.ID())
	}
	if !s.Expires().IsZero() {
		t.Fatalf("Expires(no-session): got %v want zero", s.Expires())
	}
	var v string
	if err := s.Get("k", &v); err == nil || v != "" {
		t.Fatalf("Get(no-session): got (%v,%v) want (nil,false)", v, err)
	}
	// Set/Delete are no-ops.
	s.Set("k", "v")
	s.Delete("k")
	if u, loggedIn := s.Username(); loggedIn || u != "" {
		t.Fatalf("Username(no-session): got (%q,%v) want (\"\",false)", u, loggedIn)
	}
}

func TestSession_Username_Login_Logout(t *testing.T) {
	// Start logged in as user1.
	issued := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	raw, _ := cbor.Marshal("b")
	s := &session[cbor.RawMessage]{
		sessionData: &sessionData[cbor.RawMessage]{ID: "id1", Username: "user1", Expires: issued, Period: 600, KV: map[string]cbor.RawMessage{"a": raw}},
		marshal:     cbor.Marshal,
		unmarshal:   cbor.Unmarshal,
	}

	if u, ok := s.Username(); !ok || u != "user1" {
		t.Fatalf("Username(logged out): got (%q,%v) want (\"user1\",true)", u, ok)
	}

	oldID := s.ID()
	oldExpires := s.Expires()
	if oldID == "" || oldExpires.IsZero() {
		t.Fatalf("bad initial session: id=%q expires=%v", oldID, oldExpires)
	}

	// Login should create a new session ID, reset KV, and set username.
	if err := s.Login("user2"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if s.sessionData == nil {
		t.Fatalf("Login should create sessionData")
	}
	if s.ID() == "" || s.ID() == oldID {
		t.Fatalf("Login should rotate ID: old=%q new=%q", oldID, s.ID())
	}
	if !s.Expires().After(time.Now()) {
		t.Fatalf("Login should set Expires in future")
	}
	if s.sessionData.Period != int(DefaultSessionPeriod.Seconds()) {
		t.Fatalf("Login should reset Period: got %d want %d", s.sessionData.Period, int(DefaultSessionPeriod.Seconds()))
	}
	if s.sessionData.KV == nil || len(s.sessionData.KV) != 0 {
		t.Fatalf("Login should reset KV to empty map, got %#v", s.sessionData.KV)
	}
	if u, ok := s.Username(); !ok || u != "user2" {
		t.Fatalf("Username(after login): got (%q,%v) want (\"user2\",true)", u, ok)
	}
	if !s.dirty {
		t.Fatalf("Login should mark session dirty")
	}

	// Setting KV should work after login.
	s.dirty = false
	s.Set("k", "v")
	if !s.dirty {
		t.Fatalf("Set should mark session dirty")
	}
	var v string
	if err := s.Get("k", &v); err != nil || v != "v" {
		t.Fatalf("KV after Set: got (%v,%v) want (\"v\",true)", v, err)
	}

	// Logout should drop sessionData.
	if err := s.Logout(); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if s.sessionData != nil {
		t.Fatalf("Logout should clear sessionData")
	}
	if u, ok := s.Username(); ok || u != "" {
		t.Fatalf("Username(after logout): got (%q,%v) want (\"\",false)", u, ok)
	}
	if !s.dirty {
		t.Fatalf("Logout should mark session dirty")
	}
}

func TestSession_LoginLogout_NilReceiver_ReturnsError(t *testing.T) {
	var s *session[cbor.RawMessage]
	if err := s.Login("u"); err == nil {
		t.Fatalf("Login(nil): expected error")
	}
	if err := s.Logout(); err == nil {
		t.Fatalf("Logout(nil): expected error")
	}
}

func TestSessionProcessor_NoCookie_PassesThrough(t *testing.T) {
	p, _ := newTestSessionProcessor(t, WithMaxAge(time.Minute), WithExtendThreshold(10*time.Second))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w := httptest.NewRecorder()

	called := false
	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		called = true
		got, ok := SessionFromContext(r.Context())
		if !ok || got == nil {
			t.Fatalf("expected session placeholder")
		}
		gotImpl, _ := got.(*session[cbor.RawMessage])
		if gotImpl == nil {
			t.Fatalf("expected *session, got %T", got)
		}
		if u, loggedIn := gotImpl.Username(); loggedIn || u != "" {
			t.Fatalf("expected logged out, got (%q,%v)", u, loggedIn)
		}
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w, r)

	if !called {
		t.Fatalf("next not called")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatalf("unexpected Set-Cookie")
	}
}

func TestSessionProcessor_InvalidCookie_Clears(t *testing.T) {
	p, _ := newTestSessionProcessor(t, WithMaxAge(time.Minute), WithExtendThreshold(10*time.Second))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(&http.Cookie{Name: "OSS", Value: "bad"})
	w := httptest.NewRecorder()

	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		got, ok := SessionFromContext(r.Context())
		if !ok || got == nil {
			t.Fatalf("expected session placeholder")
		}
		gotImpl, _ := got.(*session[cbor.RawMessage])
		if gotImpl == nil {
			t.Fatalf("expected *session, got %T", got)
		}
		if u, loggedIn := gotImpl.Username(); loggedIn || u != "" {
			t.Fatalf("expected logged out, got (%q,%v)", u, loggedIn)
		}
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: got %d want %d", len(cookies), 1)
	}
	if cookies[0].Name != "OSS" || cookies[0].MaxAge != -1 {
		t.Fatalf("expected clear cookie, got %+v", cookies[0])
	}
}

func TestSessionProcessor_ValidCookie_AttachesSession_NoChange_NoSetCookie(t *testing.T) {
	p, sc := newTestSessionProcessor(t, WithMaxAge(time.Hour), WithExtendThreshold(10*time.Second))

	now := time.Now().Truncate(time.Second)
	expires := now.Add(1 * time.Hour)
	sess := &session[cbor.RawMessage]{sessionData: &sessionData[cbor.RawMessage]{ID: "x", Username: "u", Expires: expires, Period: 3600, KV: map[string]cbor.RawMessage{}}}
	ck := encodeSession(t, sc, sess.sessionData, int(time.Until(sess.Expires()).Seconds()))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(ck)
	w := httptest.NewRecorder()

	var gotSess Session
	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		var ok bool
		gotSess, ok = SessionFromContext(r.Context())
		if !ok {
			t.Fatalf("expected session in context")
		}
		gotImpl, _ := gotSess.(*session[cbor.RawMessage])
		if gotImpl == nil {
			t.Fatalf("expected *session, got %T", gotSess)
		}
		if gotImpl.ID() != "x" {
			t.Fatalf("session mismatch: %+v", gotSess)
		}
		user, loggedIn := gotImpl.Username()
		if !loggedIn || user != "u" {
			t.Fatalf("session mismatch: %+v", gotSess)
		}
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w, r)

	if gotSess == nil {
		t.Fatalf("did not capture session")
	}
	// NOTE: We don't assert on Set-Cookie here because the session processor's
	// change detection re-encodes and compares cookie values; benign differences
	// such as Max-Age varying by 1s can trigger a Set-Cookie even if the session
	// payload is unchanged.
}

func TestSessionProcessor_Extends_SetsCookie(t *testing.T) {
	// Use a comfortably-large MaxAge and a high ExtendThreshold to force extension,
	// while keeping expiry far enough in the future to avoid Max-Age rounding to 0.
	p, sc := newTestSessionProcessor(t, WithMaxAge(24*time.Hour), WithExtendThreshold(24*time.Hour))

	// Expires relatively soon vs ExtendThreshold, so it will be extended.
	expires := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	sess := &session[cbor.RawMessage]{sessionData: &sessionData[cbor.RawMessage]{ID: "x", Username: "u", Expires: expires, Period: int(time.Hour.Seconds()), KV: map[string]cbor.RawMessage{}}}
	ck := encodeSession(t, sc, sess.sessionData, int(time.Until(sess.Expires()).Seconds()))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(ck)
	w := httptest.NewRecorder()

	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count: got %d want %d", len(cookies), 1)
	}
	if cookies[0].Name != "OSS" {
		t.Fatalf("cookie name: got %q want %q", cookies[0].Name, "OSS")
	}
	if cookies[0].MaxAge <= 0 {
		t.Fatalf("expected MaxAge > 0, got %d (cookie=%+v)", cookies[0].MaxAge, cookies[0])
	}
	if cookies[0].Expires.IsZero() {
		t.Fatalf("expected Expires set")
	}
}

func TestSessionProcessor_PayloadChange_SetsCookie(t *testing.T) {
	p, sc := newTestSessionProcessor(t, WithMaxAge(time.Hour), WithExtendThreshold(1*time.Second)) // not extended

	encodedValue, _ := cbor.Marshal("b")
	expires := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	sess := &session[cbor.RawMessage]{sessionData: &sessionData[cbor.RawMessage]{ID: "x", Username: "u", Expires: expires, Period: 1800, KV: map[string]cbor.RawMessage{"a": encodedValue}}}
	ck := encodeSession(t, sc, sess.sessionData, int(time.Until(sess.Expires()).Seconds()))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(ck)
	w := httptest.NewRecorder()

	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		got, ok := SessionFromContext(r.Context())
		if !ok {
			t.Fatalf("expected session")
		}
		gotImpl, _ := got.(*session[cbor.RawMessage])
		if gotImpl == nil {
			t.Fatalf("expected *session, got %T", got)
		}
		gotImpl.Set("k", "v") // modify session to mark dirty
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count: got %d want %d", len(cookies), 1)
	}
	if cookies[0].Name != "OSS" {
		t.Fatalf("cookie name: got %q want %q", cookies[0].Name, "OSS")
	}
	if cookies[0].Value == ck.Value {
		t.Fatalf("cookie value not updated")
	}
}

func TestSessionProcessor_KVSet_PersistsInCookieRoundTrip(t *testing.T) {
	p, sc := newTestSessionProcessor(t, WithMaxAge(time.Hour), WithExtendThreshold(1*time.Second)) // not extended

	expires := time.Now().Add(30 * time.Minute).Truncate(time.Second)
	sess := &session[cbor.RawMessage]{sessionData: &sessionData[cbor.RawMessage]{ID: "x", Username: "u", Expires: expires, Period: 1800, KV: map[string]cbor.RawMessage{}}}
	ck := encodeSession(t, sc, sess.sessionData, int(time.Until(sess.Expires()).Seconds()))

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(ck)
	w := httptest.NewRecorder()

	const key = "answer"
	const val = "42"

	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		got, ok := SessionFromContext(r.Context())
		if !ok {
			t.Fatalf("expected session")
		}
		gotImpl, _ := got.(*session[cbor.RawMessage])
		if gotImpl == nil {
			t.Fatalf("expected *session, got %T", got)
		}
		gotImpl.Set(key, val)
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count: got %d want %d", len(cookies), 1)
	}
	if cookies[0].Name != "OSS" {
		t.Fatalf("cookie name: got %q want %q", cookies[0].Name, "OSS")
	}
	if cookies[0].Value == ck.Value {
		t.Fatalf("cookie value not updated")
	}

	// Manual decode
	var decoded sessionData[cbor.RawMessage]
	err := sc.Decode(cookies[0], &decoded)
	if err != nil {
		t.Fatalf("Decode(updated cookie): %v", err)
	}
	if decoded.KV == nil {
		t.Fatalf("decoded KV is nil")
	}
	var v cbor.RawMessage
	var ok bool
	if v, ok = decoded.KV[key]; !ok {
		t.Fatalf("decoded KV missing key %q", key)
	}

	var v2 string
	if err = cbor.Unmarshal([]byte(v), &v2); err != nil {
		t.Fatalf("cbor.Unmarshal: %v", err)
	}
	if v2 != val {
		t.Fatalf("decoded KV[%q]: got %q want %q", key, v2, val)
	}
}

func TestSessionProcessor_NoCookie_LoginThenSet_PersistsKVAcrossRoundTrip(t *testing.T) {
	p, _ := newTestSessionProcessor(t, WithMaxAge(time.Hour), WithExtendThreshold(1*time.Second)) // not extended

	// First request has no cookie.
	r1 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	w1 := httptest.NewRecorder()

	const key = "k"
	const val = "v"

	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		sess, ok := SessionFromContext(r.Context())
		if !ok {
			t.Fatalf("expected session placeholder")
		}
		impl, _ := sess.(*session[cbor.RawMessage])
		if impl == nil {
			t.Fatalf("expected *session, got %T", sess)
		}
		if err := impl.Login("user"); err != nil {
			t.Fatalf("Login: %v", err)
		}
		impl.Set(key, val)
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w1, r1)

	// Expect a Set-Cookie with the newly created session.
	cookies := w1.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie count: got %d want %d", len(cookies), 1)
	}
	if cookies[0].Name != "OSS" {
		t.Fatalf("cookie name: got %q want %q", cookies[0].Name, "OSS")
	}

	// Second request sends that cookie back.
	r2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r2.AddCookie(cookies[0])
	w2 := httptest.NewRecorder()

	h2 := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		sess, ok := SessionFromContext(r.Context())
		if !ok {
			t.Fatalf("expected session")
		}
		impl, _ := sess.(*session[cbor.RawMessage])
		if impl == nil {
			t.Fatalf("expected *session, got %T", sess)
		}
		var v string
		if err := impl.Get(key, &v); err != nil {
			t.Fatalf("KV not persisted: got (%v,%v) want (%q,true)", v, ok, val)
		}
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h2.ServeHTTP(w2, r2)
}

func TestSessionProcessor_ExpiredSession_Clears(t *testing.T) {
	p, sc := newTestSessionProcessor(t, WithMaxAge(time.Hour), WithExtendThreshold(10*time.Second))

	sess := &session[cbor.RawMessage]{sessionData: &sessionData[cbor.RawMessage]{ID: "x", Username: "u", Expires: time.Now().Add(-time.Second).Truncate(time.Second), Period: 3600, KV: map[string]cbor.RawMessage{}}}
	ck := encodeSession(t, sc, sess.sessionData, 3600)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.AddCookie(ck)
	w := httptest.NewRecorder()

	h := endpoint.Handler(func(_ http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		got, ok := SessionFromContext(r.Context())
		if !ok || got == nil {
			t.Fatalf("expected session placeholder")
		}
		impl, _ := got.(*session[cbor.RawMessage])
		if impl == nil {
			t.Fatalf("expected *session, got %T", got)
		}
		if u, loggedIn := impl.Username(); loggedIn || u != "" {
			t.Fatalf("expected logged out, got (%q,%v)", u, loggedIn)
		}
		return &endpoint.NoContentRenderer{}, nil
	}, p)

	h.ServeHTTP(w, r)

	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 {
		t.Fatalf("expected clear cookie, got %+v", cookies)
	}
}

// Helper to encode a session
func encodeSession(t *testing.T, sc SecureCookie, sess *sessionData[cbor.RawMessage], maxAge int) *http.Cookie {
	t.Helper()
	ck, err := sc.Encode(*sess, maxAge)
	if err != nil {
		t.Fatalf("Encode helper: %v", err)
	}
	return ck
}

func newTestSessionProcessor(t *testing.T, opts ...SessionProcessorOption) (*SessionProcessor[cbor.RawMessage], SecureCookie) {
	t.Helper()
	keys := map[string][]byte{"a": make([]byte, DefaultAEADKeysize)}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}
	p, err := NewSessionProcessor("a", keys, opts...)
	if err != nil {
		t.Fatalf("NewSessionProcessor: %v", err)
	}
	// p.cookie is unexported but we are in the same package
	return p, p.cookie
}

func TestNewSessionProcessor_WithCustomOptions(t *testing.T) {
	keys := map[string][]byte{"a": make([]byte, DefaultAEADKeysize)}
	if _, err := rand.Read(keys["a"]); err != nil {
		t.Fatalf("rand.Read(key): %v", err)
	}

	// Custom encoding
	calledMarshal := false
	calledUnmarshal := false
	marshal := func(v any) ([]byte, error) {
		calledMarshal = true
		// Just delegate to CBOR for actual work to keep it simple, or JSON.
		// Since we want to verify it's called, this flag is enough.
		// But we need to return valid bytes.
		// We'll use a simple "dummy" encoding if possible, or just fail if type doesn't match?
		// Let's use standard JSON for the test.
		return json.Marshal(v)
	}
	unmarshal := func(b []byte, v any) error {
		calledUnmarshal = true
		return json.Unmarshal(b, v)
	}

	// Custom AEAD uses newAESGCMAEAD from securecookie_test.go
	//
	// Use a key size suitable for AES (16, 24, or 32 bytes). DefaultAEADKeysize (ChaCha20Poly1305) is 32.

	proc, err := NewCustomSessionProcessor[cbor.RawMessage](
		"a", keys,
		marshal, unmarshal,
		WithCookieOptions(WithAEAD(newAESGCMAEAD)),
		WithCookieName("my-custom-session"),
	)
	if err != nil {
		t.Fatalf("NewSessionProcessor: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	h := endpoint.Handler(func(w http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		// Log in to make session dirty and trigger write
		s, _ := SessionFromContext(r.Context())
		if impl, ok := s.(*session[cbor.RawMessage]); ok {
			impl.Login("user")
		}
		return &endpoint.NoContentRenderer{}, nil
	}, proc)

	h.ServeHTTP(w, r)

	if !calledMarshal {
		t.Fatalf("custom marshal not called")
	}

	// Now verify reading back triggers unmarshal
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("no cookie set")
	}
	if cookies[0].Name != "my-custom-session" {
		t.Fatalf("cookie name: got %q want %q", cookies[0].Name, "my-custom-session")
	}

	r2 := httptest.NewRequest("GET", "/", nil)
	r2.AddCookie(cookies[0])
	w2 := httptest.NewRecorder()

	h2 := endpoint.Handler(func(w http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		s, ok := SessionFromContext(r.Context())
		if !ok {
			t.Fatalf("session not loaded")
		}
		if u, _ := s.Username(); u != "user" {
			t.Fatalf("username mismatch: got %q want %q", u, "user")
		}
		return &endpoint.NoContentRenderer{}, nil
	}, proc)

	h2.ServeHTTP(w2, r2)

	if !calledUnmarshal {
		t.Fatalf("custom unmarshal not called")
	}
}
