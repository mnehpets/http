package middleware

// Session middleware for the endpoint processor/renderer pipeline.
//
// This file defines the session type + context accessors.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/mnehpets/http/endpoint"
)

var ErrNilSession = errors.New("nil session")

// SessionIDBytes is the number of random bytes used to generate a session ID.
//
// 16 bytes -> 22 chars raw URL base64.
const SessionIDBytes = 16

// DefaultSessionPeriod is the default session lifetime.
const DefaultSessionPeriod = time.Hour * 24

// MaxExtendedPeriod bounds how long a session may live in total,
// even if continually extended.
const MaxExtendedPeriod = time.Hour * 24 * 90

// DefaultSessionRevalidationExtendThreshold is the default threshold for extending a session before it expires.
const DefaultSessionRevalidationExtendThreshold = DefaultSessionPeriod / 4

// DefaultCookieName is the default name for the session cookie.
const DefaultCookieName = "OSS"

type ByteSlice interface {
	~[]byte
}

// Session is request-scoped session state.
type Session interface {
	// ID returns the session identifier.
	// Returns an empty string if the user is not logged in.
	ID() string
	// Username returns the authenticated username and a boolean flag indicating
	// whether the user is logged in.
	// The second return value is true if the user is logged in, false otherwise.
	// When the user is not logged in, the username is an empty string.
	Username() (string, bool)
	// Login authenticates the user with the given username.
	// This creates a new session with a fresh session ID and clears any existing session data.
	// Returns an error if session creation fails (e.g., insufficient randomness for session ID).
	Login(username string) error
	// Logout clears the session data and logs out the user.
	Logout() error
	// Expires returns the expiration time of the session.
	// Returns the zero time if the user is not logged in.
	Expires() time.Time
	// Get unmarshals the value associated with key into dest.
	// dest must be a pointer.
	Get(key string, dest any) error
	// Set stores the value associated with key.
	// value will be marshaled using the session's codec.
	Set(key string, value any) error
	// Delete removes the value associated with key from the session.
	// This is a no-op if the key does not exist or the user is not logged in.
	Delete(key string)
	// MaybeSetCookie writes a Set-Cookie header to w if the session has been
	// mutated since it was loaded. It is called by SessionProcessor after next()
	// returns. External implementations should leave this as a no-op.
	MaybeSetCookie(w http.ResponseWriter)
}

// sessionData[Raw] is the serializable session state.
//
// It is designed to be serialized/deserialized using the middleware secure-cookie
// marshal/unmarshal funcs (see `SecureCookieAEAD`), which defaults to CBOR.
type sessionData[Raw ByteSlice] struct {
	// ID is a random session identifier.
	ID string `cbor:"1,keysasint"`
	// Username is the authenticated username.
	Username string `cbor:"2,keysasint"`
	// Expires is the absolute expiry time for session validity.
	Expires time.Time `cbor:"3,keysasint"`
	// Period is the difference between the creation time and expiry time in seconds.
	// Note that the semantics differs from MaxAge in http.Cookie, which is relative to
	// the time the cookie is set.
	Period int `cbor:"4,keysasint"`
	// KV is an application-owned key/value bag.
	KV map[string]Raw `cbor:"5,keysasint,omitempty"`
}

// session implements Session interface with sessionData[Raw] as the underlying data,
// and with a dirty flag to track modification.
type session[Raw ByteSlice] struct {
	sessionData *sessionData[Raw]
	// cookie is used to encode/clear the session cookie.
	cookie SecureCookie
	// marshal encodes a user-supplied value into a Raw value.
	marshal func(any) ([]byte, error)
	// unmarshal decodes a Raw value into a user-supplied value.
	unmarshal func([]byte, any) error
	// dirty indicates whether the session data has been modified.
	dirty bool
}

func (s *session[Raw]) MaybeSetCookie(w http.ResponseWriter) {
	if s == nil || s.cookie == nil {
		return
	}
	if s.sessionData == nil {
		if s.dirty {
			http.SetCookie(w, s.cookie.Clear())
			s.dirty = false
		}
		return
	}
	maxAge := int(time.Until(s.sessionData.Expires).Seconds())
	if maxAge <= 0 {
		http.SetCookie(w, s.cookie.Clear())
		s.dirty = false
		return
	}
	if s.dirty {
		if c, err := s.cookie.Encode(*s.sessionData, maxAge); err == nil {
			http.SetCookie(w, c)
			s.dirty = false
		}
	}
}

func (s *session[Raw]) ID() string {
	if s == nil || s.sessionData == nil {
		return ""
	}
	return s.sessionData.ID
}

func (s *session[Raw]) Username() (string, bool) {
	if s == nil || s.sessionData == nil {
		return "", false
	}
	return s.sessionData.Username, true
}

func (s *session[Raw]) Login(username string) error {
	if s == nil {
		return ErrNilSession
	}
	// Regenerate session state on login to prevent session fixation.
	sd, err := newSessionData[Raw]()
	if err != nil {
		return err
	}
	sd.Username = username
	s.sessionData = sd
	s.dirty = true
	return nil
}

func (s *session[Raw]) Logout() error {
	if s == nil {
		return ErrNilSession
	}
	// Logout clears the cookie and removes session state.
	s.sessionData = nil
	s.dirty = true
	return nil
}

func (s *session[Raw]) Expires() time.Time {
	if s == nil || s.sessionData == nil {
		return time.Time{}
	}
	return s.sessionData.Expires
}

func (s *session[Raw]) Get(key string, dest any) error {
	if s == nil || s.sessionData == nil {
		return errors.New("user not logged in")
	}
	raw, ok := s.sessionData.KV[key]
	if !ok {
		return errors.New("key not found")
	}
	if s.unmarshal == nil {
		return errors.New("no value decoder configured")
	}
	return s.unmarshal([]byte(raw), dest)
}

func (s *session[Raw]) Set(key string, value any) error {
	if s == nil {
		return ErrNilSession
	}
	if s.sessionData == nil {
		// Auto-initialize? Or error? sessionData usually comes from cookie or login.
		// If we are setting data on a nil sessionData (e.g. no cookie yet), we should init it.
		// But newSessionData needs to be called.
		// For now, let's assume we can't set on a nil session (should have been created by middleware).
		return errors.New("user not logged in")
	}
	if s.marshal == nil {
		return errors.New("no value encoder configured")
	}

	raw, err := s.marshal(value)
	if err != nil {
		return err
	}

	if s.sessionData.KV == nil {
		s.sessionData.KV = map[string]Raw{}
	}
	s.sessionData.KV[key] = raw
	s.dirty = true
	return nil
}

func (s *session[Raw]) Delete(key string) {
	if s == nil || s.sessionData == nil {
		return
	}
	if s.sessionData.KV == nil {
		return
	}
	if _, ok := s.sessionData.KV[key]; !ok {
		return
	}
	delete(s.sessionData.KV, key)
	s.dirty = true
}

// newSessionData creates a new sessionData[Raw] with a random ID and default expiration.
func newSessionData[Raw ByteSlice]() (*sessionData[Raw], error) {
	b := make([]byte, SessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	// Default expiration is based on time of creation.
	// Truncate to second precision moves the creation time backwards, which
	// ensures the start of the valid period is in the past.
	now := time.Now().Truncate(time.Second)
	maxAge := DefaultSessionPeriod
	return &sessionData[Raw]{
		ID:      base64.RawURLEncoding.EncodeToString(b),
		Expires: now.Add(maxAge),
		Period:  int(maxAge.Seconds()),
		KV:      map[string]Raw{},
	}, nil
}

// validate checks whether the session is valid at time now.
//
// If the session is expired, it returns (false, false).
// If the session is valid, and the remaining time before expiry is less than extendThreshold,
// it extends the session by extendPeriod and returns (true, true).
func (sd *sessionData[Raw]) validate(extendThreshold, extendPeriod time.Duration) (ok bool, extended bool) {
	if sd == nil {
		return false, false
	}

	now := time.Now()

	// Defensive validation: Period participates in maximum-lifetime calculations.
	// Reject clearly invalid values.
	if sd.Period <= 0 {
		return false, false
	}
	maxPeriod := int(MaxExtendedPeriod.Seconds())
	if sd.Period > maxPeriod {
		return false, false
	}

	// If session has expired or Expires is not set, treat as invalid.
	if sd.Expires.IsZero() || !now.Before(sd.Expires) {
		return false, false
	}

	if extendThreshold <= 0 || extendPeriod <= 0 || extendPeriod < extendThreshold {
		return true, false
	}
	if sd.Expires.Sub(now) < extendThreshold {
		// If less than extendThreshold remaining, extend session
		// to a maximum age of extendPeriod from now.
		sd.extendTo(now.Add(extendPeriod))
		return true, true
	}
	return true, false
}

// extendTo sets the absolute expiry time for the session.
//
// If newExpires is not after the current Expires, this is a no-op.
// Period is increased by the amount Expires moves forward (in whole seconds).
func (sd *sessionData[Raw]) extendTo(newExpires time.Time) {
	if sd == nil {
		return
	}
	if sd.Expires.IsZero() {
		return
	}
	newExpires = newExpires.Truncate(time.Second)
	if !newExpires.After(sd.Expires) {
		return
	}

	// Enforce an absolute maximum lifetime.
	issuedAt := sd.Expires.Add(-time.Duration(sd.Period) * time.Second)
	maxExpires := issuedAt.Add(MaxExtendedPeriod)
	if newExpires.After(maxExpires) {
		newExpires = maxExpires
	}
	if !newExpires.After(sd.Expires) {
		return
	}

	delta := newExpires.Sub(sd.Expires)
	sd.Period += int(delta.Seconds())
	sd.Expires = newExpires
}

// newSession creates a session with initialized session data.
func newSession[Raw ByteSlice](marshal func(any) ([]byte, error), unmarshal func([]byte, any) error) (*session[Raw], error) {
	sd, err := newSessionData[Raw]()
	if err != nil {
		return nil, err
	}
	return &session[Raw]{
		sessionData: sd,
		dirty:       true,
		marshal:     marshal,
		unmarshal:   unmarshal,
	}, nil
}

// sessionContextKey is an unexported unique key for storing sessions in context.
type sessionContextKey struct{}

// WithSession stores sess in ctx and returns the derived context.
func WithSession(ctx context.Context, sess Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, sess)
}

// SessionFromContext returns the Session stored in ctx, if any.
func SessionFromContext(ctx context.Context) (Session, bool) {
	sess, ok := ctx.Value(sessionContextKey{}).(Session)
	if !ok || sess == nil {
		return nil, false
	}
	return sess, true
}

// SessionProcessor is an endpoint processor that revalidates a session and can
// optionally extend it.
//
// Config:
//   - MaxAge: if > 0 and session.MaxAge is 0, initialize session MaxAge/Expires.
//   - ExtendThreshold: extend only when time remaining is less than this.
type SessionProcessor[Raw ByteSlice] struct {
	cookie          SecureCookie
	MaxAge          time.Duration
	ExtendThreshold time.Duration
	marshal         func(any) ([]byte, error)
	unmarshal       func([]byte, any) error
}

// SessionProcessorOption configures the SessionProcessor.
type SessionProcessorOption func(*sessionProcessorConfig)

// We keep the configuration separate from SessionProcessor so that
// it doesn't have the `Raw` type parameter. This means that the
// option functions can be shared between generic NewCustomSessionProcessor
// and non-generic NewSessionProcessor,
type sessionProcessorConfig struct {
	cookieName      string
	cookieOptions   []SecureCookieOption
	maxAge          time.Duration
	extendThreshold time.Duration
}

// WithCookieName sets the name of the secure cookie where the session data is stored.
func WithCookieName(name string) SessionProcessorOption {
	return func(c *sessionProcessorConfig) {
		c.cookieName = name
	}
}

// WithCookieOptions adds SecureCookieOptions to secure cookie configuration.
func WithCookieOptions(opts ...SecureCookieOption) SessionProcessorOption {
	return func(c *sessionProcessorConfig) {
		c.cookieOptions = append(c.cookieOptions, opts...)
	}
}

// WithMaxAge sets the session max age.
func WithMaxAge(d time.Duration) SessionProcessorOption {
	return func(c *sessionProcessorConfig) {
		c.maxAge = d
	}
}

// WithExtendThreshold sets the session extension threshold.
func WithExtendThreshold(d time.Duration) SessionProcessorOption {
	return func(c *sessionProcessorConfig) {
		c.extendThreshold = d
	}
}

// NewCustomSessionProcessor returns a SessionProcessor with custom marshal/unmarshal.
func NewCustomSessionProcessor[Raw ByteSlice](keyID string, keys map[string][]byte, marshal func(any) ([]byte, error), unmarshal func([]byte, any) error, opts ...SessionProcessorOption) (*SessionProcessor[Raw], error) {
	cfg := sessionProcessorConfig{
		cookieName:      DefaultCookieName,
		maxAge:          DefaultSessionPeriod,
		extendThreshold: DefaultSessionRevalidationExtendThreshold,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	optsWithMarshaling := append([]SecureCookieOption{
		WithMarshalUnmarshal(marshal, unmarshal),
	}, cfg.cookieOptions...)

	cookie, err := NewSecureCookie(
		cfg.cookieName,
		keyID,
		keys,
		optsWithMarshaling...,
	)
	if err != nil {
		return nil, err
	}
	return &SessionProcessor[Raw]{
		cookie:          cookie,
		MaxAge:          cfg.maxAge,
		ExtendThreshold: cfg.extendThreshold,
		marshal:         marshal,
		unmarshal:       unmarshal,
	}, nil
}

// NewSessionProcessor returns a SessionProcessor with default marshal/unmarshal of CBOR.
func NewSessionProcessor(keyID string, keys map[string][]byte, opts ...SessionProcessorOption) (*SessionProcessor[cbor.RawMessage], error) {
	return NewCustomSessionProcessor[cbor.RawMessage](keyID, keys, cbor.Marshal, cbor.Unmarshal, opts...)
}

// Process implements endpoint.Processor.
func (p *SessionProcessor[Raw]) Process(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (endpoint.Renderer, error)) (endpoint.Renderer, error) {
	if p.cookie == nil {
		return nil, errors.New("SessionProcessor requires SecureCookie")
	}

	var sess Session

	// If a session is already present in context (installed by an outer SessionProcessor),
	// reuse it instead of trying to load from cookie again. This allows multiple SessionProcessors
	// to share the same session state.
	if existing, ok := SessionFromContext(r.Context()); ok {
		sess = existing
	} else {
		// Default to "no session" if no valid session cookie is found.
		sess0 := &session[Raw]{
			sessionData: nil,
			cookie:      p.cookie,
			marshal:     p.marshal,
			unmarshal:   p.unmarshal,
			dirty:       false,
		}

		// Try to read existing session
		c, err := r.Cookie(p.cookie.Name())
		if err == nil {
			// We have a cookie, try to decode it.
			var sessData sessionData[Raw]
			err = p.cookie.Decode(c, &sessData)
			if err == nil {
				// Make sure KV is initialized so downstream code can safely write to it.
				if sessData.KV == nil {
					sessData.KV = map[string]Raw{}
				}

				maxAge := p.MaxAge
				if maxAge <= 0 {
					maxAge = DefaultSessionPeriod
				}
				extendThreshold := p.ExtendThreshold
				if extendThreshold <= 0 {
					extendThreshold = DefaultSessionRevalidationExtendThreshold
				}

				ok, extended := sessData.validate(extendThreshold, maxAge)
				if !ok {
					// Invalid or expired. Clear it.
					// We can't clear it immediately in the response here because we might not have written headers yet,
					// but we also shouldn't write Set-Cookie header yet as we are a processor.
					// We rely on the deferred function to clear it if sess.sessionData[Raw] is nil.
					sess0.dirty = true
				} else {
					sess0.sessionData = &sessData
					sess0.dirty = extended
				}
			} else {
				// Failed to decode (tampered, invalid format, etc). Clear it.
				sess0.dirty = true
			}
		}

		*r = *r.WithContext(WithSession(r.Context(), sess0))
		sess = sess0
	}

	renderer, err := next(w, r)
	sess.MaybeSetCookie(w)
	return renderer, err
}

var _ endpoint.Processor = (*SessionProcessor[cbor.RawMessage])(nil)
var _ Session = (*session[cbor.RawMessage])(nil)
