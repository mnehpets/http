package endpoint

import (
	"io"
	"net/http"
)

// WithCloser returns a Renderer that calls c.Close() after Render() completes,
// whether or not Render returns an error. This is useful when a renderer is
// built from a resource (e.g. a file) that the renderer itself has no reference
// to, so the caller can attach the cleanup without wrapping the renderer type.
//
// The returned Renderer implements io.Closer; the endpoint handler will call
// Close() automatically via the existing io.Closer check.
//
// Multiple resources can be attached by chaining:
//
//	endpoint.WithCloser(endpoint.WithCloser(r, f1), f2)
func WithCloser(r Renderer, c io.Closer) Renderer {
	return &withCloser{Renderer: r, closer: c}
}

type withCloser struct {
	Renderer
	closer io.Closer
}

func (wc *withCloser) Close() error {
	err := wc.closer.Close()
	// Propagate to the inner renderer so that chained WithCloser calls
	// each have their closer invoked.
	if c, ok := wc.Renderer.(io.Closer); ok {
		if err2 := c.Close(); err == nil {
			err = err2
		}
	}
	return err
}

// StringRenderer is a renderer implementation that writes a string
// as the response body with an optional status code and content type.
//
// When ContentType is empty, StringRenderer defaults to
// "text/plain; charset=utf-8".
type StringRenderer struct {
	Status      int
	Body        string
	ContentType string
}

// setContentType ensures that a suitable Content-Type header is set for
// text-based responses. If the Content-Type header is already set, it is left
// unchanged. If contentType is empty, a default of "text/plain; charset=utf-8"
// is used.
func setContentType(w http.ResponseWriter, contentType string) {
	// Only set Content-Type if it has not already been set by an outer
	// renderer (e.g., a status or header renderer).
	if w.Header().Get("Content-Type") == "" {
		if contentType == "" {
			contentType = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)
	}
}

// Render implements Renderer for StringRenderer.
//
// StringRenderer is terminal: it MUST call WriteHeader and MUST NOT call next.
func (tr *StringRenderer) Render(w http.ResponseWriter, _ *http.Request) error {
	setContentType(w, tr.ContentType)
	status := tr.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if tr.Body == "" {
		return nil
	}
	_, err := w.Write([]byte(tr.Body))
	return err
}

// PlainRenderer is a convenience wrapper for plain-text responses.
//
// It embeds StringRenderer and forces a plain-text content type.
type PlainRenderer struct {
	StringRenderer
}

// Render implements Renderer for PlainRenderer.
func (pr *PlainRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	pr.StringRenderer.ContentType = "text/plain; charset=utf-8"
	return pr.StringRenderer.Render(w, r)
}

// HTMLRenderer is a convenience wrapper for HTML responses.
//
// It embeds StringRenderer and forces an HTML content type.
type HTMLRenderer struct {
	StringRenderer
}

// Render implements Renderer for HTMLRenderer.
func (hr *HTMLRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	hr.StringRenderer.ContentType = "text/html; charset=utf-8"
	return hr.StringRenderer.Render(w, r)
}

// NoContentRenderer writes a response with no body and a specific status code.
//
// If Status is 0, it defaults to http.StatusNoContent.
type NoContentRenderer struct {
	Status int
}

func (ncr *NoContentRenderer) Render(w http.ResponseWriter, _ *http.Request) error {
	status := ncr.Status
	if status == 0 {
		status = http.StatusNoContent
	}
	w.WriteHeader(status)
	return nil
}

// RedirectRenderer redirects the client to a new URL.
//
// If Status is 0, it defaults to http.StatusTemporaryRedirect (307).
type RedirectRenderer struct {
	URL    string
	Status int
}

// Render implements Renderer for RedirectRenderer.
func (rr *RedirectRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	status := rr.Status
	if status == 0 {
		status = http.StatusTemporaryRedirect
	}
	http.Redirect(w, r, rr.URL, status)
	return nil
}
