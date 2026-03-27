// Package endpoint provides a type-safe abstraction for building HTTP handlers.
//
// The core pattern separates the request decoding, business logic, and response
// rendering into distinct phases:
//
//  1. Unmarshal: The EndpointHandler decodes the request (path, query, body, etc.)
//     into a typed parameters struct using struct tags.
//  2. Endpoint: The EndpointFunc receives the decoded parameters and the request,
//     executes business logic, and returns a Renderer. It does not write to the
//     response directly.
//  3. Render: The returned Renderer writes the status code, headers, and body
//     to the http.ResponseWriter.
//
// Processors can be chained as middleware to intercept requests before they reach
// the EndpointFunc.
//
// Supported Renderers:
//   - JSONRenderer: Serializes a value as JSON.
//   - StringRenderer: Writes a plain string.
//   - TextTemplateRenderer: Renders a text/template.
//   - HTMLTemplateRenderer: Renders an html/template.
//   - StaticFileRenderer: Serves a single static file.
//   - DirectoryHTMLRenderer: Renders a directory listing as HTML.
//   - NoContentRenderer: Writes a status code with no body.
//   - ProxyRenderer: Proxies the request to an upstream endpoint.
package endpoint

import (
	"errors"
	"io"
	"net/http"
)

// EndpointError is a client-visible error that maps directly to an HTTP status code.
//
// The handler wrapper uses this to translate returned Go errors into HTTP
// responses.
type EndpointError struct {
	Status int
	// Message is a short, human-readable description suitable for an HTTP error body.
	Message string
	Cause   error
}

func (e *EndpointError) Error() string {
	if e == nil {
		return "endpoint: error: <nil>"
	}
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
		if msg == "" {
			msg = "unknown error"
		}
	}
	if e.Cause != nil {
		return msg + ": " + e.Cause.Error()
	}
	return msg
}

func (e *EndpointError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Error creates a new EndpointError.
func Error(status int, message string, err error) error {
	return newEndpointError(status, message, err)
}

func newEndpointError(status int, message string, err error) error {
	// Avoid double-wrapping.
	var ee *EndpointError
	if errors.As(err, &ee) {
		return err
	}
	return &EndpointError{Status: status, Message: message, Cause: err}
}

// Renderers are values that write a response into an http.ResponseWriter.
//
// Protocol:
//   - Renderers MUST call w.WriteHeader() to write the HTTP response status
//     and headers. It must also call w.Write() to write response
//   - Renderers may optionally write the Content-Type header before
//     calling w.WriteHeader().
//
// Error handling:
//   - If Render returns a non-nil error, it indicates a failure to write
//     the response. The caller is responsible for handling that error
//     (typically by writing an HTTP 500 response).
type Renderer interface {
	Render(w http.ResponseWriter, r *http.Request) error
}

// RendererFunc adapts a function to a Renderer.
type RendererFunc func(w http.ResponseWriter, r *http.Request) error

func (f RendererFunc) Render(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

// Processor is middleware-style logic that runs before the Renderer.
//
// Protocol:
//   - Processors MUST NOT call w.WriteHeader(...).
//   - Processors MUST NOT write to the response body.
//   - A processor either calls next and returns next's (Renderer, error), or
//     short-circuits by returning its own (Renderer, error) without calling next.
//
// Error handling:
//   - If any processor returns a non-nil error, the chain stops immediately
//     and that error is returned to the caller.
type Processor interface {
	Process(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error)
}

// ProcessorFunc adapts a function to a Processor.
type ProcessorFunc func(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error)

func (f ProcessorFunc) Process(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error) {
	return f(w, r, next)
}

// EndpointFunc is the wrapped handler function type.
//
// It receives the response writer, the incoming request, and a typed params
// value (typically a struct populated from path/query/body/form data) and
// returns a Renderer responsible for writing the response, or an error.
//
// EndpointFunc should implement business logic, without directly writing the
// response body. It may modify the request context, and use the request, and the
// params to determine the appropriate response to return, but the actual
// body of the response, Status, and Content-Type header is delegated to
// the returned Renderer.
//
// The returned Renderer should be concerned only with the content of the reponse;
// it should not need to access the request or params. Typically, the Renderer should perform
// formatting/serialization of data passed to it by the EndpointFunc.
//
// Parameter decoding is performed by the Handler wrapper.
type EndpointFunc[P any] func(w http.ResponseWriter, r *http.Request, params P) (Renderer, error)

// EndpointHandler is the standard http.Handler wrapper for an EndpointFunc.
//
// It runs zero or more processors. It then calls Endpoint with decoded
// params and invokes the returned Renderer to write the response.
//
// The params type P may be any type, but is typically a struct type used to
// hold decoded request parameters.
type EndpointHandler[P any] struct {
	Endpoint   EndpointFunc[P]
	Processors []Processor
}

// Handler constructs an EndpointHandler.
//
// This helper exists to enable type inference for the params type P.
func Handler[P any](fn EndpointFunc[P], processors ...Processor) *EndpointHandler[P] {
	return &EndpointHandler[P]{
		Endpoint:   fn,
		Processors: processors,
	}
}

// HandleFunc adapts an EndpointFunc into an http.HandlerFunc.
//
// This helper exists to enable type inference for the params type P.
func HandleFunc[P any](fn EndpointFunc[P], processors ...Processor) http.HandlerFunc {
	return Handler(fn, processors...).ServeHTTP
}

// ServeHTTP implements http.Handler.
func (h *EndpointHandler[P]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Endpoint == nil {
		http.Error(w, "endpoint: nil EndpointFunc", http.StatusInternalServerError)
		return
	}

	// run calls each processor in order, then the EndpointFunc.
	// Each level either passes through to the next or short-circuits with its own (Renderer, error).
	var run func(i int, w2 http.ResponseWriter, r2 *http.Request) (Renderer, error)
	run = func(i int, w2 http.ResponseWriter, r2 *http.Request) (Renderer, error) {
		if i < len(h.Processors) {
			if h.Processors[i] == nil {
				return nil, errors.New("endpoint: nil processor")
			}
			return h.Processors[i].Process(w2, r2, func(w3 http.ResponseWriter, r3 *http.Request) (Renderer, error) {
				return run(i+1, w3, r3)
			})
		}

		// All processors have been called; now call EndpointFunc.
		// P must be a struct type, or a pointer to a struct type.
		// This is enforced by endpoint.Unmarshal (runtime) rather than by the type system.
		var params P
		if err := Unmarshal(r2, &params); err != nil {
			return nil, err
		}
		return h.Endpoint(w2, r2, params)
	}

	renderer, err := run(0, w, r)

	if err != nil {
		status := http.StatusInternalServerError
		message := ""

		var ee *EndpointError
		if errors.As(err, &ee) && ee != nil {
			if ee.Status >= 100 {
				status = ee.Status
			}
			if ee.Message == "" {
				message = http.StatusText(status)
			} else {
				message = ee.Message
			}
		} else {
			message = err.Error()
		}
		http.Error(w, message, status)
		return
	}

	if renderer == nil {
		http.Error(w, "endpoint: nil renderer", http.StatusInternalServerError)
		return
	}

	if c, ok := renderer.(io.Closer); ok {
		defer c.Close()
	}
	if err := renderer.Render(w, r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
