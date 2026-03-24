package endpoint

import (
	"context"
	"errors"
	"fmt"
	htmltmpl "html/template"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	texttmpl "text/template"
)

type headerPreprocessor struct {
	Key   string
	Value string
}

func (hp headerPreprocessor) Process(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
	if hp.Key != "" {
		w.Header().Set(hp.Key, hp.Value)
	}
	return next(w, r)
}

func TestHandler_Constructors(t *testing.T) {
	// Test Handler() helper
	h1 := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return &StringRenderer{Body: "h1"}, nil
	})

	// Test HandleFunc() helper
	hf := HandleFunc(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return &StringRenderer{Body: "hf"}, nil
	})

	// Test direct EndpointHandler struct usage with a non-empty struct
	type MyParams struct {
		Val string
	}
	h2 := EndpointHandler[MyParams]{
		Endpoint: func(_ http.ResponseWriter, _ *http.Request, p MyParams) (Renderer, error) {
			return &StringRenderer{Body: "h2"}, nil
		},
	}

	// Verify they are usable
	req := httptest.NewRequest("GET", "/", nil)

	rec1 := httptest.NewRecorder()
	h1.ServeHTTP(rec1, req)
	if rec1.Body.String() != "h1" {
		t.Errorf("Handler failed")
	}

	rec2 := httptest.NewRecorder()
	hf(rec2, req)
	if rec2.Body.String() != "hf" {
		t.Errorf("HandleFunc failed")
	}

	rec3 := httptest.NewRecorder()
	h2.ServeHTTP(rec3, req)
	if rec3.Body.String() != "h2" {
		t.Errorf("EndpointHandler failed")
	}
}

func TestHandler_NoPreprocessors_RendererRuns(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	})

	h.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", got)
	}
}

func TestHandler_PreprocessorsThenRenderer(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	}, headerPreprocessor{Key: "X-Test", Value: "1"})

	h.ServeHTTP(rec, req)

	resp := rec.Result()
	if got := resp.Header.Get("X-Test"); got != "1" {
		t.Fatalf("expected X-Test header %q, got %q", "1", got)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", got)
	}
}

func TestHandler_Helper_JoinsProcessorAndEndpointFunc_ParamBindingAndCalls(t *testing.T) {
	h := Handler(func(_ http.ResponseWriter, _ *http.Request, params struct {
		Name string `query:"name"`
	}) (Renderer, error) {
		// Assert binding and construct body from params.
		return &StringRenderer{Body: "hello " + strings.ToUpper(params.Name)}, nil
	}, ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
		w.Header().Set("X-Processor-Called", "1")
		return next(w, r)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/?name=world", nil)
	h.ServeHTTP(rec, req)

	if got := rec.Result().Header.Get("X-Processor-Called"); got != "1" {
		t.Fatalf("expected X-Processor-Called header %q, got %q", "1", got)
	}
	if got := rec.Body.String(); got != "hello WORLD" {
		t.Fatalf("expected body %q, got %q", "hello WORLD", got)
	}
}

func TestHandler_PreprocessorsThenJSONRenderer(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/json", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		return &JSONRenderer{Value: struct{ Cities []string }{Cities: []string{"Sydney", "Melbourne"}}}, nil
	}, headerPreprocessor{Key: "X-From-Pre", Value: "1"})

	h.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("X-From-Pre"); got != "1" {
		t.Fatalf("expected X-From-Pre header %q, got %q", "1", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type %q, got %q", "application/json", got)
	}
	if got := rec.Body.String(); got != "{\"Cities\":[\"Sydney\",\"Melbourne\"]}\n" {
		t.Fatalf("expected body %q, got %q", "{\"Cities\":[\"Sydney\",\"Melbourne\"]}\\n", got)
	}
}

func TestHandler_TextTemplateRenderer_ParamsAsValues(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/t", HandleFunc(func(_ http.ResponseWriter, _ *http.Request, params struct {
		Name string `query:"name"`
	}) (Renderer, error) {
		tmpl := texttmpl.Must(texttmpl.New("base").Parse("hello {{.Name}}"))
		return &TextTemplateRenderer{Template: tmpl, Values: params}, nil
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t?name=world", nil)
	mux.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/plain; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "hello world" {
		t.Fatalf("expected body %q, got %q", "hello world", got)
	}
}

func TestHandler_HTMLTemplateRenderer_ParamsAsValues(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/t", HandleFunc(func(_ http.ResponseWriter, _ *http.Request, params struct {
		Name string `query:"name"`
	}) (Renderer, error) {
		tmpl := htmltmpl.Must(htmltmpl.New("base").Parse("<p>{{.Name}}</p>"))
		return &HTMLTemplateRenderer{Template: tmpl, Values: params}, nil
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t?name=ok", nil)
	mux.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/html; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "<p>ok</p>" {
		t.Fatalf("expected body %q, got %q", "<p>ok</p>", got)
	}
}

func TestHandler_MultiplePreprocessors(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		// Ensure preprocessors ran before the endpoint func.
		if got := r.Header.Get("X-From-Pre"); got != "yes" {
			return nil, newEndpointError(http.StatusInternalServerError, "missing preprocessor mutation", nil)
		}
		return &StringRenderer{Body: "ok"}, nil
	},
		headerPreprocessor{Key: "X-One", Value: "1"},
		ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
			r.Header.Set("X-From-Pre", "yes")
			return next(w, r)
		}),
		headerPreprocessor{Key: "X-Two", Value: "2"},
	)

	h.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("X-One"); got != "1" {
		t.Fatalf("expected X-One header %q, got %q", "1", got)
	}
	if got := resp.Header.Get("X-Two"); got != "2" {
		t.Fatalf("expected X-Two header %q, got %q", "2", got)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", got)
	}
}

func TestHandler_NilEndpoint_Is500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := EndpointHandler[struct{}]{Endpoint: nil}
	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_NilRenderer_Is500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		return nil, nil
	})

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestCookies_ProcessorToRenderer_SetCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		// EndpointFunc adds its own cookie via Defer.
		Defer(r.Context(), func(w http.ResponseWriter) {
			http.SetCookie(w, &http.Cookie{Name: "b", Value: "2", Path: "/"})
		})
		return &StringRenderer{Body: "ok"}, nil
	}, ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", Path: "/"})
		return next(w, r)
	}))

	h.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("expected body %q, got %q", "ok", got)
	}

	// Set-Cookie is a multi-value header.
	cookies := resp.Header.Values("Set-Cookie")
	sort.Strings(cookies)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie headers, got %d: %v", len(cookies), cookies)
	}
	if !strings.HasPrefix(cookies[0], "a=1") {
		t.Fatalf("expected cookie a=1, got %q", cookies[0])
	}
	if !strings.HasPrefix(cookies[1], "b=2") {
		t.Fatalf("expected cookie b=2, got %q", cookies[1])
	}
}

func TestCookies_ProcessorToProcessor_SetCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	},
		ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
			http.SetCookie(w, &http.Cookie{Name: "a", Value: "1", Path: "/"})
			return next(w, r)
		}),
		ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
			http.SetCookie(w, &http.Cookie{Name: "b", Value: "2", Path: "/"})
			return next(w, r)
		}),
	)

	h.ServeHTTP(rec, req)

	resp := rec.Result()
	cookies := resp.Header.Values("Set-Cookie")
	sort.Strings(cookies)
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie headers, got %d: %v", len(cookies), cookies)
	}
	if !strings.HasPrefix(cookies[0], "a=1") {
		t.Fatalf("expected cookie a=1, got %q", cookies[0])
	}
	if !strings.HasPrefix(cookies[1], "b=2") {
		t.Fatalf("expected cookie b=2, got %q", cookies[1])
	}
}

func TestCookies_LastWriterWins_ByHeaderOrder(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		Defer(r.Context(), func(w http.ResponseWriter) {
			// Defer sets same cookie name as processor.
			http.SetCookie(w, &http.Cookie{Name: "a", Value: "defer", Path: "/"})
		})
		return &StringRenderer{Body: "ok"}, nil
	}, ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "processor", Path: "/"})
		return next(w, r)
	}))

	h.ServeHTTP(rec, req)

	resp := rec.Result()
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) < 2 {
		t.Fatalf("expected at least 2 Set-Cookie headers, got %d: %v", len(cookies), cookies)
	}
	// In approach (1), we cannot de-duplicate: both cookies exist. The browser
	// effectively applies the last matching Set-Cookie.
	last := cookies[len(cookies)-1]
	if !strings.HasPrefix(last, "a=defer") {
		t.Fatalf("expected last Set-Cookie to be defer's, got %q (all: %v)", last, cookies)
	}
}

func TestCookies_DeferCanDeleteCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		Defer(r.Context(), func(w http.ResponseWriter) {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
		})
		return &NoContentRenderer{Status: http.StatusNoContent}, nil
	}, ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		return next(w, r)
	}))

	h.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, resp.StatusCode)
	}

	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) < 2 {
		t.Fatalf("expected at least 2 Set-Cookie headers, got %d: %v", len(cookies), cookies)
	}
	last := cookies[len(cookies)-1]
	if !strings.HasPrefix(last, "session=") {
		t.Fatalf("expected last Set-Cookie to reference session cookie, got %q", last)
	}
	// Deletion semantics are encoded in attributes. We assert that Max-Age=0 or
	// Max-Age=-1 depending on encoding; net/http uses Max-Age=0 for MaxAge<0.
	if !strings.Contains(strings.ToLower(last), "max-age=0") && !strings.Contains(strings.ToLower(last), "max-age=-1") {
		t.Fatalf("expected deletion cookie to include Max-Age attr, got %q", last)
	}
}

func TestHandler_NilPreprocessor_Is500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, r *http.Request, params struct{}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	}, nil)

	h.ServeHTTP(rec, req)

	// nil preprocessors are programmer error and should fail the request.
	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_DecodeError_IsBadRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/t/{id}", Handler(func(_ http.ResponseWriter, _ *http.Request, params struct {
		ID string `path:"id"`
		N  int    `query:"n"`
	}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	}))

	// n is not parseable as int => syntactically valid request but semantically invalid input.
	// Decoder treats this as a syntactic decoding failure (400).
	req := httptest.NewRequest(http.MethodGet, "/t/abc?n=not-an-int", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Result().StatusCode)
	}
}

func TestHandler_JSONDecodeErrors_AreBadRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/t", Handler(func(_ http.ResponseWriter, _ *http.Request, params struct {
		Body map[string]any `body:",json"`
	}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	}))

	t.Run("syntactically invalid json => 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader(`{"x":`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Result().StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Result().StatusCode)
		}
	})
}

func TestHandler_EndpointError_FromProcessor_IsRendered(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	}, ProcessorFunc(func(_ http.ResponseWriter, _ *http.Request, _ func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error) {
		return nil, newEndpointError(http.StatusForbidden, "nope", errors.New("forbidden"))
	}))

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Result().StatusCode)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "nope" {
		t.Fatalf("expected body %q, got %q", "nope", got)
	}
}

func TestHandler_EndpointError_FromEndpointFunc_IsRendered(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return nil, newEndpointError(http.StatusUnauthorized, "unauthorized", errors.New("unauthorized"))
	})

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Result().StatusCode)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "unauthorized" {
		t.Fatalf("expected body %q, got %q", "unauthorized", got)
	}
}

func TestHandler_EndpointError_EmptyMessage_FallsBackToStatusText(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return nil, newEndpointError(http.StatusNotFound, "", errors.New("missing"))
	})

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, rec.Result().StatusCode)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != http.StatusText(http.StatusNotFound) {
		t.Fatalf("expected body %q, got %q", http.StatusText(http.StatusNotFound), got)
	}
}

func TestEndpointError_Unwrap_PreservesCause(t *testing.T) {
	cause := errors.New("root")
	err := newEndpointError(http.StatusTeapot, "teapot", cause)
	if errors.Unwrap(err) != cause {
		t.Fatalf("expected errors.Unwrap(err) == %v, got %v", cause, errors.Unwrap(err))
	}
}

func TestHandler_NonEndpointError_FromProcessor_Is500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	}, ProcessorFunc(func(_ http.ResponseWriter, _ *http.Request, _ func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error) {
		return nil, errors.New("boom")
	}))

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_NonEndpointError_FromEndpointFunc_Is500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return nil, errors.New("boom")
	})

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_NonEndpointError_FromRenderer_Is500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return RendererFunc(func(_ http.ResponseWriter, _ *http.Request) error {
			return errors.New("boom")
		}), nil
	})

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_EndpointError_InvalidStatus_Is500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return nil, newEndpointError(0, "bad status", errors.New("bad"))
	})

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_EndpointError_ContentType_IsTextPlain(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return nil, newEndpointError(http.StatusForbidden, "nope", errors.New("forbidden"))
	})

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Result().StatusCode)
	}
	if got := rec.Result().Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/plain; charset=utf-8", got)
	}
}

func TestHandler_EndpointError_FirstErrorWins_StopsPipeline(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	called := 0
	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		called++
		return &StringRenderer{Body: "ok"}, nil
	},
		ProcessorFunc(func(_ http.ResponseWriter, _ *http.Request, _ func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error) {
			called++
			return nil, newEndpointError(http.StatusForbidden, "stop", errors.New("stop"))
		}),
		ProcessorFunc(func(_ http.ResponseWriter, _ *http.Request, next func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error) {
			called++
			return next(nil, nil)
		}),
	)

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rec.Result().StatusCode)
	}
	// Only the first processor should have been called; the endpoint func and
	// subsequent processors should not run.
	if called != 1 {
		t.Fatalf("expected called == 1, got %d", called)
	}
}

func TestHandler_ProcessorShortCircuit_RendererUsed_ChainNotCalled(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	subsequentCalled := false
	endpointCalled := false

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		endpointCalled = true
		return &StringRenderer{Body: "endpoint"}, nil
	},
		ProcessorFunc(func(_ http.ResponseWriter, _ *http.Request, _ func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error) {
			// Short-circuit: return a renderer without calling next.
			return &StringRenderer{Body: "short-circuit"}, nil
		}),
		ProcessorFunc(func(_ http.ResponseWriter, _ *http.Request, next func(w http.ResponseWriter, r *http.Request) (Renderer, error)) (Renderer, error) {
			subsequentCalled = true
			return next(nil, nil)
		}),
	)

	h.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if got := rec.Body.String(); got != "short-circuit" {
		t.Fatalf("expected body %q from short-circuiting processor, got %q", "short-circuit", got)
	}
	if subsequentCalled {
		t.Error("subsequent processor should not have been called after short-circuit")
	}
	if endpointCalled {
		t.Error("endpoint func should not have been called after short-circuit")
	}
}

func TestHandler_DecodeParams_FromPathQueryAndForm(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/thing/{id}/{rest...}", Handler(func(_ http.ResponseWriter, _ *http.Request, params struct {
		ID    string `path:"id"`
		Rest  string `path:"rest"`
		Q     string `query:"q"`
		N     int    `query:"n"`
		B     []byte `query:"b,base64"`
		Auto  string
		F     string  `form:"f"`
		Limit uint    `http:"-"`
		Score float64 `form:"score"`
	}) (Renderer, error) {
		// Exercise multiple types and sources.
		body := fmt.Sprintf("id=%s rest=%s q=%s n=%d b=%s auto=%s f=%s limit=%d score=%.2f", params.ID, params.Rest, params.Q, params.N, string(params.B), params.Auto, params.F, params.Limit, params.Score)
		return &StringRenderer{Body: body}, nil
	}))

	body := strings.NewReader("f=hello&limit=3&score=1.25")
	// b is base64("hi")
	req := httptest.NewRequest(http.MethodPost, "/thing/42/extra/path?q=abc&n=7&b=aGk=&auto=z", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if got := rec.Body.String(); got != "id=42 rest=extra/path q=abc n=7 b=hi auto=z f=hello limit=0 score=1.25" {
		t.Fatalf("expected body %q, got %q", "id=42 rest=extra/path q=abc n=7 b=hi auto=z f=hello limit=0 score=1.25", got)
	}
}

func TestHandler_DeferAndCommit_ExecutionOrder(t *testing.T) {
	var execOrder []string

	p1 := ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
		Defer(r.Context(), func(w http.ResponseWriter) {
			execOrder = append(execOrder, "p1-hook")
			w.Header().Set("X-P1", "val")
		})
		return next(w, r)
	})

	p2 := ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
		Defer(r.Context(), func(w http.ResponseWriter) {
			execOrder = append(execOrder, "p2-hook")
		})
		return next(w, r)
	})

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return RendererFunc(func(w http.ResponseWriter, r *http.Request) error {
			execOrder = append(execOrder, "renderer")
			w.WriteHeader(http.StatusOK)
			return nil
		}), nil
	}, p1, p2)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	// Expected order:
	// 1. Commit runs hooks LIFO (p2 registered last -> p2-hook, then p1-hook)
	// 2. Renderer runs
	// Wait. Commit runs BEFORE Render.
	// So hooks run first.

	if len(execOrder) != 3 {
		t.Fatalf("execOrder length: got %d want 3 (%v)", len(execOrder), execOrder)
	}
	if execOrder[0] != "p2-hook" {
		t.Errorf("expected p2-hook first, got %s", execOrder[0])
	}
	if execOrder[1] != "p1-hook" {
		t.Errorf("expected p1-hook second, got %s", execOrder[1])
	}
	if execOrder[2] != "renderer" {
		t.Errorf("expected renderer last, got %s", execOrder[2])
	}

	if rec.Header().Get("X-P1") != "val" {
		t.Errorf("X-P1 header not set by hook")
	}
}

func TestHandler_DeferAndCommit_RunOnError(t *testing.T) {
	hookRan := false
	p1 := ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) (Renderer, error)) (Renderer, error) {
		Defer(r.Context(), func(w http.ResponseWriter) {
			hookRan = true
		})
		return nil, errors.New("processor error")
	})

	h := Handler(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
		return &StringRenderer{Body: "ok"}, nil
	}, p1)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rec.Code)
	}
	if !hookRan {
		t.Errorf("expected deferred hook to run on error")
	}
}

func TestHandler_Defer_NoOpWithoutContext(t *testing.T) {
	// Calling Defer with background context should not panic and do nothing.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Defer panicked: %v", r)
		}
	}()
	// No hooks initialized in Background context.
	Defer(context.Background(), func(w http.ResponseWriter) {})
}

type closingRenderer struct {
	Renderer
	closeCalled bool
}

func (cr *closingRenderer) Close() error {
	cr.closeCalled = true
	return nil
}

func TestRendererCleanup(t *testing.T) {
	t.Run("cleanup on success", func(t *testing.T) {
		cr := &closingRenderer{
			Renderer: &StringRenderer{Body: "ok"},
		}
		h := HandleFunc(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
			return cr, nil
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		h(rec, req)

		if !cr.closeCalled {
			t.Error("expected Close() to be called")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("cleanup on render error", func(t *testing.T) {
		cr := &closingRenderer{
			Renderer: RendererFunc(func(w http.ResponseWriter, r *http.Request) error {
				return errors.New("render failed")
			}),
		}
		h := HandleFunc(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
			return cr, nil
		})

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		h(rec, req)

		if !cr.closeCalled {
			t.Error("expected Close() to be called even on render error")
		}
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", rec.Code)
		}
	})
}

func TestWithCloser(t *testing.T) {
	t.Run("closes after successful render", func(t *testing.T) {
		var closed bool
		closer := closerFunc(func() error { closed = true; return nil })
		r := WithCloser(&StringRenderer{Body: "ok"}, closer)
		h := HandleFunc(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
			return r, nil
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h(rec, req)
		if !closed {
			t.Error("expected Close() to be called")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("closes after render error", func(t *testing.T) {
		var closed bool
		closer := closerFunc(func() error { closed = true; return nil })
		r := WithCloser(RendererFunc(func(w http.ResponseWriter, _ *http.Request) error {
			return errors.New("render failed")
		}), closer)
		h := HandleFunc(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
			return r, nil
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h(rec, req)
		if !closed {
			t.Error("expected Close() to be called even on render error")
		}
	})

	t.Run("chained closers", func(t *testing.T) {
		var closed1, closed2 bool
		c1 := closerFunc(func() error { closed1 = true; return nil })
		c2 := closerFunc(func() error { closed2 = true; return nil })
		r := WithCloser(WithCloser(&StringRenderer{Body: "ok"}, c1), c2)
		h := HandleFunc(func(_ http.ResponseWriter, _ *http.Request, _ struct{}) (Renderer, error) {
			return r, nil
		})
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		h(rec, req)
		if !closed1 || !closed2 {
			t.Errorf("expected both closers to be called, got closed1=%v closed2=%v", closed1, closed2)
		}
	})
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
