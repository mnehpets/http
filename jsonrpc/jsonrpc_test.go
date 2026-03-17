package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mnehpets/http/endpoint"
)

func serveRPC(e *JSONRPCEndpoint, processors ...endpoint.Processor) http.Handler {
	return endpoint.Handler(e.Endpoint, processors...)
}

func TestHandlerImplementsHTTPHandler(t *testing.T) {
	e := NewEndpoint()
	_ = e // JSONRPCEndpoint is not itself an http.Handler - use endpoint.Handler(e.Endpoint)
}

func TestPOSTOnlyEnforcement(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	tests := []struct {
		method   string
		wantCode int
	}{
		{http.MethodGet, http.StatusMethodNotAllowed},
		{http.MethodPut, http.StatusMethodNotAllowed},
		{http.MethodDelete, http.StatusMethodNotAllowed},
		{http.MethodPost, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"test.Echo","params":["hello"],"id":1}`)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}

func TestContentTypeValidation(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	tests := []struct {
		name        string
		contentType string
		wantCode    int
	}{
		{"MissingContentType", "", http.StatusOK},
		{"ApplicationJSON", "application/json", http.StatusOK},
		{"ApplicationJSONWithCharset", "application/json; charset=utf-8", http.StatusOK},
		{"TextPlain", "text/plain", http.StatusUnsupportedMediaType},
		{"ApplicationXML", "application/xml", http.StatusUnsupportedMediaType},
		{"TextHTML", "text/html", http.StatusUnsupportedMediaType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"test.Echo","params":{"s":"hello"},"id":1}`)))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}

func TestMethodRegistrationWithNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &mathMethods{})

	body := `{"jsonrpc":"2.0","method":"math.Add","params":{"a":2,"b":3},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["result"].(float64) != 5 {
		t.Errorf("got result %v, want 5", resp["result"])
	}
}

func TestMethodRegistrationWithoutNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("", &mathMethods{})

	body := `{"jsonrpc":"2.0","method":"Add","params":{"a":2,"b":3},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["result"].(float64) != 5 {
		t.Errorf("got result %v, want 5", resp["result"])
	}
}

func TestSingleRequestSuccess(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":{"s":"hello"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["result"] != "hello" {
		t.Errorf("got result %v, want 'hello'", resp["result"])
	}
}

func TestNotificationHandling(t *testing.T) {
	e := NewEndpoint()
	methods := &notifyMethods{called: false}
	e.Register("notify", methods)

	body := `{"jsonrpc":"2.0","method":"notify.Ping","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if !methods.called {
		t.Error("notification method was not called")
	}

	if rec.Code != http.StatusNoContent {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestBatchRequestHandling(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &mathMethods{})

	body := `[
		{"jsonrpc":"2.0","method":"math.Add","params":{"a":1,"b":2},"id":1},
		{"jsonrpc":"2.0","method":"math.Add","params":{"a":3,"b":4},"id":2}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp) != 2 {
		t.Fatalf("got %d responses, want 2", len(resp))
	}

	if resp[0]["result"].(float64) != 3 {
		t.Errorf("got result %v, want 3", resp[0]["result"])
	}
	if resp[1]["result"].(float64) != 7 {
		t.Errorf("got result %v, want 7", resp[1]["result"])
	}
}

func TestEmptyBatchRequest(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `[]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error response for empty batch")
	}
}

func TestParseError(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":[invalid json`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeParseError {
		t.Errorf("got error code %v, want %d", errObj["code"], CodeParseError)
	}
}

func TestMethodNotFound(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Nonexistent","params":[],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("got error code %v, want %d", errObj["code"], CodeMethodNotFound)
	}
}

func TestInvalidParams(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &mathMethods{})

	body := `{"jsonrpc":"2.0","method":"math.Add","params":{"a":"not","b":"numbers"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error response for invalid params")
	}
}

func TestCustomErrorCodes(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Fail","params":{},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != -1000 {
		t.Errorf("got error code %v, want -1000", errObj["code"])
	}
}

func TestGenericErrorHidesInternalDetails(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.FailGeneric","params":{},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeInternalError {
		t.Errorf("got error code %v, want %d", errObj["code"], CodeInternalError)
	}
	if errObj["message"] != "internal error" {
		t.Errorf("got message %v, want 'internal error'", errObj["message"])
	}
}

func TestProcessorChainExecution(t *testing.T) {
	executed := false
	processor := endpoint.ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error {
		executed = true
		return next(w, r)
	})

	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":{"s":"hello"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e, processor).ServeHTTP(rec, req)

	if !executed {
		t.Error("processor was not executed")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestProcessorErrorReturnsHTTPError(t *testing.T) {
	processor := endpoint.ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error {
		return endpoint.Error(http.StatusForbidden, "access denied", nil)
	})

	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":{"s":"hello"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e, processor).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestContextPropagationThroughProcessors(t *testing.T) {
	ctxKey := struct{}{}
	var gotValue string

	processor := endpoint.ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error {
		ctx := context.WithValue(r.Context(), ctxKey, "test-value")
		return next(w, r.WithContext(ctx))
	})

	methods := &contextMethods{ctxKey: ctxKey, getValue: func(v string) { gotValue = v }}
	e := NewEndpoint()
	e.Register("ctx", methods)

	body := `{"jsonrpc":"2.0","method":"ctx.GetValue","params":{},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e, processor).ServeHTTP(rec, req)

	if gotValue != "test-value" {
		t.Errorf("got value %q, want 'test-value'", gotValue)
	}
}

func TestAllStandardErrorCodes(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	tests := []struct {
		name     string
		body     string
		wantCode int
	}{
		{"ParseError", `{invalid`, CodeParseError},
		{"InvalidRequest", `{"jsonrpc":"1.0","method":"test.Echo","id":1}`, CodeInvalidRequest},
		{"MethodNotFound", `{"jsonrpc":"2.0","method":"unknown","id":1}`, CodeMethodNotFound},
		{"InvalidParams", `{"jsonrpc":"2.0","method":"test.Echo","params":{"s":123},"id":1}`, CodeInvalidParams},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			errObj := resp["error"].(map[string]interface{})
			if int(errObj["code"].(float64)) != tt.wantCode {
				t.Errorf("got error code %v, want %d", errObj["code"], tt.wantCode)
			}
		})
	}
}

type mathMethods struct{}

type AddParams struct {
	A int `json:"a"`
	B int `json:"b"`
}

func (m *mathMethods) Add(ctx context.Context, params AddParams) (int, error) {
	return params.A + params.B, nil
}

type testMethods struct{}

type EchoParams struct {
	S string `json:"s"`
}

func (m *testMethods) Echo(ctx context.Context, params EchoParams) (string, error) {
	return params.S, nil
}

func (m *testMethods) Fail(ctx context.Context, params struct{}) (interface{}, error) {
	return nil, &JSONRPCError{Code: -1000, Message: "custom error"}
}

func (m *testMethods) FailGeneric(ctx context.Context, params struct{}) (interface{}, error) {
	return nil, errors.New("sensitive internal error details")
}

type notifyMethods struct {
	called bool
}

func (m *notifyMethods) Ping(ctx context.Context, params struct{}) (interface{}, error) {
	m.called = true
	return nil, nil
}

type contextMethods struct {
	ctxKey   interface{}
	getValue func(string)
}

func (m *contextMethods) GetValue(ctx context.Context, params struct{}) (string, error) {
	v, _ := ctx.Value(m.ctxKey).(string)
	if m.getValue != nil {
		m.getValue(v)
	}
	return v, nil
}

type paramTypesMethods struct{}

type Person struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

type TakesMultipleParams struct {
	N     int            `json:"n"`
	P     Person         `json:"p"`
	Items []int          `json:"items"`
	Data  map[string]int `json:"data"`
}

func (m *paramTypesMethods) TakesMultiple(ctx context.Context, params TakesMultipleParams) (int, error) {
	total := params.N + params.P.Age
	for _, v := range params.Items {
		total += v
	}
	for _, v := range params.Data {
		total += v
	}
	return total, nil
}

func (m *paramTypesMethods) ReturnsPointer(ctx context.Context, params struct{}) (*Person, error) {
	return &Person{Name: "test", Age: 30}, nil
}

func (m *paramTypesMethods) ReturnsSlice(ctx context.Context, params struct{}) ([]int, error) {
	return []int{1, 2, 3}, nil
}

type panicMethods struct{}

func (m *panicMethods) PanicMethod(ctx context.Context, params struct{}) (string, error) {
	panic("something went wrong")
}

func TestParamsConversion(t *testing.T) {
	e := NewEndpoint()
	e.Register("params", &paramTypesMethods{})

	tests := []struct {
		name        string
		body        string
		checkResult func(t *testing.T, resp map[string]interface{})
		wantErr     bool
	}{
		{
			"PositionalParams",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":[10,{"name":"Alice","age":30},[1,2,3],{"x":5,"y":10}],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"].(float64) != 61 {
					t.Errorf("got result %v, want 61", resp["result"])
				}
			},
			false,
		},
		{
			"NamedParams",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":{"n":10,"p":{"name":"Alice","age":30},"items":[1,2,3],"data":{"x":5,"y":10}},"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"].(float64) != 61 {
					t.Errorf("got result %v, want 61", resp["result"])
				}
			},
			false,
		},
		{
			"NamedParamsDifferentOrder",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":{"data":{"x":5,"y":10},"p":{"name":"Alice","age":30},"n":10,"items":[1,2,3]},"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"].(float64) != 61 {
					t.Errorf("got result %v, want 61", resp["result"])
				}
			},
			false,
		},
		{
			"ReturnsPointer",
			`{"jsonrpc":"2.0","method":"params.ReturnsPointer","params":{},"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				result := resp["result"].(map[string]interface{})
				if result["name"] != "test" {
					t.Errorf("got name %v, want 'test'", result["name"])
				}
			},
			false,
		},
		{
			"ReturnsSlice",
			`{"jsonrpc":"2.0","method":"params.ReturnsSlice","params":{},"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				result := resp["result"].([]interface{})
				if len(result) != 3 {
					t.Errorf("got %d items, want 3", len(result))
				}
			},
			false,
		},
		{
			"WrongParamCount",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":[1],"id":1}`,
			nil,
			true,
		},
		{
			"InvalidJSONInParams",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":[1,{invalid}],"id":1}`,
			nil,
			true,
		},
		{
			"MissingParam",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":{"n":10,"p":{"name":"Alice","age":30},"items":[1,2,3]},"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"].(float64) != 46 {
					t.Errorf("got result %v, want 46 (missing param has zero value)", resp["result"])
				}
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if tt.wantErr {
				if resp["error"] == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if resp["error"] != nil {
					t.Errorf("unexpected error: %v", resp["error"])
				}
				if tt.checkResult != nil {
					tt.checkResult(t, resp)
				}
			}
		})
	}
}

func TestPanicRecovery(t *testing.T) {
	e := NewEndpoint()
	e.Register("panic", &panicMethods{})

	tests := []struct {
		name   string
		method string
	}{
		{"PanicMethod", "panic.PanicMethod"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","method":"` + tt.method + `","params":{},"id":1}`
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if resp["error"] == nil {
				t.Error("expected error for panic")
			}
			errObj := resp["error"].(map[string]interface{})
			if int(errObj["code"].(float64)) != CodeInternalError {
				t.Errorf("got error code %v, want %d", errObj["code"], CodeInternalError)
			}
		})
	}
}

func TestUnexportedMethodsNotRegistered(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &unexportedMethods{})

	body := `{"jsonrpc":"2.0","method":"test.hidden","params":[],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Error("expected error for unexported method")
	}
	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("got error code %v, want %d (method not found)", errObj["code"], CodeMethodNotFound)
	}
}

type unexportedMethods struct{}

func (m *unexportedMethods) hidden() (string, error) {
	return "should not be callable", nil
}

func (m *unexportedMethods) Visible(ctx context.Context) (string, error) {
	return "visible", nil
}

func TestBatchWithMixedResults(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})
	e.Register("math", &mathMethods{})

	body := `[
		{"jsonrpc":"2.0","method":"test.Echo","params":{"s":"hello"},"id":1},
		{"jsonrpc":"2.0","method":"test.Nonexistent","params":{},"id":2},
		{"jsonrpc":"2.0","method":"math.Add","params":{"a":1,"b":2},"id":3}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	var resp []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if len(resp) != 3 {
		t.Fatalf("got %d responses, want 3", len(resp))
	}

	if resp[0]["result"] != "hello" {
		t.Errorf("first result should be 'hello'")
	}
	if resp[1]["error"] == nil {
		t.Errorf("second result should be an error")
	}
	if resp[2]["result"].(float64) != 3 {
		t.Errorf("third result should be 3")
	}
}

func TestBatchWithNotifications(t *testing.T) {
	e := NewEndpoint()
	notify := &notifyMethods{called: false}
	e.Register("notify", notify)
	e.Register("math", &mathMethods{})

	body := `[
		{"jsonrpc":"2.0","method":"notify.Ping","params":{}},
		{"jsonrpc":"2.0","method":"math.Add","params":{"a":1,"b":2},"id":1}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if !notify.called {
		t.Error("notification should have been called")
	}

	var resp []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if len(resp) != 1 {
		t.Errorf("got %d responses, want 1 (notification should not produce response)", len(resp))
	}
}

type lowercaseMethods struct{}

type lowercaseParams struct {
	_ struct{} `jsonrpc:"add"`
	A int      `json:"a"`
	B int      `json:"b"`
}

func (m *lowercaseMethods) Add(ctx context.Context, params lowercaseParams) (int, error) {
	return params.A + params.B, nil
}

func TestLowercaseMethodNameOverride(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &lowercaseMethods{})

	body := `{"jsonrpc":"2.0","method":"math.add","params":{"a":2,"b":3},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["result"].(float64) != 5 {
		t.Errorf("got result %v, want 5", resp["result"])
	}
}

type collisionMethods1 struct{}

type collisionParams1 struct {
	_ struct{} `jsonrpc:"add"`
	A int      `json:"a"`
	B int      `json:"b"`
}

func (m *collisionMethods1) Add(ctx context.Context, params collisionParams1) (int, error) {
	return params.A + params.B, nil
}

type collisionMethods2 struct{}

type collisionParams2 struct {
	_ struct{} `jsonrpc:"add"`
	X int      `json:"x"`
	Y int      `json:"y"`
}

func (m *collisionMethods2) Add(ctx context.Context, params collisionParams2) (int, error) {
	return params.X + params.Y, nil
}

func TestMethodNameCollision(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for method name collision")
		}
	}()

	e := NewEndpoint()
	e.Register("math", &collisionMethods1{})
	e.Register("math", &collisionMethods2{})
}

type nonStructParamsMethods struct{}

func (m *nonStructParamsMethods) BadMethod(ctx context.Context, s string) (string, error) {
	return s, nil
}

func TestNonStructParamsNotRegistered(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &nonStructParamsMethods{})

	body := `{"jsonrpc":"2.0","method":"test.BadMethod","params":{"s":"hello"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Error("expected error for non-struct params method")
	}
	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("got error code %v, want %d (method not found)", errObj["code"], CodeMethodNotFound)
	}
}

type multiParamMethods struct{}

func (m *multiParamMethods) Add(ctx context.Context, a, b int) (int, error) {
	return a + b, nil
}

func TestMultipleParamsNotRegistered(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &multiParamMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Add","params":{"a":1,"b":2},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Error("expected error for multiple params method")
	}
	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("got error code %v, want %d (method not found)", errObj["code"], CodeMethodNotFound)
	}
}

func TestBatchSizeLimit(t *testing.T) {
	e := NewEndpoint()
	e.MaxBatchSize = 3
	e.Register("math", &mathMethods{})

	tests := []struct {
		name      string
		batchSize int
		wantErr   bool
		errCode   int
	}{
		{"WithinLimit", 3, false, 0},
		{"ExceedsLimit", 4, true, CodeInvalidRequest},
		{"SingleRequest", 1, false, 0},
		{"AtExactLimit", 3, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body strings.Builder
			body.WriteString("[")
			for i := 0; i < tt.batchSize; i++ {
				if i > 0 {
					body.WriteString(",")
				}
				body.WriteString(fmt.Sprintf(`{"jsonrpc":"2.0","method":"math.Add","params":{"a":%d,"b":%d},"id":%d}`, i, i+1, i+1))
			}
			body.WriteString("]")

			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body.String())))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
			}

			if tt.wantErr {
				var resp map[string]interface{}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if resp["error"] == nil {
					t.Error("expected error for batch size exceeding limit")
				} else {
					errObj := resp["error"].(map[string]interface{})
					if int(errObj["code"].(float64)) != tt.errCode {
						t.Errorf("got error code %v, want %d", errObj["code"], tt.errCode)
					}
				}
			} else {
				var resp []map[string]interface{}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if len(resp) != tt.batchSize {
					t.Errorf("got %d responses, want %d", len(resp), tt.batchSize)
				}
			}
		})
	}
}

func TestBatchSizeUnlimited(t *testing.T) {
	e := NewEndpoint()
	e.MaxBatchSize = 0 // Unlimited
	e.Register("math", &mathMethods{})

	// Create a batch with 150 requests (more than default limit)
	var body strings.Builder
	body.WriteString("[")
	for i := 0; i < 150; i++ {
		if i > 0 {
			body.WriteString(",")
		}
		body.WriteString(fmt.Sprintf(`{"jsonrpc":"2.0","method":"math.Add","params":{"a":%d,"b":%d},"id":%d}`, i, i+1, i+1))
	}
	body.WriteString("]")

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body.String())))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp) != 150 {
		t.Errorf("got %d responses, want 150", len(resp))
	}
}
