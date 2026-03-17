package jsonrpc

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"github.com/mnehpets/http/endpoint"
)

const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	return e.Message
}

func NewError(code int, message string) *JSONRPCError {
	return &JSONRPCError{Code: code, Message: message}
}

// rpcMethod holds reflection data for a registered RPC method.
type rpcMethod struct {
	receiver    reflect.Value
	method      reflect.Method
	paramType   reflect.Type
	paramFields []int // Field indices for positional params unmarshaling
	methodName  string
}

func (m *rpcMethod) call(ctx context.Context, params json.RawMessage) (result interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("jsonrpc panic: %v", r)
			err = NewError(CodeInternalError, "internal error")
		}
	}()

	args := make([]reflect.Value, 0, 2)
	args = append(args, m.receiver)
	args = append(args, reflect.ValueOf(ctx))

	if m.paramType != nil {
		if params == nil {
			params = json.RawMessage("null")
		}

		param := reflect.New(m.paramType)

		var paramList []json.RawMessage
		if err := json.Unmarshal(params, &paramList); err == nil {
			// Positional params: array elements map to struct fields by declaration order.
			if len(paramList) != len(m.paramFields) {
				return nil, NewError(CodeInvalidParams, "invalid number of params")
			}
			// Directly unmarshal each element into the corresponding struct field.
			for i, rawElem := range paramList {
				fieldIdx := m.paramFields[i]
				field := param.Elem().Field(fieldIdx)
				if err := json.Unmarshal(rawElem, field.Addr().Interface()); err != nil {
					return nil, NewError(CodeInvalidParams, "invalid params")
				}
			}
		} else {
			// Named params: JSON object keys map to struct fields by json tags.
			if err := json.Unmarshal(params, param.Interface()); err != nil {
				return nil, NewError(CodeInvalidParams, "invalid params")
			}
		}
		args = append(args, param.Elem())
	}

	results := m.method.Func.Call(args)

	retResult := results[0].Interface()
	var retErr error
	if !results[1].IsNil() {
		retErr = results[1].Interface().(error)
	}

	return retResult, retErr
}

// JSONRPCEndpoint is a registry for JSON-RPC methods.
// Use endpoint.Handler(e.Endpoint, processors...) to create an http.Handler.
type JSONRPCEndpoint struct {
	mu           sync.RWMutex
	methods      map[string]*rpcMethod
	MaxBatchSize int // Maximum number of requests allowed in a batch (0 = unlimited)
}

// NewEndpoint creates a new JSON-RPC method registry.
func NewEndpoint() *JSONRPCEndpoint {
	return &JSONRPCEndpoint{
		methods:      make(map[string]*rpcMethod),
		MaxBatchSize: 100,
	}
}

// Register adds methods from a receiver struct to the endpoint.
// The namespace prefixes all method names (e.g., "math" + "Add" -> "math.Add").
// Use empty string for no namespace (method names used directly).
// Only exported methods with valid signatures are registered.
func (e *JSONRPCEndpoint) Register(namespace string, receiver interface{}) {
	val := reflect.ValueOf(receiver)
	typ := val.Type()

	for i := 0; i < val.NumMethod(); i++ {
		method := typ.Method(i)
		if !method.IsExported() {
			continue
		}

		handler, methodName := parseMethod(val, method)
		if handler == nil {
			continue
		}

		name := methodName
		if namespace != "" {
			name = namespace + "." + methodName
		}

		e.mu.Lock()
		if _, exists := e.methods[name]; exists {
			e.mu.Unlock()
			panic("jsonrpc: method name collision: " + name)
		}
		e.methods[name] = handler
		e.mu.Unlock()
	}
}

// rpcParams captures the raw JSON-RPC request body.
// We defer parsing until inside the endpoint handler,
// as json-rpc requires different handling of json parsing
// errors than the default oneserve json body parser.
type rpcParams struct {
	Body []byte `body:""`
}

// Endpoint is the endpoint function that processes JSON-RPC requests.
// Pass to endpoint.Handler() to create an http.Handler.
func (e *JSONRPCEndpoint) Endpoint(w http.ResponseWriter, r *http.Request, params rpcParams) (endpoint.Renderer, error) {
	if r.Method != http.MethodPost {
		return nil, endpoint.Error(http.StatusMethodNotAllowed, "JSON-RPC requires POST method", nil)
	}

	// Per JSON-RPC over HTTP spec, Content-Type must be application/json
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		return nil, endpoint.Error(http.StatusUnsupportedMediaType, "Content-Type must be application/json", nil)
	}

	return e.handleBody(r.Context(), params.Body)
}

// handleBody processes the JSON-RPC request body and returns a renderer.
func (e *JSONRPCEndpoint) handleBody(ctx context.Context, body []byte) (endpoint.Renderer, error) {
	var reqs []json.RawMessage
	var single bool

	if len(body) > 0 && body[0] == '[' {
		if err := json.Unmarshal(body, &reqs); err != nil {
			return &jsonrpcRenderer{err: NewError(CodeParseError, "parse error")}, nil
		}
	} else {
		reqs = []json.RawMessage{body}
		single = true
	}

	if len(reqs) == 0 {
		return &jsonrpcRenderer{err: NewError(CodeInvalidRequest, "invalid request")}, nil
	}

	if e.MaxBatchSize > 0 && len(reqs) > e.MaxBatchSize {
		return &jsonrpcRenderer{err: NewError(CodeInvalidRequest, "batch size exceeds maximum")}, nil
	}

	responses := make([]response, 0, len(reqs))
	for _, rawReq := range reqs {
		var req request
		if err := json.Unmarshal(rawReq, &req); err != nil {
			responses = append(responses, response{
				JSONRPC: "2.0",
				Error:   NewError(CodeParseError, "parse error"),
				ID:      nil,
			})
			continue
		}

		if req.JSONRPC != "2.0" {
			responses = append(responses, response{
				JSONRPC: "2.0",
				Error:   NewError(CodeInvalidRequest, "invalid request"),
				ID:      req.ID,
			})
			continue
		}

		if req.Method == "" {
			responses = append(responses, response{
				JSONRPC: "2.0",
				Error:   NewError(CodeInvalidRequest, "method required"),
				ID:      req.ID,
			})
			continue
		}

		// Notification: no id means no response expected.
		if req.ID == nil {
			if _, err := e.invokeMethod(ctx, req.Method, req.Params); err != nil {
				log.Printf("jsonrpc notification error: method=%s error=%v", req.Method, err)
			}
			continue
		}

		result, err := e.invokeMethod(ctx, req.Method, req.Params)
		resp := response{
			JSONRPC: "2.0",
			ID:      req.ID,
		}
		if err != nil {
			resp.Error = mapError(err)
		} else {
			resp.Result = result
		}
		responses = append(responses, resp)
	}

	// No responses means all requests were notifications.
	if len(responses) == 0 {
		return &jsonrpcRenderer{noContent: true}, nil
	}

	return &jsonrpcRenderer{responses: responses, single: single}, nil
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	ID      interface{} `json:"id,omitempty"`
}

// jsonrpcRenderer renders JSON-RPC responses.
type jsonrpcRenderer struct {
	responses []response
	single    bool
	noContent bool
	err       *JSONRPCError
}

func (r *jsonrpcRenderer) Render(w http.ResponseWriter, req *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	if r.err != nil {
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(response{
			JSONRPC: "2.0",
			Error:   r.err,
			ID:      nil,
		})
	}

	if r.noContent {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	w.WriteHeader(http.StatusOK)
	if r.single {
		return json.NewEncoder(w).Encode(r.responses[0])
	}
	return json.NewEncoder(w).Encode(r.responses)
}

// parseMethod extracts method signature information via reflection.
// Valid signature: func(ctx context.Context, params...) (result, error)
// Returns nil for invalid signatures.
func parseMethod(receiver reflect.Value, method reflect.Method) (*rpcMethod, string) {
	ft := method.Func.Type()

	if ft.NumIn() != 3 {
		return nil, ""
	}
	if ft.In(1) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		return nil, ""
	}
	if ft.NumOut() != 2 {
		return nil, ""
	}
	if ft.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		return nil, ""
	}

	rpc := &rpcMethod{
		receiver: receiver,
		method:   method,
	}

	paramType := ft.In(2)
	if paramType.Kind() != reflect.Struct {
		return nil, ""
	}

	rpc.paramType = paramType
	rpc.methodName = method.Name

	paramFields := make([]int, 0)
	for i := 0; i < paramType.NumField(); i++ {
		field := paramType.Field(i)
		if field.Name == "_" {
			if tag := field.Tag.Get("jsonrpc"); tag != "" {
				rpc.methodName = tag
			}
			continue
		}
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" {
			paramFields = append(paramFields, i)
		} else {
			name := strings.Split(jsonTag, ",")[0]
			if name == "" || name == "-" {
				continue
			}
			paramFields = append(paramFields, i)
		}
	}
	rpc.paramFields = paramFields

	return rpc, rpc.methodName
}

func (e *JSONRPCEndpoint) invokeMethod(ctx context.Context, name string, params json.RawMessage) (interface{}, error) {
	e.mu.RLock()
	method, ok := e.methods[name]
	e.mu.RUnlock()

	if !ok {
		return nil, NewError(CodeMethodNotFound, "method not found: "+name)
	}

	return method.call(ctx, params)
}

// mapError converts any error to a JSON-RPC error.
// JSONRPCError types preserve their code; other errors become InternalError
// with a generic message to avoid exposing internal details.
func mapError(err error) interface{} {
	if rpcErr, ok := err.(*JSONRPCError); ok {
		return rpcErr
	}
	log.Printf("jsonrpc internal error: %v", err)
	return &JSONRPCError{
		Code:    CodeInternalError,
		Message: "internal error",
	}
}
