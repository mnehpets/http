package main

import (
	"context"
	"log"
	"net/http"

	"github.com/mnehpets/http/endpoint"
	"github.com/mnehpets/http/jsonrpc"
)

type MathMethods struct{}

type MathParams struct {
	A int `json:"a"`
	B int `json:"b"`
}

func (m *MathMethods) Add(ctx context.Context, params MathParams) (int, error) {
	return params.A + params.B, nil
}

func (m *MathMethods) Subtract(ctx context.Context, params MathParams) (int, error) {
	return params.A - params.B, nil
}

func (m *MathMethods) Multiply(ctx context.Context, params MathParams) (int, error) {
	return params.A * params.B, nil
}

func (m *MathMethods) Divide(ctx context.Context, params MathParams) (int, error) {
	if params.B == 0 {
		return 0, jsonrpc.NewError(jsonrpc.CodeInvalidParams, "division by zero")
	}
	return params.A / params.B, nil
}

func main() {
	e := jsonrpc.NewEndpoint()
	e.Register("math", &MathMethods{})

	http.Handle("/rpc", endpoint.Handler(e.Endpoint))

	log.Println("JSON-RPC server listening on :8080")
	log.Println("Try: curl -X POST http://localhost:8080/rpc -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"math.Add\",\"params\":[5,3],\"id\":1}'")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
