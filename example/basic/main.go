package main

import (
	"log"
	"net/http"

	"github.com/mnehpets/http/endpoint"
)

// HelloParams defines the parameters for the hello endpoint.
type HelloParams struct{}

// HelloEndpoint is the business logic for the hello endpoint.
func HelloEndpoint(w http.ResponseWriter, r *http.Request, params HelloParams) (endpoint.Renderer, error) {
	return &endpoint.StringRenderer{
		Body: "Hello, World!",
	}, nil
}

func main() {
	// Create a handler for the hello endpoint.
	// endpoint.Handler wraps the function and provides type-safe parameter decoding.
	handler := endpoint.HandleFunc(HelloEndpoint)

	log.Println("Listening on :8080")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}
