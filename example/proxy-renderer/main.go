package main

import (
	"log"
	"net/http"

	"github.com/mnehpets/http/endpoint"
)

func main() {
	// For this example, we'll proxy to https://httpbin.org/
	target := "https://httpbin.org"

	proxyEndpoint := func(w http.ResponseWriter, r *http.Request, _ struct{}) (endpoint.Renderer, error) {
		// Log the request
		log.Printf("Proxying request %s %s to %s", r.Method, r.URL.Path, target)
		return endpoint.NewProxyRenderer(target)
	}

	handler := endpoint.HandleFunc(proxyEndpoint)

	log.Println("Listening on :8080. Proxying to", target)
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}
