package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mnehpets/http/endpoint"
)

type EmptyParams struct{}

func eventsEndpoint(w http.ResponseWriter, r *http.Request, params EmptyParams) (endpoint.Renderer, error) {
	msgType := "message"
	events := func(yield func(endpoint.SSEvent) bool) {
		for i := 0; i < 5; i++ {
			if !yield(endpoint.SSEvent{
				Type: &msgType,
				Data: fmt.Sprintf(`{"count": %d}`, i),
			}) {
				return
			}
			time.Sleep(time.Second)
		}
	}
	return &endpoint.SSERenderer{Events: events}, nil
}

func main() {
	handler := endpoint.HandleFunc(eventsEndpoint)
	log.Println("Listening on :8080")
	log.Println("Visit http://localhost:8080/events in browser")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}
