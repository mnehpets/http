package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"

	"github.com/mnehpets/http/endpoint"
)

func main() {
	// Serve the local ./public directory.
	root := os.DirFS("public")

	fsEndpoint := &endpoint.FileSystem{
		FS: func(ctx context.Context, r *http.Request) (fs.FS, error) {
			return root, nil
		},
		IndexHTML:        true,
		DirectoryListing: true,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{path...}", endpoint.HandleFunc(fsEndpoint.Endpoint))

	log.Println("Filesystem example listening on :8080")
	log.Println("Serving FS from ./public")
	if _, err := fs.Stat(root, "."); err != nil {
		log.Println("warning: ./public does not exist or is not readable:", err)
	}

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
