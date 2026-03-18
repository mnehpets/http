package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"

	mnfs "github.com/mnehpets/fs"
	"github.com/mnehpets/http/endpoint"
)

var (
	addr      = flag.String("addr", "127.0.0.1:8080", "listen address ([host]:port)")
	symlink   = flag.String("symlink", "no", "symlink handling: no, unlisted, yes")
	dotfile   = flag.String("dotfile", "no", "dotfile handling: no, unlisted, yes")
	indexHTML = flag.Bool("indexhtml", true, "serve index.html for directories")
	dirList   = flag.Bool("dirlist", true, "enable directory listings")
)


func parseFilterMode(name, val string) (mnfs.FilterMode, error) {
	switch val {
	case "no":
		return mnfs.Disallowed, nil
	case "unlisted":
		return mnfs.Unlisted, nil
	case "yes":
		return 0, nil
	default:
		return 0, fmt.Errorf("--%s: invalid value %q: must be no, unlisted, or yes", name, val)
	}
}

func buildFilterFS(base fs.FS) (fs.FS, error) {
	symlinkMode, err := parseFilterMode("symlink", *symlink)
	if err != nil {
		return nil, err
	}
	dotfileMode, err := parseFilterMode("dotfile", *dotfile)
	if err != nil {
		return nil, err
	}

	var opts []mnfs.FilterOption
	if symlinkMode != 0 {
		opts = append(opts, mnfs.WithSymlinks(symlinkMode))
	}
	if dotfileMode != 0 {
		opts = append(opts, mnfs.WithDotfiles(dotfileMode))
	}
	if len(opts) == 0 {
		return base, nil
	}
	return mnfs.NewFilterFS(base, opts...), nil
}

func dirMode(dir string) (fs.FS, error) {
	return buildFilterFS(os.DirFS(dir))
}

func filesMode(paths []string) (fs.FS, error) {
	tree := mnfs.NewTreeFS()
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("files mode: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("files mode: %q is not a regular file", p)
		}
		name := filepath.Base(p)
		if err := tree.Add(name, mnfs.OSFile(p)); err != nil {
			return nil, fmt.Errorf("files mode: %w", err)
		}
	}
	return buildFilterFS(tree)
}

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var fsys fs.FS
	var err error

	if len(args) == 1 {
		if info, statErr := os.Stat(args[0]); statErr == nil && info.IsDir() {
			fsys, err = dirMode(args[0])
		} else {
			fsys, err = filesMode(args)
		}
	} else {
		fsys, err = filesMode(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "oneserve:", err)
		os.Exit(1)
	}

	fsEndpoint := &endpoint.FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fsys, nil
		},
		IndexHTML:        *indexHTML,
		DirectoryListing: *dirList,
		DirTemplate:      endpoint.FancyDirTemplate,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/{path...}", endpoint.HandleFunc(fsEndpoint.Endpoint))

	log.Printf("oneserve listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "oneserve:", err)
		os.Exit(2)
	}
}
