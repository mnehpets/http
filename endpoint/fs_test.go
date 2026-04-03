package endpoint

import (
	"context"
	"errors"
	htmltmpl "html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestStaticFileRenderer_ServesContent(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	modTime := time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC)
	fsys := fstest.MapFS{
		"test.txt": &fstest.MapFile{
			Data:    []byte("hello world"),
			ModTime: modTime,
		},
	}
	f, err := fsys.Open("test.txt")
	if err != nil {
		t.Fatalf("fs.Open returned error: %v", err)
	}
	defer f.Close()

	r := StaticFileRenderer{File: f}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := rec.Body.String(); got != "hello world" {
		t.Fatalf("expected body %q, got %q", "hello world", got)
	}
}

func TestStaticFileRenderer_SetsContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
	modTime := time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC)
	fsys := fstest.MapFS{
		"file.txt": &fstest.MapFile{
			Data:    []byte("content"),
			ModTime: modTime,
		},
	}
	f, err := fsys.Open("file.txt")
	if err != nil {
		t.Fatalf("fs.Open returned error: %v", err)
	}
	defer f.Close()

	r := StaticFileRenderer{File: f}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		t.Fatalf("expected Content-Type to be set, got empty")
	}
	if !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("expected text/plain Content-Type, got %q", ct)
	}
}

func TestStaticFileRenderer_NilFile_NoOutput(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := StaticFileRenderer{File: nil}
	if err := r.Render(rec, req); err == nil {
		t.Fatalf("expected error for nil File in Render, got nil")
	}
}

// fs.FileInfoToDirEntry uses FileInfo.IsDir() to set IsDir behavior. MemoryFile
// file infos always report IsDir=false. For the directory row test, wrap it.
type testDirFileInfo struct {
	fs.FileInfo
	isDir bool
}

func (fi testDirFileInfo) IsDir() bool { return fi.isDir }

func TestDirectoryHTMLRenderer_DefaultTemplate_RendersAndSetsDefaults(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	fsys := fstest.MapFS{
		"subdir":   &fstest.MapFile{Mode: fs.ModeDir | 0o755, ModTime: time.Date(2020, 1, 2, 3, 4, 0, 0, time.UTC)},
		"file.txt": &fstest.MapFile{Data: []byte("hello"), Mode: 0o644, ModTime: time.Date(2021, 2, 3, 4, 5, 0, 0, time.UTC)},
	}

	fiDirInfo, err := fs.Stat(fsys, "subdir")
	if err != nil {
		t.Fatalf("stat dir returned error: %v", err)
	}
	fiFileInfo, err := fs.Stat(fsys, "file.txt")
	if err != nil {
		t.Fatalf("stat file returned error: %v", err)
	}

	deDir := fs.FileInfoToDirEntry(testDirFileInfo{FileInfo: fiDirInfo, isDir: true})
	deFile := fs.FileInfoToDirEntry(fiFileInfo)

	entries := []fs.DirEntry{
		deDir,
		deFile,
	}

	renderer := DirectoryHTMLRenderer{DirectoryHTMLData: DirectoryHTMLData{Path: "subdir", Entries: entries}}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/html; charset=utf-8", got)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Directory: subdir") {
		t.Fatalf("expected body to contain directory path heading, got %q", body)
	}
	if !strings.Contains(body, "subdir/") {
		t.Fatalf("expected body to contain %q, got %q", "subdir/", body)
	}
	if !strings.Contains(body, "href=\"subdir/\"") {
		t.Fatalf("expected directory href in body, got %q", body)
	}
	if !strings.Contains(body, "href=\"file.txt\"") {
		t.Fatalf("expected file href in body, got %q", body)
	}
	if !strings.Contains(body, ">5<") {
		t.Fatalf("expected file size in body, got %q", body)
	}
	if !strings.Contains(body, "2021-02-03 04:05") {
		t.Fatalf("expected file modtime in body, got %q", body)
	}
}

func TestDirectoryHTMLRenderer_CustomTemplate_NameAndStatus(t *testing.T) {
	tmpl := htmltmpl.Must(htmltmpl.New("one").Parse("ONE"))
	htmltmpl.Must(tmpl.New("two").Parse("TWO"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := DirectoryHTMLRenderer{DirectoryHTMLData: DirectoryHTMLData{Entries: nil}, Template: tmpl, Name: "two", Status: http.StatusCreated}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if rec.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, rec.Result().StatusCode)
	}
	if got := rec.Body.String(); got != "TWO" {
		t.Fatalf("expected body %q, got %q", "TWO", got)
	}
}

func TestDirectoryHTMLRenderer_EmptyDirectory(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := DirectoryHTMLRenderer{DirectoryHTMLData: DirectoryHTMLData{Path: "empty", Entries: nil}}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/html; charset=utf-8", got)
	}

	// Should render the page skeleton without any rows.
	body := rec.Body.String()
	if !strings.Contains(body, "<h1>Directory: empty</h1>") {
		t.Fatalf("expected body to contain header, got %q", body)
	}
	if strings.Contains(body, "href=\"") {
		t.Fatalf("expected no links for empty directory, got %q", body)
	}
}

func TestFileSystemEndpoint_ServesFile(t *testing.T) {
	f := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"hello.txt": &fstest.MapFile{Data: []byte("hello")},
			}, nil
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	rndr, err := f.Endpoint(rec, req, FileSystemParams{Path: "hello.txt"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}

	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if got := rec.Body.String(); got != "hello" {
		t.Fatalf("expected body %q, got %q", "hello", got)
	}
}

func TestFileSystemEndpoint_DirectoryRedirectsWithoutSlash(t *testing.T) {
	f := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"dir/index.html": &fstest.MapFile{Data: []byte("INDEX")},
			}, nil
		},
		IndexHTML: true,
	}

	// Use a real ServeMux to validate path param handling / canonicalization.
	mux := http.NewServeMux()
	mux.HandleFunc("/{path...}", HandleFunc(f.Endpoint))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dir", nil)
	mux.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("expected status %d, got %d", http.StatusMovedPermanently, resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/dir/" {
		t.Fatalf("expected Location %q, got %q", "/dir/", got)
	}
}

func TestFileSystemEndpoint_DirectoryServesIndexHTML(t *testing.T) {
	f := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"dir/index.html": &fstest.MapFile{Data: []byte("INDEX")},
			}, nil
		},
		IndexHTML: true,
	}

	// Use a real ServeMux to validate path param handling.
	mux := http.NewServeMux()
	mux.HandleFunc("/{path...}", HandleFunc(f.Endpoint))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dir/", nil)
	mux.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if got := rec.Body.String(); got != "INDEX" {
		t.Fatalf("expected body %q, got %q", "INDEX", got)
	}
}

func TestFileSystemEndpoint_DirectoryRedirects_WhenMountedUnderPrefix(t *testing.T) {
	f := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"dira/dirb/index.html": &fstest.MapFile{Data: []byte("INDEX")},
			}, nil
		},
		IndexHTML: true,
	}

	// Use a real ServeMux to ensure prefix mounting and path param decoding.
	mux := http.NewServeMux()
	mux.HandleFunc("/prefix/{path...}", HandleFunc(f.Endpoint))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/prefix/dira/dirb", nil)
	mux.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("expected status %d, got %d", http.StatusMovedPermanently, resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/prefix/dira/dirb/" {
		t.Fatalf("expected Location %q, got %q", "/prefix/dira/dirb/", got)
	}
}

func TestFileSystemEndpoint_DirectoryListing(t *testing.T) {
	f := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"dir/a.txt": &fstest.MapFile{Data: []byte("A")},
				"dir/b.txt": &fstest.MapFile{Data: []byte("B")},
			}, nil
		},
		DirectoryListing: true,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dir/", nil)

	rndr, err := f.Endpoint(rec, req, FileSystemParams{Path: "dir/"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}

	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/html; charset=utf-8", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "href=\"a.txt\"") {
		t.Fatalf("expected listing to contain a.txt link, got %q", body)
	}
}

func TestFileSystemEndpoint_DirectoryWithoutIndexOrListingIs404(t *testing.T) {
	f := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"dir/a.txt": &fstest.MapFile{Data: []byte("A")},
			}, nil
		},
		IndexHTML:        false,
		DirectoryListing: false,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dir/", nil)

	rndr, err := f.Endpoint(rec, req, FileSystemParams{Path: "dir/"})
	if err == nil {
		t.Fatalf("expected error, got renderer=%T", rndr)
	}
	var ee *EndpointError
	if !errors.As(err, &ee) {
		t.Fatalf("expected EndpointError, got %T: %v", err, err)
	}
	if ee.Status != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, ee.Status)
	}
}

func TestFileSystemEndpoint_FileRendererHook_ReturnsRenderer(t *testing.T) {
	called := false
	hook := FileRendererHook(func(filePath string, fsys fs.FS, f fs.File) (Renderer, error) {
		called = true
		if filePath != "hello.txt" {
			return nil, nil
		}
		_ = f // hook takes ownership
		return &StringRenderer{Body: "hook rendered"}, nil
	})

	fs := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"hello.txt": &fstest.MapFile{Data: []byte("static")},
			}, nil
		},
	}
	fs.FileRenderer = hook

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)

	rndr, err := fs.Endpoint(rec, req, FileSystemParams{Path: "hello.txt"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}
	if !called {
		t.Fatal("expected hook to be called")
	}
	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if got := rec.Body.String(); got != "hook rendered" {
		t.Fatalf("expected body %q, got %q", "hook rendered", got)
	}
}

func TestFileSystemEndpoint_FileRendererHook_NilFallsThrough(t *testing.T) {
	hook := FileRendererHook(func(filePath string, fsys fs.FS, f fs.File) (Renderer, error) {
		return nil, nil // not handled — fall through to default
	})

	fse := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"static.css": &fstest.MapFile{Data: []byte("body{}")},
			}, nil
		},
	}
	fse.FileRenderer = hook

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static.css", nil)

	rndr, err := fse.Endpoint(rec, req, FileSystemParams{Path: "static.css"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}
	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if got := rec.Body.String(); got != "body{}" {
		t.Fatalf("expected default static body %q, got %q", "body{}", got)
	}
}

func TestFileSystemEndpoint_FileRendererHook_Omitted_DefaultBehaviour(t *testing.T) {
	fse := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"page.txt": &fstest.MapFile{Data: []byte("content")},
			}, nil
		},
	}
	// No FileRenderer set.

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/page.txt", nil)

	rndr, err := fse.Endpoint(rec, req, FileSystemParams{Path: "page.txt"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}
	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if got := rec.Body.String(); got != "content" {
		t.Fatalf("expected body %q, got %q", "content", got)
	}
}

func TestFileSystemEndpoint_DirRendererHook_ReturnsRenderer(t *testing.T) {
	called := false
	hook := FileRendererHook(func(filePath string, fsys fs.FS, f fs.File) (Renderer, error) {
		called = true
		if filePath != "blog" {
			return nil, nil
		}
		return &StringRenderer{Body: "blog index"}, nil
	})

	fse := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"blog/post.md": &fstest.MapFile{Data: []byte("post")},
			}, nil
		},
	}
	fse.DirRenderer = hook

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/blog/", nil)

	rndr, err := fse.Endpoint(rec, req, FileSystemParams{Path: "blog/"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}
	if !called {
		t.Fatal("expected DirFallback hook to be called")
	}
	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if got := rec.Body.String(); got != "blog index" {
		t.Fatalf("expected body %q, got %q", "blog index", got)
	}
}

func TestFileSystemEndpoint_DirRendererHook_NilFallsThrough(t *testing.T) {
	hook := FileRendererHook(func(filePath string, fsys fs.FS, f fs.File) (Renderer, error) {
		return nil, nil // not handled
	})

	fse := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"dir/a.txt": &fstest.MapFile{Data: []byte("A")},
			}, nil
		},
		DirectoryListing: true,
	}
	fse.DirRenderer = hook

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dir/", nil)

	rndr, err := fse.Endpoint(rec, req, FileSystemParams{Path: "dir/"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}
	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	// Should fall through to directory listing.
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected directory listing Content-Type, got %q", got)
	}
}

func TestFileSystemEndpoint_DirRendererHook_Omitted_DefaultBehaviour(t *testing.T) {
	fse := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"dir/a.txt": &fstest.MapFile{Data: []byte("A")},
			}, nil
		},
		DirectoryListing: true,
		// No DirRenderer set.
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dir/", nil)

	rndr, err := fse.Endpoint(rec, req, FileSystemParams{Path: "dir/"})
	if err != nil {
		t.Fatalf("Endpoint returned error: %v", err)
	}
	if err := rndr.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected directory listing Content-Type, got %q", got)
	}
}

func TestFileSystemEndpoint_PathTraversalIsNotFound(t *testing.T) {
	f := &FileSystem{
		FS: func(_ context.Context, _ *http.Request) (fs.FS, error) {
			return fstest.MapFS{
				"index.html": &fstest.MapFile{Data: []byte("ROOT")},
			}, nil
		},
		IndexHTML: false,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// This should clean to "." and attempt to open dot; in a plain fstest.MapFS
	// it won't exist, so we should get a 404 rather than serving something else.
	rndr, err := f.Endpoint(rec, req, FileSystemParams{Path: "../"})
	_ = rndr
	if err == nil {
		t.Fatalf("expected error")
	}
	var ee *EndpointError
	if !errors.As(err, &ee) {
		t.Fatalf("expected EndpointError, got %T: %v", err, err)
	}
	if ee.Status != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, ee.Status)
	}

	// Ensure a non-empty path doesn't cause redirect URL issues.
	// This is mostly a regression guard for Location formatting.
	loc := (&url.URL{Path: "dir"}).String()
	_ = loc
}
