package endpoint

import (
	"context"
	"errors"
	"fmt"
	htmltmpl "html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// StaticFileRenderer is a terminal renderer implementation that serves a
// single static file from an fs.File.
//
// StaticFileRenderer expects an fs.File that also implements io.ReadSeeker
// StaticFileRenderer closes the file when Close() is called, which happens
// automatically when the renderer is returned by an EndpointHandler.
type StaticFileRenderer struct {
	File fs.File
}

// Close closes the underlying file.
func (sfr *StaticFileRenderer) Close() error {
	if sfr.File != nil {
		return sfr.File.Close()
	}
	return nil
}

// Render streams the file contents to the response using http.ServeContent,
// which handles Content-Type detection, range requests, caching headers, and
// writes the status line.
//
// StaticFileRenderer is terminal: it MUST call WriteHeader (indirectly via
// http.ServeContent) and MUST NOT call next.
func (sfr *StaticFileRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	if sfr.File == nil {
		// Nil File indicates a programming or wiring error.
		return http.ErrMissingFile
	}

	// Derive a name and modification time from the file's Stat result. These
	// are optional hints to ServeContent.
	var (
		name    string
		modTime time.Time
	)
	if info, err := sfr.File.Stat(); err == nil {
		name = info.Name()
		modTime = info.ModTime()
	}

	// http.ServeContent requires an io.ReadSeeker. StaticFileRenderer expects
	// that the provided fs.File implements io.ReadSeeker; if it does not, this
	// is treated as a programming error.
	rs, ok := sfr.File.(io.ReadSeeker)
	if !ok {
		return http.ErrNotSupported
	}

	http.ServeContent(w, r, name, modTime, rs)
	return nil
}

// DirectoryHTMLRenderer renders a directory listing as HTML.
// Rendering is buffered to catch template execution errors before
// committing the response.
//
// Entries is required.
//
// Template is optional. If nil, a default template is used.
//
// Name is optional; when set, ExecuteTemplate is used.
//
// Status is optional; when 0, http.StatusOK is used.
type DirectoryHTMLRenderer struct {
	DirectoryHTMLData

	Template *htmltmpl.Template
	Name     string
	Status   int
}

// DirectoryHTMLData is the default template data model for DirectoryHTMLRenderer.
//
// It is embedded into DirectoryHTMLRenderer so custom templates can access these
// fields directly.
type DirectoryHTMLData struct {
	// Path is the relative path within the served FS for which Entries were read.
	// It is provided to templates for display purposes (e.g., heading/title).
	// Optional; when empty, templates may treat it as "." or root.
	Path string

	Entries []fs.DirEntry
}

func (dr *DirectoryHTMLRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	tmpl := dr.Template
	if tmpl == nil {
		var err error

		// Construct default template with helper functions.
		tmpl, err = htmltmpl.New("dir").Funcs(htmltmpl.FuncMap{
			"formatSize": FormatSize,
		}).Parse(defaultDirectoryHTMLTemplateText)
		if err != nil {
			return err
		}
	}

	renderer := HTMLTemplateRenderer{
		Status:   dr.Status,
		Template: tmpl,
		Name:     dr.Name,
		Values:   &dr.DirectoryHTMLData,
	}
	return renderer.Render(w, r)
}

const defaultDirectoryHTMLTemplateText = `
<html>
	<head>
		<title>Directory: {{ .Path }}</title>
		<style>
html { font-family: monospace; }
		</style>
	</head>

	<body>
		<h1>Directory: {{ .Path }}</h1>
		<table>
			<thead>
				<tr>
					<th>Modified</th>
					<th>Size</th>
					<th>Name</th>
				</tr>
			</thead>
			<tbody>
{{- range .Entries }}
				{{- $fi := .Info }}
				<tr>
					{{- if $fi }}
					<td>{{ $fi.ModTime.Format "2006-01-02 15:04" }}</td>
					{{- else }}
					<td></td>
					{{- end }}
{{- if .IsDir }}
					<td>[DIR]</td>
					<td><a href="{{ .Name }}/">{{ .Name }}/</a></td>
{{- else }}
					{{- if $fi }}
					<td>{{ formatSize $fi.Size }}</td>
					{{- else }}
					<td></td>
					{{- end }}
					<td><a href="{{ .Name }}">{{ .Name }}</a></td>
{{- end }}
				</tr>
{{- end }}
			</tbody>
		</table>
	</body>
</html>
`

// FormatSize formats a byte size into a compact human-readable string.
func FormatSize(size int64) string {
	if size < 5e2 {
		return strconv.FormatInt(size, 10)
	} else if size < 5e5 {
		return fmt.Sprintf("%1.2fk", float64(size)/1024)
	} else if size < 5e8 {
		return fmt.Sprintf("%1.2fM", float64(size)/1024/1024)
	}
	return fmt.Sprintf("%1.2fG", float64(size)/1024/1024/1024)
}

// FileRendererHook is called by FileSystem when a file or directory is opened.
// It receives the request URL path and the open fs.File.
//
// Ownership rules:
//   - If a non-nil Renderer is returned, ownership of the file transfers to
//     the hook; FileSystem will not close it.
//   - If nil, nil is returned, ownership remains with FileSystem, which will
//     continue with its default handling. The hook MUST NOT have called Read
//     or ReadDir on the file; Stat is safe.
type FileRendererHook func(urlPath string, f fs.File) (Renderer, error)

// FileSystemOption configures a FileSystem endpoint.
type FileSystemOption func(*FileSystem)

// WithFileRenderer returns a FileSystemOption that installs a hook called
// after path normalisation but before default static file serving. Returning
// nil, nil falls through to http.ServeContent.
func WithFileRenderer(fn FileRendererHook) FileSystemOption {
	return func(f *FileSystem) { f.fileRenderer = fn }
}

// WithDirRenderer returns a FileSystemOption that installs a hook called
// after path normalisation but before any index-file lookup or directory
// listing. Returning nil, nil falls through to the default directory handling
// (IndexHTML, DirectoryListing, 404).
func WithDirRenderer(fn FileRendererHook) FileSystemOption {
	return func(f *FileSystem) { f.dirRenderer = fn }
}

// FileSystemParams are the decoded request params for FileSystem.
//
// Callers typically mount this using a mux wildcard like: "/blah/{path...}".
type FileSystemParams struct {
	// Path is the requested file path, relative to the handler mount.
	Path string `path:"path"`
}

// FileSystem is an endpoint for serving files from an fs.FS.
//
// It intentionally contains ONLY generic file serving features:
//   - direct file mapping
//   - optional index.html resolution for directories
//   - optional directory listings
//   - trailing-slash redirects for directories
//
// SPA-style fallback routing is intentionally not implemented.
type FileSystem struct {
	// FS is a factory that returns the fs.FS to serve for the current request.
	//
	// This is invoked per-request so callers can construct an FS dynamically,
	// e.g. using credentials carried on the request.
	FS func(ctx context.Context, r *http.Request) (fs.FS, error)

	// IndexHTML, if true, serves "index.html" when a directory is requested.
	IndexHTML bool

	// DirectoryListing, if true, serves an HTML listing when a directory is
	// requested and IndexHTML does not resolve.
	DirectoryListing bool

	fileRenderer FileRendererHook
	dirRenderer  FileRendererHook
}

// Endpoint serves a file or directory from the configured FS.
//
// Signature matches endpoint.EndpointFunc so callers can do:
// mux.HandleFunc("/blah/{path...}", endpoint.Handler(fs.Endpoint))
func (f *FileSystem) Endpoint(w http.ResponseWriter, r *http.Request, params FileSystemParams) (Renderer, error) {
	if r == nil {
		return nil, Error(http.StatusInternalServerError, "internal server error", errors.New("endpoint: filesystem: nil request"))
	}
	if f == nil || f.FS == nil {
		return nil, Error(http.StatusInternalServerError, "filesystem: nil FS", errors.New("endpoint: filesystem: nil FS"))
	}

	fsys, err := f.FS(r.Context(), r)
	if err != nil {
		return nil, Error(http.StatusInternalServerError, "failed to resolve filesystem", err)
	}
	if fsys == nil {
		return nil, Error(http.StatusInternalServerError, "filesystem: nil FS", errors.New("endpoint: filesystem: FS factory returned nil"))
	}

	// Sanitize and normalize into an fs.FS path.
	//	- params.Path can be empty (mount root)
	//	- fs.FS paths must be relative and must not start with '/'
	//	- path.Clean yields a slash-separated path regardless of OS
	p := path.Clean("/" + params.Path)
	if p == "/" {
		p = "."
	} else {
		p = strings.TrimPrefix(p, "/")
	}

	file, err := fsys.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, Error(http.StatusNotFound, "not found", err)
		}
		return nil, Error(http.StatusInternalServerError, "internal server error", err)
	}

	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return nil, Error(http.StatusInternalServerError, "internal server error", statErr)
	}

	if info.IsDir() {
		// Redirect to add trailing slash if missing so that relative links resolve.
		// Empty path means mount root; do not redirect.
		if params.Path != "" && !strings.HasSuffix(params.Path, "/") {
			_ = file.Close()
			// Preserve any mux mount prefix by redirecting based on the request path.
			// r.URL.Path is the full request path (including the mount prefix).
			// Since we're only appending a trailing slash, this remains within the
			// same logical resource.
			urlPath := "/"
			if r.URL != nil && r.URL.Path != "" {
				urlPath = r.URL.Path
			}
			if !strings.HasSuffix(urlPath, "/") {
				urlPath += "/"
			}
			return &RedirectRenderer{URL: urlPath, Status: http.StatusMovedPermanently}, nil
		}

		// DirRenderer hook: called before index-file lookup or directory listing.
		// The hook receives the open directory file; it MUST NOT call ReadDir
		// if it returns nil, nil.
		if f.dirRenderer != nil {
			urlPath := ""
			if r.URL != nil {
				urlPath = r.URL.Path
			}
			renderer, err := f.dirRenderer(urlPath, file)
			if err != nil {
				_ = file.Close()
				return nil, err
			}
			if renderer != nil {
				// Ownership of file transferred to the hook/renderer.
				return renderer, nil
			}
		}

		// Optionally serve index.html for directories.
		if f.IndexHTML {
			indexPath := path.Join(p, "index.html")
			if indexFile, err := fsys.Open(indexPath); err == nil {
				_ = file.Close()
				return &StaticFileRenderer{File: indexFile}, nil
			}
		}

		// Optionally provide listing.
		if f.DirectoryListing {
			if rdf, ok := file.(fs.ReadDirFile); ok {
				entries, err := rdf.ReadDir(-1)
				if err != nil {
					_ = file.Close()
					return nil, Error(http.StatusInternalServerError, "failed to read directory", err)
				}
				_ = file.Close()
				// Provide a stable, relative directory path for the template.
				dirPath := p
				if dirPath == "." {
					dirPath = ""
				}
				return &DirectoryHTMLRenderer{DirectoryHTMLData: DirectoryHTMLData{Path: dirPath, Entries: entries}}, nil
			}
		}

		_ = file.Close()
		return nil, Error(http.StatusNotFound, "not found", fs.ErrNotExist)
	}

	// FileRenderer hook: called before default static file serving.
	// The hook receives the open file; it MUST NOT call Read if it returns nil, nil.
	if f.fileRenderer != nil {
		urlPath := ""
		if r.URL != nil {
			urlPath = r.URL.Path
		}
		renderer, err := f.fileRenderer(urlPath, file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if renderer != nil {
			// Ownership of file transferred to the hook/renderer.
			return renderer, nil
		}
		// nil, nil: fall through to default static file serving.
	}

	return &StaticFileRenderer{File: file}, nil
}
