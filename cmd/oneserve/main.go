package main

import (
	"context"
	"flag"
	"fmt"
	htmltmpl "html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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

const dirTemplateText = `<!doctype html>
<html><head>
<meta charset="utf-8">
<title>{{ if .Path }}/{{ .Path }}{{ else }}/{{ end }}</title>
<style>
body { margin: 0; font-family: lucida-sans, verdana, sans-serif; }
a { color: blue; text-decoration: none; }
a:hover { text-decoration: underline; }
.head {
  padding: 8px 24px;
  margin-bottom: 8px;
  background-color: rgb(240, 240, 255);
  font-size: 24px;
  font-weight: bold;
  color: rgb(92, 25, 130);
}
table { margin-left: 8px; margin-right: 8px; border-collapse: collapse; font-family: Consolas, Monaco, monospace; font-size: 12px; }
th { padding: 4px; text-align: right; cursor: pointer; user-select: none; white-space: nowrap; }
th:first-child { text-align: left; }
th[aria-sort=ascending]::after { content: " ↑"; }
th[aria-sort=descending]::after { content: " ↓"; }
td { padding-left: 4px; padding-right: 4px; text-align: right; }
td:first-child { text-align: left; }
</style>
</head><body>
<div class="head">Directory:{{- range pathLinks .Path }} {{- if .URL }}<a href="{{ .URL }}">{{ .Name }}</a>{{- else }}{{ .Name }}{{- end }}/{{- end }}</div>
<table id="t">
<thead><tr>
  <th data-col="0">Name</th>
  <th data-col="1">Size</th>
  <th data-col="2">Modified</th>
</tr></thead>
<tbody>
{{- range .Entries }}
{{- $info := .Info }}
<tr data-isdir="{{ if .IsDir }}1{{ else }}0{{ end }}">
{{- if .IsDir }}
  <td><a href="{{ .Name }}/">{{ .Name }}/</a></td>
  <td data-sort="-1">—</td>
  <td data-sort="{{ $info.ModTime.Unix }}">{{ $info.ModTime.Format "2006-01-02 15:04" }}</td>
{{- else }}
  <td><a href="{{ .Name }}">{{ .Name }}</a></td>
  <td data-sort="{{ $info.Size }}">{{ formatSize $info.Size }}</td>
  <td data-sort="{{ $info.ModTime.Unix }}">{{ $info.ModTime.Format "2006-01-02 15:04" }}</td>
{{- end }}
</tr>
{{- end }}
</tbody>
</table>
<script>
(function(){
  // All header cells and current sort state (col index, direction).
  // col === -1 means no sort has been applied yet.
  var ths = document.querySelectorAll('#t th');
  var col = -1, asc = true;

  function onClick(th) {
      var c = parseInt(th.dataset.col, 10);

      // Clicking the active column toggles direction; clicking a new column
      // resets to ascending for Name (col 0) and descending for others.
      if (col === c) { asc = !asc; } else { col = c; asc = c === 0; }

      // Update aria-sort on the active header for the CSS arrows.
      ths.forEach(function(h){ h.removeAttribute('aria-sort'); });
      th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');

      var tbody = document.querySelector('#t tbody');
      var rows = Array.from(tbody.rows);
      rows.sort(function(a, b){
        // Directories always sort before files regardless of column or direction.
        var da = a.dataset.isdir === '1' ? 0 : 1;
        var db = b.dataset.isdir === '1' ? 0 : 1;
        if (da !== db) return da - db;

        // Each cell carries a data-sort attribute with a numeric value for
        // accurate ordering (Unix timestamp for dates, raw bytes for sizes).
        // Fall back to the visible text if no data-sort is present.
        var av = a.cells[c].dataset.sort !== undefined ? a.cells[c].dataset.sort : a.cells[c].textContent.trim();
        var bv = b.cells[c].dataset.sort !== undefined ? b.cells[c].dataset.sort : b.cells[c].textContent.trim();

        // Compare numerically when both values parse as numbers, else lexically.
        var an = parseFloat(av), bn = parseFloat(bv);
        var cmp = (!isNaN(an) && !isNaN(bn)) ? an - bn : av.localeCompare(bv);
        return asc ? cmp : -cmp;
      });
      rows.forEach(function(r){ tbody.appendChild(r); });
  }

  // Attach click handlers to all header cells.
  ths.forEach(function(th){
    th.addEventListener('click', function(){ onClick(th); });
  });

  // Apply default sort: Name ascending.
  onClick(ths[0]);
})();
</script>
</body></html>`

type pathLink struct {
	Name string
	URL  string // empty for the current (last) segment
}

// pathLinks splits a directory path into breadcrumb segments, each with a
// relative URL to navigate to that directory. The root is always first.
// The last segment (current directory) has an empty URL.
func pathLinks(p string) []pathLink {
	if p == "" {
		return []pathLink{{Name: "(root)"}} // root only, no link needed
	}
	parts := strings.Split(p, "/")
	n := len(parts)
	links := make([]pathLink, 0, n+1)
	links = append(links, pathLink{Name: "(root)", URL: strings.Repeat("../", n)})
	for i, part := range parts {
		levels := n - 1 - i
		url := ""
		if levels > 0 {
			url = strings.Repeat("../", levels)
		}
		links = append(links, pathLink{Name: part, URL: url})
	}
	return links
}

var dirTemplate = htmltmpl.Must(htmltmpl.New("dir").Funcs(htmltmpl.FuncMap{
	"formatSize": endpoint.FormatSize,
	"pathLinks":  pathLinks,
}).Parse(dirTemplateText))

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
	}
	endpoint.WithDirTemplate(dirTemplate)(fsEndpoint)

	mux := http.NewServeMux()
	mux.HandleFunc("/{path...}", endpoint.HandleFunc(fsEndpoint.Endpoint))

	log.Printf("oneserve listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "oneserve:", err)
		os.Exit(2)
	}
}
