package endpoint

import (
	htmltmpl "html/template"
	"strings"
)

// PathLink is a breadcrumb segment used by [FancyDirTemplate].
// Name is the display label; URL is the relative href (empty for the current segment).
type PathLink struct {
	Name string
	URL  string // empty for the current (last) segment
}

// PathLinks splits a directory path into breadcrumb segments for use in
// directory listing templates. The root segment is always first; the last
// segment (the current directory) has an empty URL.
func PathLinks(p string) []PathLink {
	if p == "" {
		return []PathLink{{Name: "(root)"}}
	}
	parts := strings.Split(p, "/")
	n := len(parts)
	links := make([]PathLink, 0, n+1)
	links = append(links, PathLink{Name: "(root)", URL: strings.Repeat("../", n)})
	for i, part := range parts {
		levels := n - 1 - i
		url := ""
		if levels > 0 {
			url = strings.Repeat("../", levels)
		}
		links = append(links, PathLink{Name: part, URL: url})
	}
	return links
}

const fancyDirTemplateText = `<!doctype html>
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

// FancyDirTemplate is a styled, sortable directory listing template ready for
// use as [FileSystem.DirTemplate]. It renders a table with clickable column headers
// (Name, Size, Modified), breadcrumb navigation, and JavaScript-powered
// client-side sorting. Directories always sort before files.
//
// The template data model is [DirectoryHTMLData].
var FancyDirTemplate = htmltmpl.Must(htmltmpl.New("dir").Funcs(htmltmpl.FuncMap{
	"formatSize": FormatSize,
	"pathLinks":  PathLinks,
}).Parse(fancyDirTemplateText))
