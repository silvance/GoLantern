package report

import (
	"bytes"
	"fmt"
	"html/template"
)

// htmlTemplate is the single-page report. Kept inline (and small) so
// stylistic tweaks don't need a separate file walk; the SPA renders
// the same bundle natively, so this template is mainly for emailable /
// printable exports.
//
// Severity gets a CSS class so callers can colour-code without parsing
// the text. html/template handles all escaping automatically.
const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Project.Name}} — Lantern report</title>
<style>
  body { font: 14px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 1080px; margin: 2em auto; padding: 0 1em; color: #1a1a1a; }
  h1 { font-size: 1.6em; margin-bottom: 0.2em; }
  h2 { font-size: 1.2em; margin-top: 1.6em; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }
  .meta { color: #555; }
  table { border-collapse: collapse; width: 100%; margin: 0.5em 0 1.5em; }
  th, td { text-align: left; padding: 0.4em 0.6em; border-bottom: 1px solid #eee; vertical-align: top; }
  th { background: #f5f5f7; font-weight: 600; }
  .sev-critical { color: #b91c1c; font-weight: 600; }
  .sev-high     { color: #c2410c; font-weight: 600; }
  .sev-medium   { color: #a16207; }
  .sev-low      { color: #4d7c0f; }
  .sev-info     { color: #475569; }
  .empty { color: #888; font-style: italic; }
  pre { background: #f5f5f7; padding: 0.6em; overflow-x: auto; font-size: 12px; border-radius: 4px; }
</style>
</head>
<body>
<h1>{{.Project.Name}}</h1>
<p class="meta">
  {{with .Project.Organization}}{{.}} · {{end}}
  Mode: {{.Project.Mode}} ·
  Default scope: {{.Project.DefaultScope}} ·
  Template: {{.Project.ReportTemplate}}
</p>
{{with .Project.Description}}<p>{{.}}</p>{{end}}

<h2>Summary</h2>
<table>
  <tr><th>Entities</th><td>{{.Summary.EntitiesTotal}}</td></tr>
  <tr><th>Findings</th><td>{{.Summary.FindingsTotal}}</td></tr>
  <tr><th>Runs</th><td>{{.Summary.RunsTotal}}</td></tr>
</table>

<h2>Findings</h2>
{{if .Findings}}
<table>
  <thead><tr><th>Severity</th><th>Title</th><th>Confidence</th><th>Category</th><th>Evidence</th></tr></thead>
  <tbody>
  {{range .Findings}}
    <tr>
      <td><span class="sev-{{.Severity}}">{{.Severity}}</span></td>
      <td>
        <strong>{{.Title}}</strong>
        {{with .Description}}<div>{{.}}</div>{{end}}
        {{with .Recommendation}}<div><em>Recommendation:</em> {{.}}</div>{{end}}
      </td>
      <td>{{.Confidence}}</td>
      <td>{{or .Category "—"}}</td>
      <td>{{len .Evidence}}</td>
    </tr>
  {{end}}
  </tbody>
</table>
{{else}}<p class="empty">No findings.</p>{{end}}

<h2>Entities</h2>
{{range $kind, $rows := .EntitiesByKind}}
  {{if $rows}}
    <h3>{{$kind}} ({{len $rows}})</h3>
    <table>
      <thead><tr><th>Value</th></tr></thead>
      <tbody>{{range $rows}}<tr><td>{{.Value}}</td></tr>{{end}}</tbody>
    </table>
  {{end}}
{{else}}<p class="empty">No entities.</p>{{end}}

<h2>Runs</h2>
{{if .Runs}}
<table>
  <thead><tr><th>Phase</th><th>Status</th><th>Label</th><th>ID</th></tr></thead>
  <tbody>
  {{range .Runs}}
    <tr><td>{{.Phase}}</td><td>{{.Status}}</td><td>{{or .Label ""}}</td><td><code>{{.ID}}</code></td></tr>
  {{end}}
  </tbody>
</table>
{{else}}<p class="empty">No runs.</p>{{end}}
</body>
</html>
`

// parsed once at init so render errors surface at startup instead of
// the first request.
var htmlT = template.Must(template.New("report").Parse(htmlTemplate))

// RenderHTML writes a self-contained HTML document for b to a byte
// buffer. The output is safe to serve directly (html/template handles
// escaping); CSS is inlined so there are no external requests.
func RenderHTML(b *Bundle) ([]byte, error) {
	var buf bytes.Buffer
	if err := htmlT.Execute(&buf, b); err != nil {
		return nil, fmt.Errorf("report.RenderHTML: %w", err)
	}
	return buf.Bytes(), nil
}
