package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// RenderDOCX writes a Microsoft Word (.docx) document of the bundle.
// DOCX is just zipped Office Open XML — no external library required.
// We ship the minimum file set a conforming reader needs:
//
//	[Content_Types].xml   — MIME map
//	_rels/.rels           — package-level relationships
//	word/document.xml     — body
//
// styles.xml is intentionally omitted; Word + LibreOffice fall back to
// their built-in default style and the document renders fine without it.
//
// The body uses paragraphs with run properties for bold / heading
// sizes, and one table per section. We don't try to match the HTML
// renderer's layout pixel-for-pixel — DOCX rendering is reader-driven
// anyway — but the section ordering and content are identical.
func RenderDOCX(b *Bundle) ([]byte, error) {
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>`)

	// Title.
	body.WriteString(heading(b.Project.Name, 1))
	metaParts := []string{}
	if b.Project.Organization != "" {
		metaParts = append(metaParts, b.Project.Organization)
	}
	metaParts = append(metaParts,
		"Mode: "+b.Project.Mode,
		"Default scope: "+b.Project.DefaultScope,
		"Template: "+b.Project.ReportTemplate,
	)
	body.WriteString(paragraph(strings.Join(metaParts, " · "), false))
	if b.Project.Description != "" {
		body.WriteString(paragraph(b.Project.Description, false))
	}

	// Summary.
	body.WriteString(heading("Summary", 2))
	body.WriteString(twoColTable([][2]string{
		{"Entities", itoa(b.Summary.EntitiesTotal)},
		{"Findings", itoa(b.Summary.FindingsTotal)},
		{"Runs", itoa(b.Summary.RunsTotal)},
	}))

	// Findings.
	body.WriteString(heading("Findings", 2))
	if len(b.Findings) == 0 {
		body.WriteString(paragraph("No findings.", true))
	} else {
		rows := make([][2]string, 0, len(b.Findings)+1)
		rows = append(rows, [2]string{"Severity", "Title"})
		for _, f := range b.Findings {
			rows = append(rows, [2]string{f.Severity, f.Title})
		}
		body.WriteString(twoColTable(rows))
	}

	// Entities by kind.
	body.WriteString(heading("Entities", 2))
	wroteAny := false
	for _, kind := range sortedKinds(b.EntitiesByKind) {
		rs := b.EntitiesByKind[kind]
		if len(rs) == 0 {
			continue
		}
		wroteAny = true
		body.WriteString(heading(fmt.Sprintf("%s (%d)", kind, len(rs)), 3))
		for _, e := range rs {
			body.WriteString(paragraph("  • "+e.Value, false))
		}
	}
	if !wroteAny {
		body.WriteString(paragraph("No entities.", true))
	}

	// Runs.
	body.WriteString(heading("Runs", 2))
	if len(b.Runs) == 0 {
		body.WriteString(paragraph("No runs.", true))
	} else {
		header := [][3]string{{"Phase", "Status", "Label"}}
		rows := make([][3]string, 0, len(b.Runs)+1)
		rows = append(rows, header[0])
		for _, r := range b.Runs {
			rows = append(rows, [3]string{r.Phase, r.Status, r.Label})
		}
		body.WriteString(threeColTable(rows))
	}

	body.WriteString(`</w:body></w:document>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string]string{
		"[Content_Types].xml": contentTypesXML,
		"_rels/.rels":         relsXML,
		"word/document.xml":   body.String(),
	}
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, fmt.Errorf("docx zip create %s: %w", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("docx zip write %s: %w", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("docx zip close: %w", err)
	}
	return buf.Bytes(), nil
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

// heading emits an OOXML paragraph with a heading-level style. Level
// 1-3 cover the section depths the report uses; out-of-range collapses
// to level 3 to avoid emitting an invalid style id.
func heading(text string, level int) string {
	if level < 1 {
		level = 1
	}
	if level > 3 {
		level = 3
	}
	// Approximate point sizes: H1 28, H2 18, H3 14 (half-points: 56/36/28).
	sz := []int{56, 36, 28}[level-1]
	return fmt.Sprintf(
		`<w:p><w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="%d"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		sz, escapeXML(text),
	)
}

func paragraph(text string, italic bool) string {
	rpr := ""
	if italic {
		rpr = `<w:rPr><w:i/></w:rPr>`
	}
	return fmt.Sprintf(
		`<w:p><w:r>%s<w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		rpr, escapeXML(text),
	)
}

func twoColTable(rows [][2]string) string {
	var sb strings.Builder
	sb.WriteString(`<w:tbl>`)
	sb.WriteString(tableProps())
	for _, r := range rows {
		sb.WriteString(`<w:tr>`)
		sb.WriteString(tableCell(r[0], 2000))
		sb.WriteString(tableCell(r[1], 7000))
		sb.WriteString(`</w:tr>`)
	}
	sb.WriteString(`</w:tbl>`)
	return sb.String()
}

func threeColTable(rows [][3]string) string {
	var sb strings.Builder
	sb.WriteString(`<w:tbl>`)
	sb.WriteString(tableProps())
	for _, r := range rows {
		sb.WriteString(`<w:tr>`)
		sb.WriteString(tableCell(r[0], 2500))
		sb.WriteString(tableCell(r[1], 1800))
		sb.WriteString(tableCell(r[2], 4700))
		sb.WriteString(`</w:tr>`)
	}
	sb.WriteString(`</w:tbl>`)
	return sb.String()
}

func tableProps() string {
	return `<w:tblPr><w:tblW w:w="0" w:type="auto"/><w:tblBorders><w:top w:val="single" w:sz="4"/><w:bottom w:val="single" w:sz="4"/><w:left w:val="single" w:sz="4"/><w:right w:val="single" w:sz="4"/><w:insideH w:val="single" w:sz="4"/><w:insideV w:val="single" w:sz="4"/></w:tblBorders></w:tblPr>`
}

func tableCell(text string, twipsWidth int) string {
	return fmt.Sprintf(
		`<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/></w:tcPr><w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p></w:tc>`,
		twipsWidth, escapeXML(text),
	)
}

// escapeXML uses encoding/xml's escaping so embedded angle brackets in
// finding titles / values don't break the document.
func escapeXML(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}
