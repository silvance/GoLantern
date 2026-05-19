package report

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/go-pdf/fpdf"
)

// RenderPDF writes a structured PDF of the bundle. Output mirrors the
// HTML renderer's sections (summary / findings / entities / runs) but
// laid out with fpdf primitives rather than browser-rendered HTML, so
// the rendering needs no Chromium / external service. Pure Go.
//
// Layout choices favor reviewability over polish: A4 portrait, 10pt
// sans-serif body, single-column. Tables use fpdf's built-in CellFormat
// with explicit column widths so wide content wraps at row boundaries
// rather than overflowing the page.
func RenderPDF(b *Bundle) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(15, 15, 15)
	pdf.SetAutoPageBreak(true, 15)
	pdf.AddPage()

	// Title.
	pdf.SetFont("Helvetica", "B", 18)
	pdf.MultiCell(0, 9, b.Project.Name, "", "L", false)
	pdf.Ln(2)

	// Meta line.
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(85, 85, 85)
	meta := []string{
		"Mode: " + b.Project.Mode,
		"Default scope: " + b.Project.DefaultScope,
		"Template: " + b.Project.ReportTemplate,
	}
	if b.Project.Organization != "" {
		meta = append([]string{b.Project.Organization}, meta...)
	}
	pdf.MultiCell(0, 5, strings.Join(meta, "  ·  "), "", "L", false)
	pdf.SetTextColor(0, 0, 0)
	if b.Project.Description != "" {
		pdf.Ln(1)
		pdf.SetFont("Helvetica", "", 10)
		pdf.MultiCell(0, 5, b.Project.Description, "", "L", false)
	}
	pdf.Ln(4)

	// Summary table.
	sectionHeading(pdf, "Summary")
	pdf.SetFont("Helvetica", "", 10)
	for _, row := range [][2]string{
		{"Entities", itoa(b.Summary.EntitiesTotal)},
		{"Findings", itoa(b.Summary.FindingsTotal)},
		{"Runs", itoa(b.Summary.RunsTotal)},
	} {
		pdf.CellFormat(40, 6, row[0], "B", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, row[1], "B", 1, "L", false, 0, "")
	}
	pdf.Ln(4)

	// Findings.
	sectionHeading(pdf, "Findings")
	if len(b.Findings) == 0 {
		emptyLine(pdf, "No findings.")
	} else {
		// Header row.
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetFillColor(245, 245, 247)
		pdf.CellFormat(22, 6, "Severity", "1", 0, "L", true, 0, "")
		pdf.CellFormat(0, 6, "Title", "1", 0, "L", true, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", 9)
		for _, f := range b.Findings {
			x0, y0 := pdf.GetXY()
			pdf.CellFormat(22, 6, f.Severity, "1", 0, "L", false, 0, "")
			pdf.SetXY(x0+22, y0)
			pdf.MultiCell(0, 6, f.Title, "1", "L", false)
		}
	}
	pdf.Ln(4)

	// Entities by kind.
	sectionHeading(pdf, "Entities")
	keys := sortedKinds(b.EntitiesByKind)
	wroteAny := false
	pdf.SetFont("Helvetica", "", 9)
	for _, kind := range keys {
		rows := b.EntitiesByKind[kind]
		if len(rows) == 0 {
			continue
		}
		wroteAny = true
		pdf.SetFont("Helvetica", "B", 10)
		pdf.MultiCell(0, 6, fmt.Sprintf("%s (%d)", kind, len(rows)), "", "L", false)
		pdf.SetFont("Helvetica", "", 9)
		for _, e := range rows {
			pdf.MultiCell(0, 5, "  • "+e.Value, "", "L", false)
		}
		pdf.Ln(2)
	}
	if !wroteAny {
		emptyLine(pdf, "No entities.")
	}
	pdf.Ln(2)

	// Runs.
	sectionHeading(pdf, "Runs")
	if len(b.Runs) == 0 {
		emptyLine(pdf, "No runs.")
	} else {
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetFillColor(245, 245, 247)
		pdf.CellFormat(40, 6, "Phase", "1", 0, "L", true, 0, "")
		pdf.CellFormat(30, 6, "Status", "1", 0, "L", true, 0, "")
		pdf.CellFormat(0, 6, "Label", "1", 0, "L", true, 0, "")
		pdf.Ln(-1)
		pdf.SetFont("Helvetica", "", 9)
		for _, r := range b.Runs {
			pdf.CellFormat(40, 6, r.Phase, "1", 0, "L", false, 0, "")
			pdf.CellFormat(30, 6, r.Status, "1", 0, "L", false, 0, "")
			pdf.CellFormat(0, 6, r.Label, "1", 0, "L", false, 0, "")
			pdf.Ln(-1)
		}
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("report.RenderPDF: %w", err)
	}
	return buf.Bytes(), nil
}

func sectionHeading(pdf *fpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 12)
	pdf.MultiCell(0, 7, title, "", "L", false)
	pdf.SetDrawColor(220, 220, 220)
	x, y := pdf.GetXY()
	pdf.Line(x, y, x+180, y)
	pdf.Ln(2)
}

func emptyLine(pdf *fpdf.Fpdf, msg string) {
	pdf.SetFont("Helvetica", "I", 10)
	pdf.SetTextColor(120, 120, 120)
	pdf.MultiCell(0, 5, msg, "", "L", false)
	pdf.SetTextColor(0, 0, 0)
}

func sortedKinds(m map[string][]EntityView) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
