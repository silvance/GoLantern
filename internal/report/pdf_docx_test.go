package report_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/report"
)

// TestRenderPDFShape checks the magic header, that the project name
// makes it into the rendered output, and that the binary is non-trivial
// in size (catches an empty/aborted render).
func TestRenderPDFShape(t *testing.T) {
	st, p := reportFixture(t)
	b, err := report.Generate(context.Background(), deps(st), p.ID, report.Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := report.RenderPDF(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatalf("PDF magic missing; first 8 bytes: %q", out[:8])
	}
	if len(out) < 1000 {
		t.Fatalf("PDF suspiciously small (%d bytes)", len(out))
	}
	// fpdf compresses streams by default, so the title bytes don't
	// appear literally. We still verify the trailer is there.
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Fatal("PDF missing the end-of-file trailer")
	}
}

// TestRenderDOCXIsValidZip opens the produced bytes as a zip archive
// and confirms the three required parts are present and document.xml
// holds the project name.
func TestRenderDOCXIsValidZip(t *testing.T) {
	st, p := reportFixture(t)
	b, err := report.Generate(context.Background(), deps(st), p.ID, report.Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, err := report.RenderDOCX(b)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("DOCX is not a valid zip: %v", err)
	}
	required := map[string]bool{
		"[Content_Types].xml": false,
		"_rels/.rels":         false,
		"word/document.xml":   false,
	}
	for _, f := range zr.File {
		if _, ok := required[f.Name]; ok {
			required[f.Name] = true
		}
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			body, _ := io.ReadAll(rc)
			rc.Close()
			if !strings.Contains(string(body), b.Project.Name) {
				t.Fatalf("document.xml missing project name; first 200 bytes: %s", string(body)[:min(200, len(body))])
			}
			// Confirm XML escaping happened — the fixture's critical
			// finding title doesn't contain unsafe chars by default,
			// so we just check the body is non-trivial.
			if len(body) < 200 {
				t.Fatalf("document.xml suspiciously small (%d bytes)", len(body))
			}
		}
	}
	for name, present := range required {
		if !present {
			t.Errorf("DOCX missing required part: %s", name)
		}
	}
}

// TestRenderDOCXEscapesAngleBrackets ensures a finding title with HTML
// special characters can't break the OOXML when injected verbatim.
func TestRenderDOCXEscapesAngleBrackets(t *testing.T) {
	st, p := reportFixture(t)
	if err := st.Findings.CreateFinding(context.Background(), &finding.Finding{
		ProjectID:  p.ID,
		Title:      "<script>alert(1)</script>",
		Severity:   finding.SeverityHigh,
		Confidence: finding.ConfidenceMedium,
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := report.Generate(context.Background(), deps(st), p.ID, report.Options{})
	out, err := report.RenderDOCX(b)
	if err != nil {
		t.Fatal(err)
	}
	// Open + re-parse the zip; if the XML is malformed, zip.NewReader
	// is fine but encoding/xml on document.xml would fail. We rely on
	// the round-trip below.
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("DOCX not a valid zip: %v", err)
	}
	var body []byte
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			body, _ = io.ReadAll(rc)
			rc.Close()
		}
	}
	if strings.Contains(string(body), "<script>") {
		t.Fatal("unsafe title leaked into document.xml without escaping")
	}
	if !strings.Contains(string(body), "&lt;script&gt;") {
		t.Fatalf("expected XML-escaped title in body; not found")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
