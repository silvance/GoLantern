package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
)

// RenderCSV writes a multi-section CSV: a summary block, then one
// section per kind of row (findings, entities, runs). Sections are
// separated by blank lines so a human eyeballing the export can tell
// them apart and a spreadsheet importer treats each as its own range.
//
// Mirrors the spirit of lantern.reports.csv_renderer (Python's
// renderer emits the same three sections in the same order). The
// exact column set is a deliberate subset — the bundle's full JSON
// shape (e.g. evidence payloads) doesn't fit comfortably into CSV.
func RenderCSV(b *Bundle) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Section 1: project summary.
	rows := [][]string{
		{"section", "project"},
		{"id", b.Project.ID},
		{"name", b.Project.Name},
		{"organization", b.Project.Organization},
		{"mode", b.Project.Mode},
		{"default_scope", b.Project.DefaultScope},
		{"entities_total", strconv.Itoa(b.Summary.EntitiesTotal)},
		{"findings_total", strconv.Itoa(b.Summary.FindingsTotal)},
		{"runs_total", strconv.Itoa(b.Summary.RunsTotal)},
		{},
	}
	if err := w.WriteAll(rows); err != nil {
		return nil, fmt.Errorf("report.RenderCSV: %w", err)
	}

	// Section 2: findings.
	if err := w.Write([]string{"section", "findings"}); err != nil {
		return nil, err
	}
	if err := w.Write([]string{"id", "severity", "confidence", "category", "title", "evidence_count"}); err != nil {
		return nil, err
	}
	for _, f := range b.Findings {
		if err := w.Write([]string{
			f.ID, f.Severity, f.Confidence, f.Category, f.Title,
			strconv.Itoa(len(f.Evidence)),
		}); err != nil {
			return nil, err
		}
	}
	_ = w.Write(nil)

	// Section 3: entities.
	if err := w.Write([]string{"section", "entities"}); err != nil {
		return nil, err
	}
	if err := w.Write([]string{"kind", "value", "id"}); err != nil {
		return nil, err
	}
	// Iterate kinds in canonical order so the output is deterministic.
	for _, kind := range allKindStrings() {
		for _, e := range b.EntitiesByKind[kind] {
			if err := w.Write([]string{e.Kind, e.Value, e.ID}); err != nil {
				return nil, err
			}
		}
	}
	_ = w.Write(nil)

	// Section 4: runs.
	if err := w.Write([]string{"section", "runs"}); err != nil {
		return nil, err
	}
	if err := w.Write([]string{"id", "phase", "status", "label"}); err != nil {
		return nil, err
	}
	for _, r := range b.Runs {
		if err := w.Write([]string{r.ID, r.Phase, r.Status, r.Label}); err != nil {
			return nil, err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, fmt.Errorf("report.RenderCSV: %w", err)
	}
	return buf.Bytes(), nil
}
