// Package exiftool extracts document / image metadata via exiftool
// and turns it into DOCUMENT / PERSON / EMAIL entities. Catches
// authorship leaks, leftover filesystem paths, embedded GPS, and the
// creator-tool string that often gives away the operator's stack.
//
// Ported from lantern/tools/exiftool.py (compact form: the central
// "authors -> PERSON, regex-mined emails -> EMAIL, embedded paths +
// GPS -> evidence" flow is preserved).
package exiftool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/scan"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/subprocess"
	"github.com/silvance/golantern/internal/workflow"
)

const (
	Name           = "exiftool"
	defaultBinary  = "exiftool"
	defaultTimeout = 120 * time.Second
)

var (
	authorKeys = []string{
		"XMP:Creator", "XMP:Author", "PDF:Author", "EXIF:Artist",
		"Composite:Author", "Author",
	}
	creatorToolKeys = []string{
		"XMP:CreatorTool", "PDF:Creator", "PDF:Producer", "Software",
		"Composite:Software", "CreatorTool",
	}
	titleKeys   = []string{"XMP:Title", "PDF:Title", "Title"}
	companyKeys = []string{"XMP:Company", "Company"}
	createKeys  = []string{"PDF:CreateDate", "XMP:CreateDate", "CreateDate"}
	modifyKeys  = []string{"PDF:ModifyDate", "XMP:ModifyDate", "ModifyDate"}

	emailRE = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	// Path-leak regex: Windows-style (C:\Users\foo) and Unix /home/foo.
	pathLeakRE = regexp.MustCompile(
		`(?i)(?:[A-Z]:\\Users\\[A-Za-z0-9_.\- ]+|/home/[a-zA-Z0-9_.\-]+|/Users/[A-Za-z0-9_.\- ]+)`,
	)
)

func New() scan.Collector { return &collector{} }

type runnerFn func(ctx context.Context, spec subprocess.Spec) (subprocess.Result, error)

func newWithRunner(r runnerFn) scan.Collector { return &collector{runner: r} }

type collector struct{ runner runnerFn }

func (collector) Metadata() scan.Meta {
	return scan.Meta{
		Name:           Name,
		Phase:          workflow.PhaseEnrichment,
		RequiredScope:  scope.KindPassive,
		Description:    "Extract document/image metadata via exiftool. Detects authors, embedded paths, GPS, creator tool.",
		Consumes:       []entity.Kind{entity.KindDocument},
		Produces:       []entity.Kind{entity.KindDocument, entity.KindPerson, entity.KindEmail},
		SourceCategory: finding.SourceDocMetadata,
		Binary:         "exiftool",
		InstallHint:    "apt install libimage-exiftool-perl (Debian/Ubuntu/Kali) | brew install exiftool (macOS)",
		Parameters: []scan.ParameterSpec{
			{Name: "paths", Type: "string_list",
				Description: "Files to scan."},
			{Name: "directory", Type: "string",
				Description: "Directory to scan (non-recursive unless recursive=true)."},
			{Name: "recursive", Type: "bool", Default: false},
			{Name: "binary", Type: "string", Default: "exiftool"},
			{Name: "timeout_seconds", Type: "float", Default: 120.0},
		},
	}
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])

	files, err := expandPaths(cctx.Parameters())
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("exiftool: no files to scan; pass parameters[\"paths\"] or [\"directory\"]")
	}

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	args := append([]string{"-j", "-G", "-charset", "UTF8"}, files...)
	result, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           args,
		Timeout:        timeout,
		AllowPartialRC: []int{1},
	})
	if err != nil {
		return fmt.Errorf("exiftool: %w", err)
	}
	if len(result.Stdout) == 0 {
		return nil
	}
	var raw []map[string]any
	if err := json.Unmarshal(result.Stdout, &raw); err != nil {
		return fmt.Errorf("exiftool: parse JSON: %w", err)
	}

	emailsSeen := map[string]struct{}{}
	peopleSeen := map[string]struct{}{}
	for _, rec := range raw {
		sourceFile, _ := rec["SourceFile"].(string)
		if sourceFile == "" {
			continue
		}
		author := firstNonEmpty(rec, authorKeys)
		creator := firstNonEmpty(rec, creatorToolKeys)
		title := firstNonEmpty(rec, titleKeys)
		company := firstNonEmpty(rec, companyKeys)
		createDate := firstNonEmpty(rec, createKeys)
		modifyDate := firstNonEmpty(rec, modifyKeys)
		gpsLat := firstNonEmpty(rec, []string{"EXIF:GPSLatitude"})
		gpsLon := firstNonEmpty(rec, []string{"EXIF:GPSLongitude"})
		hasGPS := gpsLat != "" || gpsLon != ""

		docValue := filepath.Base(sourceFile)
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindDocument,
			Value:          docValue,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourceDocMetadata,
			Attributes: map[string]any{
				"author":       author,
				"creator_tool": creator,
				"title":        title,
				"company":      company,
				"create_date":  createDate,
				"modify_date":  modifyDate,
				"has_gps":      hasGPS,
				"source_file":  sourceFile,
			},
		}); err != nil {
			return err
		}
		if author != "" {
			if _, dup := peopleSeen[strings.ToLower(author)]; !dup {
				peopleSeen[strings.ToLower(author)] = struct{}{}
				if _, err := cctx.EmitEntity(fact.EntityFact{
					Kind:           entity.KindPerson,
					Value:          author,
					Confidence:     finding.ConfidenceMedium,
					SourceCategory: finding.SourceDocMetadata,
				}); err != nil {
					return err
				}
			}
		}
		// Regex-mine all string values for emails + filesystem paths.
		emails := map[string]struct{}{}
		paths := map[string]struct{}{}
		for _, v := range rec {
			s, ok := v.(string)
			if !ok || s == "" {
				continue
			}
			for _, m := range emailRE.FindAllString(s, -1) {
				emails[strings.ToLower(m)] = struct{}{}
			}
			for _, m := range pathLeakRE.FindAllString(s, -1) {
				paths[m] = struct{}{}
			}
		}
		for email := range emails {
			if _, dup := emailsSeen[email]; dup {
				continue
			}
			emailsSeen[email] = struct{}{}
			if _, err := cctx.EmitEntity(fact.EntityFact{
				Kind:           entity.KindEmail,
				Value:          email,
				Confidence:     finding.ConfidenceLow,
				SourceCategory: finding.SourceDocMetadata,
			}); err != nil {
				return err
			}
		}
		leakedPaths := make([]string, 0, len(paths))
		for p := range paths {
			leakedPaths = append(leakedPaths, p)
		}
		if err := cctx.EmitEvidence(fact.EvidenceFact{
			SourceTool:     Name,
			SourceCategory: finding.SourceDocMetadata,
			Confidence:     finding.ConfidenceHigh,
			Payload: map[string]any{
				"source_file":     sourceFile,
				"author":          author,
				"creator_tool":    creator,
				"title":           title,
				"company":         company,
				"create_date":     createDate,
				"modify_date":     modifyDate,
				"has_gps":         hasGPS,
				"emails_in_meta":  keys(emails),
				"paths_in_meta":   leakedPaths,
			},
			EntityKind:  entity.KindDocument,
			EntityValue: docValue,
		}); err != nil {
			return err
		}
	}
	return nil
}

// expandPaths resolves paths + (optional directory) into a flat,
// deduplicated list of file paths.
func expandPaths(params map[string]any) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	addIfFile := func(p string) {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, raw := range parseStringList(params["paths"]) {
		if p := strings.TrimSpace(raw); p != "" {
			addIfFile(p)
		}
	}
	if dir, _ := params["directory"].(string); strings.TrimSpace(dir) != "" {
		recursive, _ := params["recursive"].(bool)
		dir = strings.TrimSpace(dir)
		if recursive {
			_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				addIfFile(p)
				return nil
			})
		} else {
			entries, err := os.ReadDir(dir)
			if err == nil {
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					addIfFile(filepath.Join(dir, e.Name()))
				}
			}
		}
	}
	return out, nil
}

func firstNonEmpty(obj map[string]any, keys []string) string {
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			switch x := v.(type) {
			case string:
				if s := strings.TrimSpace(x); s != "" {
					return s
				}
			case float64:
				return fmt.Sprintf("%v", x)
			case int:
				return fmt.Sprintf("%d", x)
			}
		}
	}
	return ""
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func parseTimeout(v any) time.Duration {
	switch x := v.(type) {
	case float64:
		if x > 0 {
			return time.Duration(x * float64(time.Second))
		}
	case int:
		if x > 0 {
			return time.Duration(x) * time.Second
		}
	}
	return defaultTimeout
}

func parseStringList(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		out := make([]string, 0, len(s))
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	case string:
		if s == "" {
			return nil
		}
		return []string{s}
	}
	return nil
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
