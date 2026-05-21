// Package cloudbucket wraps s3scanner for open S3 / GCS / Azure
// bucket discovery. Real engagements consistently surface open
// public buckets attached to a brand or asset, and there was no
// previous collector in this surface area.
//
// Two-stage scan: the operator supplies bucket-name candidates
// (organization name, product slugs, common prefixes) or seeds
// from Organization/Domain entities. s3scanner probes each name
// across the configured providers (default: aws, gcp, azure) and
// reports existence + ACL status. Open buckets land as findings;
// existing-but-private buckets land as CLOUD_BUCKET entities for
// later review.
package cloudbucket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	Name           = "cloud_bucket"
	defaultBinary  = "s3scanner"
	defaultTimeout = 600 * time.Second
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
		Description:    "Discover open S3 / GCS / Azure buckets associated with the organization. Reads-only probes; no upload/write attempts.",
		Consumes:       []entity.Kind{entity.KindOrganization, entity.KindDomain},
		Produces:       []entity.Kind{entity.KindCloudBucket},
		SourceCategory: finding.SourcePublicOSINT,
		Binary:         "s3scanner",
		InstallHint:    "go install github.com/sa7mon/s3scanner@latest",
		Parameters: []scan.ParameterSpec{
			{Name: "candidates", Type: "string_list", Placeholder: "acme, acme-prod, acme-backup",
				Description: "Bucket-name candidates to probe. Empty derives candidates from ORGANIZATION + DOMAIN entities."},
			{Name: "providers", Type: "string", Default: "aws",
				Description: "Comma-separated provider list. s3scanner supports 'aws'; extend by chaining other tools."},
			{Name: "binary", Type: "string", Default: "s3scanner"},
			{Name: "timeout_seconds", Type: "float", Default: 600.0},
		},
	}
}

// s3scannerJSON captures the JSON-lines output shape of s3scanner v3.
// Fields are deliberately liberal — older versions used slightly
// different keys and we accept either.
type s3scannerJSON struct {
	Name        string `json:"name"`
	Bucket      string `json:"bucket"`
	Region      string `json:"region"`
	Exists      bool   `json:"exists"`
	BucketExist int    `json:"bucket_exists"` // alternate v2 shape: 1/0
	Provider    string `json:"provider"`
	Permissions struct {
		AuthUsers struct {
			Read      bool `json:"read"`
			Write     bool `json:"write"`
			ReadACP   bool `json:"read_acp"`
			WriteACP  bool `json:"write_acp"`
			FullCtrl  bool `json:"full_control"`
		} `json:"auth_users"`
		AllUsers struct {
			Read      bool `json:"read"`
			Write     bool `json:"write"`
			ReadACP   bool `json:"read_acp"`
			WriteACP  bool `json:"write_acp"`
			FullCtrl  bool `json:"full_control"`
		} `json:"all_users"`
	} `json:"permissions"`
	ObjectsEnumerated bool `json:"objects_enumerated"`
	NumObjects        int  `json:"num_objects"`
}

func (r s3scannerJSON) BucketName() string {
	if r.Name != "" {
		return r.Name
	}
	return r.Bucket
}

func (r s3scannerJSON) IsExists() bool {
	if r.Exists {
		return true
	}
	return r.BucketExist == 1
}

func (c *collector) Run(ctx context.Context, cctx scan.Context) error {
	binary := strings.TrimSpace(toString(cctx.Parameters()["binary"]))
	if binary == "" {
		binary = defaultBinary
	}
	timeout := parseTimeout(cctx.Parameters()["timeout_seconds"])

	candidates, err := c.resolveCandidates(cctx)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return errors.New("cloud_bucket: no candidate names; pass parameters[\"candidates\"] or seed ORGANIZATION/DOMAIN entities")
	}

	args := []string{"scan", "--bucket-list", "-", "--json"}

	stdin := []byte(strings.Join(candidates, "\n") + "\n")

	run := c.runner
	if run == nil {
		run = subprocess.Run
	}
	result, err := run(ctx, subprocess.Spec{
		Binary:         binary,
		Args:           args,
		Stdin:          stdin,
		Timeout:        timeout,
		AllowPartialRC: []int{1},
	})
	if err != nil {
		return fmt.Errorf("cloud_bucket: %w", err)
	}

	discovered := 0
	openBuckets := 0
	for _, raw := range strings.Split(string(result.Stdout), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		var rec s3scannerJSON
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		bucketName := rec.BucketName()
		if bucketName == "" {
			continue
		}
		if !rec.IsExists() {
			continue
		}
		provider := rec.Provider
		if provider == "" {
			provider = "aws"
		}
		bucketURI := fmt.Sprintf("s3://%s", bucketName)
		if provider == "gcp" {
			bucketURI = fmt.Sprintf("gs://%s", bucketName)
		} else if provider == "azure" {
			bucketURI = fmt.Sprintf("azure://%s", bucketName)
		}
		attrs := map[string]any{
			"name":               bucketName,
			"provider":           provider,
			"region":             rec.Region,
			"objects_enumerated": rec.ObjectsEnumerated,
			"num_objects":        rec.NumObjects,
		}
		if _, err := cctx.EmitEntity(fact.EntityFact{
			Kind:           entity.KindCloudBucket,
			Value:          bucketURI,
			Attributes:     attrs,
			Confidence:     finding.ConfidenceHigh,
			SourceCategory: finding.SourcePublicOSINT,
		}); err != nil {
			return err
		}
		discovered++

		// Findings: any AllUsers permission is a public exposure.
		// AuthUsers permissions (any AWS-authenticated principal) are
		// nearly as bad — flag at a lower severity.
		findingsForBucket := emitBucketFindings(cctx, bucketURI, rec)
		openBuckets += findingsForBucket
	}
	return cctx.EmitEvidence(fact.EvidenceFact{
		SourceTool:     Name,
		SourceCategory: finding.SourcePublicOSINT,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"candidates":          len(candidates),
			"buckets_discovered":  discovered,
			"open_or_misconfig":   openBuckets,
		},
	})
}

func emitBucketFindings(cctx scan.Context, bucketURI string, rec s3scannerJSON) int {
	emitted := 0
	type permGroup struct {
		label string
		sev   finding.Severity
		grp   struct {
			Read     bool `json:"read"`
			Write    bool `json:"write"`
			ReadACP  bool `json:"read_acp"`
			WriteACP bool `json:"write_acp"`
			FullCtrl bool `json:"full_control"`
		}
	}
	all := permGroup{label: "AllUsers (public)", sev: finding.SeverityCritical}
	all.grp.Read = rec.Permissions.AllUsers.Read
	all.grp.Write = rec.Permissions.AllUsers.Write
	all.grp.ReadACP = rec.Permissions.AllUsers.ReadACP
	all.grp.WriteACP = rec.Permissions.AllUsers.WriteACP
	all.grp.FullCtrl = rec.Permissions.AllUsers.FullCtrl

	auth := permGroup{label: "AuthenticatedUsers (any AWS account)", sev: finding.SeverityHigh}
	auth.grp.Read = rec.Permissions.AuthUsers.Read
	auth.grp.Write = rec.Permissions.AuthUsers.Write
	auth.grp.ReadACP = rec.Permissions.AuthUsers.ReadACP
	auth.grp.WriteACP = rec.Permissions.AuthUsers.WriteACP
	auth.grp.FullCtrl = rec.Permissions.AuthUsers.FullCtrl

	for _, pg := range []permGroup{all, auth} {
		var perms []string
		if pg.grp.Read {
			perms = append(perms, "READ")
		}
		if pg.grp.Write {
			perms = append(perms, "WRITE")
		}
		if pg.grp.ReadACP {
			perms = append(perms, "READ_ACP")
		}
		if pg.grp.WriteACP {
			perms = append(perms, "WRITE_ACP")
		}
		if pg.grp.FullCtrl {
			perms = append(perms, "FULL_CONTROL")
		}
		if len(perms) == 0 {
			continue
		}
		// WRITE on a public bucket is critical regardless of group.
		sev := pg.sev
		if pg.grp.Write || pg.grp.WriteACP || pg.grp.FullCtrl {
			sev = finding.SeverityCritical
		}
		_, _ = cctx.EmitFinding(fact.FindingFact{
			Title:       fmt.Sprintf("Open cloud bucket — %s on %s", strings.Join(perms, ","), bucketURI),
			Severity:    sev,
			Confidence:  finding.ConfidenceHigh,
			Category:    "cloud.exposure",
			Description: fmt.Sprintf("Bucket %s grants %s to %s.", bucketURI, strings.Join(perms, ", "), pg.label),
			Attributes: map[string]any{
				"bucket":      bucketURI,
				"principal":   pg.label,
				"permissions": perms,
				"provider":    rec.Provider,
				"region":      rec.Region,
			},
			SupportingEntities: []fact.EntityRef{{Kind: entity.KindCloudBucket, Value: bucketURI}},
		})
		emitted++
	}
	return emitted
}

func (c *collector) resolveCandidates(cctx scan.Context) ([]string, error) {
	explicit := parseStringList(cctx.Parameters()["candidates"])
	if len(explicit) > 0 {
		out := make([]string, 0, len(explicit))
		seen := map[string]struct{}{}
		for _, t := range explicit {
			if t = sanitizeName(t); t != "" {
				if _, dup := seen[t]; dup {
					continue
				}
				seen[t] = struct{}{}
				out = append(out, t)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// Seed from organization + domain entities.
	seen := map[string]struct{}{}
	var out []string
	addCandidate := func(s string) {
		s = sanitizeName(s)
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	orgs, _ := cctx.ListEntityValues(entity.KindOrganization)
	for _, o := range orgs {
		addCandidate(o)
		addCandidate(o + "-prod")
		addCandidate(o + "-backup")
		addCandidate(o + "-dev")
		addCandidate(o + "-data")
	}
	domains, _ := cctx.ListEntityValues(entity.KindDomain)
	for _, d := range domains {
		// Strip TLD: "example.com" -> "example".
		base := d
		if i := strings.IndexByte(d, '.'); i > 0 {
			base = d[:i]
		}
		addCandidate(base)
		addCandidate(base + "-prod")
		addCandidate(base + "-backup")
		addCandidate(base + "-assets")
	}
	return out, nil
}

// sanitizeName lowercases and strips characters that S3 bucket names
// forbid. AWS bucket names are 3-63 chars, lowercase letters, digits,
// dots, hyphens. We're conservative: drop characters that aren't
// alphanumeric or hyphen.
func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune(r)
		case r == ' ' || r == '_' || r == '.':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) < 3 || len(out) > 63 {
		return ""
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
