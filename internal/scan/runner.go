package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/fact"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
)

// Runner orchestrates a single tool execution: scope precheck, audit
// emission, fact persistence, error mapping. Mirrors Python's
// CollectorRunner.execute.
//
// Construct with NewRunner. A Runner is bound to one scope policy; if
// the policy changes between runs (e.g. operator added a rule mid-run)
// build a fresh Runner. The Python version takes the same approach via
// load_scope_policy at job-dispatch time.
type Runner struct {
	deps   Deps
	logger *slog.Logger
	audits audit.Repository // optional
}

func NewRunner(deps Deps, logger *slog.Logger, audits audit.Repository) (*Runner, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{deps: deps, logger: logger, audits: audits}, nil
}

// Execute runs collector under runID for projectID with the given
// parameters. Returns the resulting *run.ToolExecution (already
// persisted). Errors only escape for infra failures (DB unreachable);
// collector-level errors are recorded on the ToolExecution row and
// the returned tx.Status carries the outcome.
//
// The scope precheck is the "allows_at_default" reachability check
// from Python: if no rule and no default can ever authorize the
// collector's RequiredScope, we skip the run with
// SKIPPED_OUT_OF_SCOPE. Per-target gates happen inside the collector
// via cctx.IsInScope.
func (r *Runner) Execute(
	ctx context.Context,
	projectID, runID string,
	collector Collector,
	parameters map[string]any,
) (*run.ToolExecution, error) {
	meta := collector.Metadata()
	now := time.Now().UTC()

	tx := &run.ToolExecution{
		RunID:      runID,
		Tool:       meta.Name,
		Parameters: redactParameters(parameters),
		Status:     run.ToolStatusPending,
	}
	if err := r.deps.Runs.SaveToolExecution(ctx, tx); err != nil {
		return nil, fmt.Errorf("create tool execution: %w", err)
	}

	// Reachability check. Mirrors Python's allows_at_default.
	if !r.deps.Scope.AllowsAtDefault(meta.RequiredScope) {
		tx.Status = run.ToolStatusSkippedOutOfScope
		tx.FinishedAt = &now
		tx.ErrorSummary = fmt.Sprintf(
			"Tool %q requires %q scope, but the project has no rule "+
				"(and no default_scope) that authorizes that level. "+
				"Add a scope rule whose kind is %q or higher, or set the "+
				"project default_scope to %q.",
			meta.Name, meta.RequiredScope, meta.RequiredScope, meta.RequiredScope,
		)
		_ = r.deps.Runs.SaveToolExecution(ctx, tx)
		r.audit(ctx, projectID, "collector.skipped_out_of_scope", meta.Name, map[string]any{
			"required_scope": string(meta.RequiredScope),
		})
		return tx, nil
	}

	tx.Status = run.ToolStatusRunning
	tx.StartedAt = &now
	_ = r.deps.Runs.SaveToolExecution(ctx, tx)

	r.audit(ctx, projectID, "collector.start", meta.Name, map[string]any{
		"parameters": parameters,
		"phase":      string(meta.Phase),
	})

	// Build the persisting context that the collector emits into.
	pctx := &persistingContext{
		runner:      r,
		baseCtx:     ctx,
		projectID:   projectID,
		runID:       runID,
		tx:          tx,
		meta:        meta,
		parameters:  parameters,
		entityCache: make(map[string]string),
		findCache:   make(map[string]string),
	}

	// Run the collector. We recover from panics so a broken collector
	// can't crash the worker; the recovery becomes a FAILED row with
	// the stack in error_debug.
	err := r.runWithRecovery(ctx, collector, pctx)
	switch {
	case err == nil:
		tx.Status = run.ToolStatusCompleted
	case errors.Is(err, scope.ErrOutOfScope):
		tx.Status = run.ToolStatusSkippedOutOfScope
		tx.ErrorSummary = err.Error()
	default:
		tx.Status = run.ToolStatusFailed
		tx.ErrorSummary = fmt.Sprintf("%T: %v", err, err)
		// Stack lives only on the row, gated behind a debug flag in
		// the API serializer (not yet wired). Two-tier error storage
		// matches Python.
		if pctx.recoveryStack != "" {
			tx.ErrorDebug = pctx.recoveryStack
		}
	}

	// Zero-emission diagnostic: COMPLETED with nothing produced AND
	// every target was rejected by scope. The most likely cause is a
	// scope rule that doesn't reach the operator's targets; surface
	// it on the row so the SPA shows it next to the empty result.
	r.applyZeroEmissionDiagnostic(tx, meta, pctx)

	finishedAt := time.Now().UTC()
	tx.FinishedAt = &finishedAt
	tx.Result = map[string]any{
		"entities_emitted": tx.EntitiesEmitted,
		"evidence_emitted": tx.EvidenceEmitted,
		"findings_emitted": tx.FindingsEmitted,
	}
	if err := r.deps.Runs.SaveToolExecution(ctx, tx); err != nil {
		return tx, fmt.Errorf("persist final tool execution: %w", err)
	}

	r.audit(ctx, projectID, "collector.finish", meta.Name, map[string]any{
		"status":           string(tx.Status),
		"entities_emitted": tx.EntitiesEmitted,
		"evidence_emitted": tx.EvidenceEmitted,
		"findings_emitted": tx.FindingsEmitted,
	})
	return tx, nil
}

// runWithRecovery runs the collector, converting panics into errors so
// a broken collector can't crash the worker. Mirrors Python's
// catch-everything block.
func (r *Runner) runWithRecovery(ctx context.Context, c Collector, pctx *persistingContext) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			pctx.recoveryStack = string(debug.Stack())
			err = fmt.Errorf("collector panic: %v", rec)
		}
	}()
	return c.Run(ctx, pctx)
}

func (r *Runner) applyZeroEmissionDiagnostic(
	tx *run.ToolExecution, meta Meta, pctx *persistingContext,
) {
	if tx.Status != run.ToolStatusCompleted {
		return
	}
	if tx.EntitiesEmitted > 0 || tx.FindingsEmitted > 0 || tx.EvidenceEmitted > 0 {
		return
	}
	if tx.ErrorSummary != "" {
		return
	}
	if pctx.scopeAccepts != 0 || len(pctx.scopeRejections) == 0 {
		return
	}
	const sampleN = 3
	rejects := pctx.scopeRejections
	sample := strings.Join(rejects[:min(sampleN, len(rejects))], ", ")
	more := ""
	if len(rejects) > sampleN {
		more = fmt.Sprintf(" (+%d more)", len(rejects)-sampleN)
	}
	tx.ErrorSummary = fmt.Sprintf(
		"All %d probed targets were out of scope: %s%s. "+
			"The collector requires %s authorization; add or widen a scope rule, "+
			"or raise the project default_scope.",
		len(rejects), sample, more, meta.RequiredScope,
	)
}

func (r *Runner) audit(ctx context.Context, projectID, action, target string, detail map[string]any) {
	if r.audits == nil {
		return
	}
	if err := r.audits.Record(ctx, &audit.LogEntry{
		ProjectID: projectID,
		Action:    action,
		Target:    target,
		Detail:    detail,
	}); err != nil {
		r.logger.WarnContext(ctx, "audit failed in runner",
			slog.String("action", action),
			slog.String("target", target),
			slog.Any("err", err))
	}
}

// redactParameters replaces secret-shaped values with "***" so the
// persisted ToolExecution.parameters doesn't carry api_key / token /
// password into the DB (and thus into reports and API responses).
// Mirrors lantern.security.redact_parameters.
//
// We deliberately match by substring so "auth_token", "api_key_v2",
// "github_password" all redact. False positives (e.g. a param literally
// named "key" that holds a column name) are accepted as the cost of
// being conservative.
func redactParameters(in map[string]any) map[string]any {
	if len(in) == 0 {
		return map[string]any{}
	}
	const placeholder = "***"
	secretSubstrings := []string{"password", "token", "secret", "api_key", "apikey"}
	out := make(map[string]any, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		redact := false
		for _, s := range secretSubstrings {
			if strings.Contains(lk, s) {
				redact = true
				break
			}
		}
		if redact {
			out[k] = placeholder
		} else {
			out[k] = v
		}
	}
	return out
}

// ----- persistingContext -----------------------------------------------

// persistingContext is the production Context: every Emit goes
// straight to the repositories. Tests can either pass a recording
// Context (no DB) or build one of these around an in-memory store.
type persistingContext struct {
	runner     *Runner
	baseCtx    context.Context
	projectID  string
	runID      string
	tx         *run.ToolExecution
	meta       Meta
	parameters map[string]any

	// Per-execution caches.
	entityCache map[string]string // "kind|value" -> entityID
	findCache   map[string]string // title -> findingID

	// Scope-filter telemetry. Drives the zero-emission diagnostic.
	scopeAccepts    int
	scopeRejections []string

	// Captured if the collector panicked.
	recoveryStack string
}

func (p *persistingContext) ProjectID() string          { return p.projectID }
func (p *persistingContext) ToolExecutionID() string    { return p.tx.ID }
func (p *persistingContext) Parameters() map[string]any { return p.parameters }

func (p *persistingContext) IsInScope(target string) bool {
	allowed := p.runner.deps.Scope.IsAllowed(target, p.meta.RequiredScope)
	if allowed {
		p.scopeAccepts++
	} else {
		p.scopeRejections = append(p.scopeRejections, target)
	}
	return allowed
}

func (p *persistingContext) ListEntityValues(kind entity.Kind) ([]string, error) {
	return p.runner.deps.Entities.ListValuesByKind(p.baseCtx, p.projectID, kind)
}

func (p *persistingContext) StoreArtifact(_ []byte, _, _ string) (string, error) {
	return "", ErrStoreArtifactNotImplemented
}

func (p *persistingContext) EmitEntity(f fact.EntityFact) (string, error) {
	id, err := p.upsertEntity(f.Kind, f.Value, f.Attributes)
	if err != nil {
		return "", err
	}
	src := f.SourceCategory
	if src == "" {
		src = p.defaultSourceCategory()
	}
	conf := f.Confidence
	if conf == "" {
		conf = finding.ConfidenceMedium
	}
	if err := p.runner.deps.Findings.CreateEvidence(p.baseCtx, &finding.Evidence{
		ProjectID:       p.projectID,
		ToolExecutionID: p.tx.ID,
		EntityID:        id,
		SourceTool:      p.meta.Name,
		SourceCategory:  src,
		Confidence:      conf,
		Payload: map[string]any{
			"value":      f.Value,
			"attributes": f.Attributes,
		},
		Notes: f.Notes,
	}); err != nil {
		return "", fmt.Errorf("emit entity evidence: %w", err)
	}
	p.tx.EntitiesEmitted++
	p.tx.EvidenceEmitted++
	return id, nil
}

func (p *persistingContext) EmitRelation(f fact.RelationFact) error {
	// Relation persistence (entity_relations table) is not yet
	// ported. Phase 4 scaffold accepts the call and counts the
	// endpoint entities to keep them deduped; the actual edge will
	// land when the entity_relations repository ships.
	if _, err := p.upsertEntity(f.Src.Kind, f.Src.Value, nil); err != nil {
		return err
	}
	if _, err := p.upsertEntity(f.Dst.Kind, f.Dst.Value, nil); err != nil {
		return err
	}
	return nil
}

func (p *persistingContext) EmitEvidence(f fact.EvidenceFact) error {
	var entityID, findingID string
	if f.EntityValue != "" && f.EntityKind != "" {
		id, err := p.upsertEntity(f.EntityKind, f.EntityValue, nil)
		if err != nil {
			return err
		}
		entityID = id
	}
	if f.FindingTitle != "" {
		if id, ok := p.findCache[f.FindingTitle]; ok {
			findingID = id
		}
	}
	sourceTool := f.SourceTool
	if sourceTool == "" {
		sourceTool = p.meta.Name
	}
	if err := p.runner.deps.Findings.CreateEvidence(p.baseCtx, &finding.Evidence{
		ProjectID:       p.projectID,
		ToolExecutionID: p.tx.ID,
		EntityID:        entityID,
		FindingID:       findingID,
		SourceTool:      sourceTool,
		SourceCategory:  f.SourceCategory,
		Confidence:      f.Confidence,
		Payload:         f.Payload,
		ArtifactURI:     f.ArtifactURI,
		Notes:           f.Notes,
	}); err != nil {
		return err
	}
	p.tx.EvidenceEmitted++
	return nil
}

func (p *persistingContext) EmitFinding(f fact.FindingFact) (string, error) {
	fObj := &finding.Finding{
		ProjectID:      p.projectID,
		Title:          f.Title,
		Severity:       f.Severity,
		Confidence:     f.Confidence,
		Description:    f.Description,
		Recommendation: f.Recommendation,
		Category:       f.Category,
		Attributes:     f.Attributes,
	}
	if err := p.runner.deps.Findings.CreateFinding(p.baseCtx, fObj); err != nil {
		return "", err
	}
	p.findCache[f.Title] = fObj.ID
	for _, ref := range f.SupportingEntities {
		eid, err := p.upsertEntity(ref.Kind, ref.Value, nil)
		if err != nil {
			return fObj.ID, err
		}
		if err := p.runner.deps.Findings.CreateEvidence(p.baseCtx, &finding.Evidence{
			ProjectID:       p.projectID,
			ToolExecutionID: p.tx.ID,
			EntityID:        eid,
			FindingID:       fObj.ID,
			SourceTool:      p.meta.Name,
			SourceCategory:  p.defaultSourceCategory(),
			Confidence:      f.Confidence,
			Payload:         map[string]any{"reason": "supporting_entity"},
		}); err != nil {
			return fObj.ID, err
		}
		p.tx.EvidenceEmitted++
	}
	p.tx.FindingsEmitted++
	return fObj.ID, nil
}

func (p *persistingContext) upsertEntity(kind entity.Kind, value string, attrs map[string]any) (string, error) {
	canonical := entity.Canonicalize(kind, value)
	cacheKey := string(kind) + "|" + canonical
	if id, ok := p.entityCache[cacheKey]; ok {
		if len(attrs) > 0 {
			// The cached entry's attributes still need merging; re-call
			// the repo so the merge happens there.
			if _, err := p.runner.deps.Entities.Upsert(p.baseCtx, p.projectID, kind, canonical, attrs); err != nil {
				return "", err
			}
		}
		return id, nil
	}
	id, err := p.runner.deps.Entities.Upsert(p.baseCtx, p.projectID, kind, canonical, attrs)
	if err != nil {
		return "", err
	}
	p.entityCache[cacheKey] = id
	return id, nil
}

func (p *persistingContext) defaultSourceCategory() finding.SourceCategory {
	if p.meta.SourceCategory != "" {
		return p.meta.SourceCategory
	}
	return finding.SourcePublicOSINT
}

// min is small enough to inline; lift out if Go 1.21+ builtin isn't
// available, but our go.mod is 1.25 so the builtin works.
