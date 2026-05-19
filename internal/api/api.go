// Package api wires the domain repositories into HTTP handlers.
//
// Read-only for now (Phase 2 of the migration). Uses stdlib net/http's
// pattern-based routing (Go 1.22+) so we avoid pulling in a router
// dependency just for path templates. Writers go through chi or a
// similar router in a later phase when middleware (auth, audit, request
// IDs) starts to earn its keep.
//
// Wire format is a deliberate subset of Lantern's existing FastAPI
// responses; the SPA can call Go for reads without seeing schema drift.
// We do not attempt to match Pydantic's exact JSON envelope (no
// "items"/"total" wrapping; lists are returned as raw JSON arrays).
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
	"github.com/silvance/golantern/internal/workflow"
)

// Server wires the repositories the handlers need. Construct with
// New, then call Handler() to obtain the *http.ServeMux suitable for
// http.ListenAndServe or httptest.NewServer.
type Server struct {
	Projects project.Repository
	Scopes   scope.Repository
	Runs     run.Repository
	Audit    audit.Repository
	Logger   *slog.Logger
}

// New constructs a Server with sensible defaults. Logger defaults to
// slog.Default when nil.
func New(
	projects project.Repository,
	scopes scope.Repository,
	runs run.Repository,
	audits audit.Repository,
) *Server {
	return &Server{
		Projects: projects,
		Scopes:   scopes,
		Runs:     runs,
		Audit:    audits,
		Logger:   slog.Default(),
	}
}

// Handler returns the routing tree. Re-callable; each call produces a
// fresh mux so tests can mount it independently.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/projects", s.handleListProjects)
	mux.HandleFunc("GET /api/v1/projects/{id}", s.handleGetProject)
	mux.HandleFunc("GET /api/v1/projects/{id}/scope-rules", s.handleListScopeRules)
	mux.HandleFunc("POST /api/v1/projects/{id}/scope-rules", s.handleCreateScopeRule)
	mux.HandleFunc("DELETE /api/v1/projects/{id}/scope-rules/{ruleID}", s.handleDeleteScopeRule)
	mux.HandleFunc("GET /api/v1/projects/{id}/scope/test", s.handleScopeTest)
	mux.HandleFunc("GET /api/v1/projects/{id}/audit-logs", s.handleListAuditLogs)
	mux.HandleFunc("GET /api/v1/projects/{id}/runs", s.handleListRuns)
	mux.HandleFunc("GET /api/v1/runs/{id}", s.handleGetRun)
	mux.HandleFunc("GET /api/v1/runs/{id}/tool-executions", s.handleListToolExecutions)
	return mux
}

// ----- handlers --------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	list, err := s.Projects.List(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]projectDTO, len(list))
	for i, p := range list {
		out[i] = toProjectDTO(p)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.Projects.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toProjectDTO(p))
}

func (s *Server) handleListScopeRules(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	if _, err := s.Projects.Get(r.Context(), pid); err != nil {
		s.writeError(w, r, err)
		return
	}
	rules, err := s.Scopes.ListByProject(r.Context(), pid)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]scopeRuleDTO, len(rules))
	for i, sr := range rules {
		out[i] = scopeRuleDTO{
			ID:        sr.ID,
			ProjectID: sr.ProjectID,
			Pattern:   sr.Rule.Pattern,
			Kind:      string(sr.Rule.Kind),
			Note:      sr.Note,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCreateScopeRule implements POST /api/v1/projects/{id}/scope-rules.
//
// Body: {pattern: string (required), kind?: string, note?: string}.
// When kind is omitted, the project's mode preset chooses one and the
// audit record's detail.kind_source flips from "explicit" to
// "mode_preset" — preserves the Python audit invariant.
//
// 201 + JSON body on success, 400 on bad input, 409 on duplicate
// pattern within the project, 404 if the project is gone.
func (s *Server) handleCreateScopeRule(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	p, err := s.Projects.Get(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	var req createScopeRuleRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	req.Pattern = strings.TrimSpace(req.Pattern)
	if req.Pattern == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("pattern is required"))
		return
	}

	kind := scope.RuleKind(strings.ToLower(strings.TrimSpace(req.Kind)))
	kindSource := "explicit"
	if req.Kind == "" {
		kind = workflow.PresetFor(p.Mode).SuggestedScopeKind
		kindSource = "mode_preset"
	}
	if !kind.Valid() {
		writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("invalid kind %q", req.Kind)))
		return
	}

	sr := &scope.StoredRule{
		ProjectID: projectID,
		Rule:      scope.Rule{Pattern: req.Pattern, Kind: kind},
		Note:      strings.TrimSpace(req.Note),
	}
	if err := s.Scopes.Add(r.Context(), sr); err != nil {
		s.writeError(w, r, err)
		return
	}

	// Audit-log the action. Failures here are logged but do not roll
	// back the create — losing the audit row is worse than losing the
	// rule, but a partial write is even worse, and we have no
	// cross-repo transaction yet. Phase 5 will introduce a Tx scope
	// around handlers that need atomicity.
	auditEntry := &audit.LogEntry{
		ProjectID:           projectID,
		ProjectNameSnapshot: p.Name,
		Action:              audit.ActionScopeRuleCreated,
		Target:              sr.Rule.Pattern,
		Detail: map[string]any{
			"kind":        string(sr.Rule.Kind),
			"note":        sr.Note,
			"kind_source": kindSource,
		},
	}
	if err := s.Audit.Record(r.Context(), auditEntry); err != nil {
		s.Logger.WarnContext(r.Context(), "audit record failed",
			slog.String("action", auditEntry.Action),
			slog.String("rule_id", sr.ID),
			slog.Any("err", err))
	}

	writeJSON(w, http.StatusCreated, scopeRuleDTO{
		ID:        sr.ID,
		ProjectID: sr.ProjectID,
		Pattern:   sr.Rule.Pattern,
		Kind:      string(sr.Rule.Kind),
		Note:      sr.Note,
	})
}

// handleDeleteScopeRule implements DELETE /api/v1/projects/{id}/scope-rules/{ruleID}.
//
// 204 No Content on success, 404 if the project or rule doesn't exist
// or if the rule belongs to a different project. The cross-project
// guard is important: without it a caller who guesses a rule ID could
// delete rules from projects they shouldn't see.
func (s *Server) handleDeleteScopeRule(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	ruleID := r.PathValue("ruleID")

	p, err := s.Projects.Get(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	// Look up the rule via the project's rule list so we both
	// authenticate the cross-project boundary and capture the rule
	// fields for the audit row before deleting it.
	rules, err := s.Scopes.ListByProject(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var target *scope.StoredRule
	for i := range rules {
		if rules[i].ID == ruleID {
			target = &rules[i]
			break
		}
	}
	if target == nil {
		writeJSON(w, http.StatusNotFound, errorBody("scope rule not found"))
		return
	}

	if err := s.Scopes.Delete(r.Context(), ruleID); err != nil {
		s.writeError(w, r, err)
		return
	}

	auditEntry := &audit.LogEntry{
		ProjectID:           projectID,
		ProjectNameSnapshot: p.Name,
		Action:              audit.ActionScopeRuleDeleted,
		Target:              target.Rule.Pattern,
		Detail:              map[string]any{"kind": string(target.Rule.Kind)},
	}
	if err := s.Audit.Record(r.Context(), auditEntry); err != nil {
		s.Logger.WarnContext(r.Context(), "audit record failed",
			slog.String("action", auditEntry.Action),
			slog.String("rule_id", ruleID),
			slog.Any("err", err))
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	if _, err := s.Projects.Get(r.Context(), pid); err != nil {
		s.writeError(w, r, err)
		return
	}
	rows, err := s.Audit.ListByProject(r.Context(), pid)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]auditLogDTO, len(rows))
	for i, e := range rows {
		out[i] = auditLogDTO{
			ID:                  e.ID,
			ProjectID:           e.ProjectID,
			ProjectNameSnapshot: e.ProjectNameSnapshot,
			Actor:               e.Actor,
			Action:              e.Action,
			Target:              e.Target,
			Detail:              e.Detail,
			CreatedAt:           e.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleScopeTest(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("missing 'target' query parameter"))
		return
	}
	pol, err := workflow.LoadPolicy(r.Context(), s.Projects, s.Scopes, r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target":  target,
		"matched": string(pol.MatchedScope(target)),
	})
}

func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	pid := r.PathValue("id")
	if _, err := s.Projects.Get(r.Context(), pid); err != nil {
		s.writeError(w, r, err)
		return
	}
	list, err := s.Runs.ListByProject(r.Context(), pid)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]runDTO, len(list))
	for i, ru := range list {
		out[i] = toRunDTO(ru)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	ru, err := s.Runs.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toRunDTO(ru))
}

func (s *Server) handleListToolExecutions(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("id")
	if _, err := s.Runs.Get(r.Context(), rid); err != nil {
		s.writeError(w, r, err)
		return
	}
	txs, err := s.Runs.ListToolExecutions(r.Context(), rid)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]toolExecDTO, len(txs))
	for i, tx := range txs {
		out[i] = toolExecDTO{
			ID:              tx.ID,
			RunID:           tx.RunID,
			Tool:            tx.Tool,
			Status:          string(tx.Status),
			EntitiesEmitted: tx.EntitiesEmitted,
			EvidenceEmitted: tx.EvidenceEmitted,
			FindingsEmitted: tx.FindingsEmitted,
			ErrorSummary:    tx.ErrorSummary,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ----- helpers ---------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func errorBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}

// writeError maps known sentinel errors to HTTP statuses. Anything we
// don't recognize is logged at warn level and surfaced as 500 with a
// generic message — leaking internal error text to clients is a
// security smell we explicitly avoid (mirrors lantern's two-tier
// error_summary / error_debug split).
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, project.ErrNotFound),
		errors.Is(err, scope.ErrNotFound),
		errors.Is(err, run.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody("not found"))
	case errors.Is(err, project.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
	case errors.Is(err, project.ErrDuplicate),
		errors.Is(err, scope.ErrDuplicate):
		writeJSON(w, http.StatusConflict, errorBody("duplicate"))
	default:
		s.Logger.WarnContext(r.Context(), "api: internal error",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Any("err", err))
		writeJSON(w, http.StatusInternalServerError, errorBody("internal error"))
	}
}

// ----- DTOs ------------------------------------------------------------

// We define DTOs explicitly rather than serializing the domain types
// directly so the wire format and the in-memory model can drift without
// surprising consumers. The Python service exposes the same fields under
// the same names; the SPA needs no changes.

type projectDTO struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Organization string `json:"organization,omitempty"`
	DefaultScope string `json:"default_scope"`
	Mode         string `json:"mode"`
}

func toProjectDTO(p *project.Project) projectDTO {
	return projectDTO{
		ID:           p.ID,
		Name:         p.Name,
		Description:  p.Description,
		Organization: p.Organization,
		DefaultScope: string(p.DefaultScope),
		Mode:         string(p.Mode),
	}
}

type scopeRuleDTO struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Pattern   string `json:"pattern"`
	Kind      string `json:"kind"`
	Note      string `json:"note,omitempty"`
}

type runDTO struct {
	ID           string `json:"id"`
	ProjectID    string `json:"project_id"`
	Phase        string `json:"phase"`
	Status       string `json:"status"`
	Label        string `json:"label,omitempty"`
	ErrorSummary string `json:"error_summary,omitempty"`
}

func toRunDTO(r *run.Run) runDTO {
	return runDTO{
		ID:           r.ID,
		ProjectID:    r.ProjectID,
		Phase:        string(r.Phase),
		Status:       string(r.Status),
		Label:        r.Label,
		ErrorSummary: r.ErrorSummary,
	}
}

type toolExecDTO struct {
	ID              string `json:"id"`
	RunID           string `json:"run_id"`
	Tool            string `json:"tool"`
	Status          string `json:"status"`
	EntitiesEmitted int    `json:"entities_emitted"`
	EvidenceEmitted int    `json:"evidence_emitted"`
	FindingsEmitted int    `json:"findings_emitted"`
	ErrorSummary    string `json:"error_summary,omitempty"`
}

type createScopeRuleRequest struct {
	Pattern string `json:"pattern"`
	Kind    string `json:"kind,omitempty"`
	Note    string `json:"note,omitempty"`
}

type auditLogDTO struct {
	ID                  string         `json:"id"`
	ProjectID           string         `json:"project_id,omitempty"`
	ProjectNameSnapshot string         `json:"project_name_snapshot,omitempty"`
	Actor               string         `json:"actor"`
	Action              string         `json:"action"`
	Target              string         `json:"target,omitempty"`
	Detail              map[string]any `json:"detail"`
	CreatedAt           string         `json:"created_at"`
}

// decodeJSONBody reads at most maxBodyBytes from r.Body and decodes it
// into dst. Rejects unknown fields so a typo in the SPA surfaces as
// 400 rather than silently being ignored.
const maxBodyBytes = 1 << 20 // 1 MiB; way more than any scope-rule body

func decodeJSONBody(r *http.Request, dst any) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("empty request body")
		}
		return err
	}
	// Refuse trailing garbage; a body like `{"a":1}{"b":2}` is almost
	// always a client bug rather than legitimate input.
	if dec.More() {
		return fmt.Errorf("unexpected trailing data in request body")
	}
	return nil
}
