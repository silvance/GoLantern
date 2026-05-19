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
	"log/slog"
	"net/http"

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
	Logger   *slog.Logger
}

// New constructs a Server with sensible defaults. Logger defaults to
// slog.Default when nil.
func New(projects project.Repository, scopes scope.Repository, runs run.Repository) *Server {
	return &Server{
		Projects: projects,
		Scopes:   scopes,
		Runs:     runs,
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
	mux.HandleFunc("GET /api/v1/projects/{id}/scope/test", s.handleScopeTest)
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
