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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/silvance/golantern/internal/artifact"
	"github.com/silvance/golantern/internal/assistant"
	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/engine"
	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/events"
	"github.com/silvance/golantern/internal/finding"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/report"
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
	// Entities and Findings are optional at the Server level. The
	// report endpoint needs them; everything else does without. When
	// either is nil, GET /report returns 501.
	Entities entity.Repository
	Findings finding.Repository
	// Artifacts + ArtifactStore are optional. When both are wired,
	// GET /api/v1/artifacts/{id} streams the bytes; when either is
	// nil, that endpoint returns 501.
	Artifacts     artifact.Repository
	ArtifactStore artifact.Store
	// Bus is optional. When set, GET /runs/{id}/events streams
	// Server-Sent Events; nil makes that endpoint return 501.
	Bus *events.Bus
	// SSEKeepalive is how often the events endpoint emits a comment
	// frame to keep idle connections open. Defaults to 15s. Tests
	// override this to keep the suite fast.
	SSEKeepalive time.Duration
	// Assistant is optional. When nil, POST /assistant/ask returns
	// 501. cmd/golantern wires this when LANTERN_ASSISTANT_ENABLED
	// is true.
	Assistant assistant.Provider
	Logger    *slog.Logger

	// Enqueue is the run-dispatch hook. When nil, POST /runs with a
	// non-empty tools list returns 501 (Phase 4 behaviour). When set
	// (Phase 5+), the handler enqueues and returns 201 — the queue's
	// worker drives the run to a terminal status asynchronously.
	//
	// Injected as a function so the api package has no dependency on
	// the queue package. cmd/golantern wires the two.
	Enqueue EnqueueFunc
}

// EnqueueFunc dispatches a Run for asynchronous execution by the job
// queue. ctx is the request context; the queue is free to detach if
// the work outlives the request.
type EnqueueFunc func(ctx context.Context, runID string, invocations []ToolInvocation) error

// ToolInvocation is the request-shape for a single tool to run inside
// a Run. We re-export the JSON DTO as the public type for EnqueueFunc
// so the queue package needn't import the api package's internals.
type ToolInvocation = toolInvocation

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
	mux.HandleFunc("POST /api/v1/projects", s.handleCreateProject)
	mux.HandleFunc("GET /api/v1/projects/{id}", s.handleGetProject)
	mux.HandleFunc("PATCH /api/v1/projects/{id}", s.handleUpdateProject)
	mux.HandleFunc("DELETE /api/v1/projects/{id}", s.handleDeleteProject)
	mux.HandleFunc("GET /api/v1/projects/{id}/scope-rules", s.handleListScopeRules)
	mux.HandleFunc("POST /api/v1/projects/{id}/scope-rules", s.handleCreateScopeRule)
	mux.HandleFunc("DELETE /api/v1/projects/{id}/scope-rules/{ruleID}", s.handleDeleteScopeRule)
	mux.HandleFunc("GET /api/v1/projects/{id}/scope/test", s.handleScopeTest)
	mux.HandleFunc("GET /api/v1/projects/{id}/audit-logs", s.handleListAuditLogs)
	mux.HandleFunc("GET /api/v1/projects/{id}/report", s.handleReport)
	mux.HandleFunc("GET /api/v1/projects/{id}/runs", s.handleListRuns)
	mux.HandleFunc("POST /api/v1/projects/{id}/runs", s.handleCreateRun)
	mux.HandleFunc("GET /api/v1/runs/{id}", s.handleGetRun)
	mux.HandleFunc("GET /api/v1/runs/{id}/tool-executions", s.handleListToolExecutions)
	mux.HandleFunc("GET /api/v1/runs/{id}/events", s.handleRunEvents)
	mux.HandleFunc("POST /api/v1/projects/{id}/assistant/ask", s.handleAssistantAsk)
	mux.HandleFunc("GET /api/v1/projects/{id}/artifacts", s.handleListArtifacts)
	mux.HandleFunc("GET /api/v1/artifacts/{id}", s.handleGetArtifact)
	return mux
}

// handleListArtifacts returns metadata rows for every artifact a project
// owns, newest first. Bytes are fetched separately via
// GET /api/v1/artifacts/{id}.
func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	if s.Artifacts == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody("artifact storage not configured"))
		return
	}
	projectID := r.PathValue("id")
	if _, err := s.Projects.Get(r.Context(), projectID); err != nil {
		s.writeError(w, r, err)
		return
	}
	rows, err := s.Artifacts.ListByProject(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := make([]artifactDTO, 0, len(rows))
	for _, a := range rows {
		out = append(out, toArtifactDTO(a))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGetArtifact streams the raw bytes for an artifact. The
// Content-Type comes from the stored row; Content-Disposition is
// "attachment" so a browser hitting the endpoint directly saves the
// file rather than trying to render it (useful for raw HTML captures
// from nuclei etc., which we don't want rendered in the operator's
// browser context).
func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	if s.Artifacts == nil || s.ArtifactStore == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody("artifact storage not configured"))
		return
	}
	artifactID := r.PathValue("id")
	a, err := s.Artifacts.Get(r.Context(), artifactID)
	if err != nil {
		if errors.Is(err, artifact.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorBody("not found"))
			return
		}
		s.writeError(w, r, err)
		return
	}
	body, err := s.ArtifactStore.Get(r.Context(), a.StorageURI)
	if err != nil {
		if errors.Is(err, artifact.ErrNotFound) {
			// Row says it exists but bytes are gone. Treat as 410 so
			// callers can distinguish from "never existed".
			writeJSON(w, http.StatusGone, errorBody("artifact bytes are gone"))
			return
		}
		s.writeError(w, r, err)
		return
	}
	contentType := a.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if a.Filename != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", a.Filename))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// artifactDTO is the wire shape for artifact rows. StorageURI is
// deliberately omitted — clients should fetch via the artifact id
// endpoint, not poke at filesystem paths.
type artifactDTO struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	SizeBytes   int       `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
	CreatedAt   time.Time `json:"created_at"`
}

func toArtifactDTO(a *artifact.Artifact) artifactDTO {
	return artifactDTO{
		ID:          a.ID,
		ProjectID:   a.ProjectID,
		Filename:    a.Filename,
		ContentType: a.ContentType,
		SizeBytes:   a.SizeBytes,
		SHA256:      a.SHA256,
		CreatedAt:   a.CreatedAt,
	}
}

// handleAssistantAsk implements POST /api/v1/projects/{id}/assistant/ask.
//
// Body: {question: string, mode?: string}. The mode parameter, when
// omitted, defaults to the project's mode. Returns the assistant's
// reply text plus the model name and token usage so the SPA can show
// cost.
//
// 501 when Server.Assistant is nil (feature disabled or unconfigured);
// 400 on missing/empty question; 404 on missing project; 502 on
// upstream provider failure (rate limit, server error). The provider
// error message is included verbatim so analysts can distinguish a
// transient 429 from a malformed-request 400.
func (s *Server) handleAssistantAsk(w http.ResponseWriter, r *http.Request) {
	if s.Assistant == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody(
			"assistant not configured on this server"))
		return
	}
	if s.Entities == nil || s.Findings == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody(
			"assistant needs entity + finding repositories on the server"))
		return
	}
	projectID := r.PathValue("id")
	p, err := s.Projects.Get(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	var req assistantAskRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	req.Question = strings.TrimSpace(req.Question)
	if req.Question == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("question is required"))
		return
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = string(p.Mode)
	}

	// Build the bundle once; reuse for the prompt's context block.
	bundle, err := report.Generate(r.Context(), report.Deps{
		Projects: s.Projects, Entities: s.Entities, Findings: s.Findings,
		Runs: s.Runs, Audit: s.Audit,
	}, projectID, report.Options{})
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	system := assistant.SystemPromptFor(mode)
	user := assistant.BuildPrompt(bundle, req.Question)

	reply, err := s.Assistant.Complete(r.Context(), system, []assistant.Message{
		{Role: "user", Content: user},
	})
	if err != nil {
		s.Logger.WarnContext(r.Context(), "assistant Complete failed",
			slog.String("project_id", projectID), slog.Any("err", err))
		writeJSON(w, http.StatusBadGateway, errorBody(err.Error()))
		return
	}
	// Audit the call so the trail of "what did the LLM see / say"
	// stays reviewable. Detail omits the prompt text (too long) but
	// records the mode, question, model, and usage.
	_ = s.Audit.Record(r.Context(), &audit.LogEntry{
		ProjectID:           projectID,
		ProjectNameSnapshot: p.Name,
		Action:              "assistant.ask",
		Target:              reply.Model,
		Detail: map[string]any{
			"mode":          mode,
			"question_len":  len(req.Question),
			"reply_len":     len(reply.Content),
			"input_tokens":  reply.InputTokens,
			"output_tokens": reply.OutputTokens,
		},
	})
	writeJSON(w, http.StatusOK, assistantAskResponse{
		Content:      reply.Content,
		Model:        reply.Model,
		InputTokens:  reply.InputTokens,
		OutputTokens: reply.OutputTokens,
	})
}

type assistantAskRequest struct {
	Question string `json:"question"`
	Mode     string `json:"mode,omitempty"`
}

type assistantAskResponse struct {
	Content      string `json:"content"`
	Model        string `json:"model"`
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
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

// handleCreateProject implements POST /api/v1/projects.
//
// Body: ProjectCreate (name required; default_scope defaults to passive;
// mode defaults to assessment; target is honored only when mode=ctf).
// Returns 201 with the new project. CTF auto-rule mirrors Python's
// schemas/project.py contract: a single FULL_ACTIVE ScopeRule is added
// for `target` when mode=CTF, with audit detail.kind_source="ctf_auto".
func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("name is required"))
		return
	}

	defScope := scope.RuleKind(strings.ToLower(strings.TrimSpace(req.DefaultScope)))
	if defScope == "" {
		defScope = scope.KindPassive
	}
	if !defScope.Valid() {
		writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("invalid default_scope %q", req.DefaultScope)))
		return
	}
	mode := project.Mode(strings.ToLower(strings.TrimSpace(req.Mode)))
	if mode == "" {
		mode = project.ModeAssessment
	}
	if !mode.Valid() {
		writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("invalid mode %q", req.Mode)))
		return
	}

	p := &project.Project{
		Name:         req.Name,
		Description:  strings.TrimSpace(req.Description),
		Organization: strings.TrimSpace(req.Organization),
		DefaultScope: defScope,
		Mode:         mode,
	}
	if err := s.Projects.Save(r.Context(), p); err != nil {
		s.writeError(w, r, err)
		return
	}

	// project.created audit. Detail mirrors Python exactly.
	if err := s.Audit.Record(r.Context(), &audit.LogEntry{
		ProjectID:           p.ID,
		ProjectNameSnapshot: p.Name,
		Action:              audit.ActionProjectCreated,
		Target:              p.Name,
		Detail: map[string]any{
			"default_scope": string(p.DefaultScope),
			"mode":          string(p.Mode),
		},
	}); err != nil {
		s.Logger.WarnContext(r.Context(), "audit record failed",
			slog.String("action", audit.ActionProjectCreated),
			slog.Any("err", err))
	}

	// CTF auto-rule. Non-CTF modes ignore the target field on purpose.
	target := strings.TrimSpace(req.Target)
	if target != "" && p.Mode == project.ModeCTF {
		sr := &scope.StoredRule{
			ProjectID: p.ID,
			Rule:      scope.Rule{Pattern: target, Kind: scope.KindFullActive},
			Note:      "auto-created from CTF project target",
		}
		if err := s.Scopes.Add(r.Context(), sr); err != nil {
			// Failure here is non-fatal for the project create; surface
			// it in the response logs but still return the project so
			// the SPA can present a useful state.
			s.Logger.WarnContext(r.Context(), "CTF auto-rule failed",
				slog.String("project_id", p.ID),
				slog.Any("err", err))
		} else {
			_ = s.Audit.Record(r.Context(), &audit.LogEntry{
				ProjectID:           p.ID,
				ProjectNameSnapshot: p.Name,
				Action:              audit.ActionScopeRuleCreated,
				Target:              sr.Rule.Pattern,
				Detail: map[string]any{
					"kind":        string(sr.Rule.Kind),
					"note":        sr.Note,
					"kind_source": "ctf_auto",
				},
			})
		}
	}

	writeJSON(w, http.StatusCreated, toProjectDTO(p))
}

// handleUpdateProject implements PATCH /api/v1/projects/{id}.
//
// Partial update: only fields present in the JSON body are touched.
// Empty-string values clear the field on the project (description /
// organization). Audit detail records the actual changes, matching
// Python's model_dump(exclude_unset=True) behaviour.
func (s *Server) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	p, err := s.Projects.Get(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	// Use a map first so we can tell "absent" from "explicit empty".
	var raw map[string]json.RawMessage
	if err := decodeJSONBody(r, &raw); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	if len(raw) == 0 {
		writeJSON(w, http.StatusBadRequest, errorBody("no fields to update"))
		return
	}

	changes := make(map[string]any, len(raw))
	allowed := map[string]bool{
		"name": true, "description": true, "organization": true,
		"default_scope": true, "mode": true,
	}
	for k, v := range raw {
		if !allowed[k] {
			writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("unknown field %q", k)))
			return
		}
		var sv string
		if err := json.Unmarshal(v, &sv); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("field %q must be a string", k)))
			return
		}
		changes[k] = sv
	}

	if v, ok := changes["name"]; ok {
		name := strings.TrimSpace(v.(string))
		if name == "" {
			writeJSON(w, http.StatusBadRequest, errorBody("name cannot be empty"))
			return
		}
		p.Name = name
	}
	if v, ok := changes["description"]; ok {
		p.Description = v.(string)
	}
	if v, ok := changes["organization"]; ok {
		p.Organization = v.(string)
	}
	if v, ok := changes["default_scope"]; ok {
		k := scope.RuleKind(strings.ToLower(strings.TrimSpace(v.(string))))
		if !k.Valid() {
			writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("invalid default_scope %q", v)))
			return
		}
		p.DefaultScope = k
	}
	if v, ok := changes["mode"]; ok {
		m := project.Mode(strings.ToLower(strings.TrimSpace(v.(string))))
		if !m.Valid() {
			writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("invalid mode %q", v)))
			return
		}
		p.Mode = m
	}

	if err := s.Projects.Save(r.Context(), p); err != nil {
		s.writeError(w, r, err)
		return
	}

	if err := s.Audit.Record(r.Context(), &audit.LogEntry{
		ProjectID:           p.ID,
		ProjectNameSnapshot: p.Name,
		Action:              audit.ActionProjectUpdated,
		Target:              p.Name,
		Detail:              changes,
	}); err != nil {
		s.Logger.WarnContext(r.Context(), "audit record failed",
			slog.String("action", audit.ActionProjectUpdated),
			slog.Any("err", err))
	}

	writeJSON(w, http.StatusOK, toProjectDTO(p))
}

// handleDeleteProject implements DELETE /api/v1/projects/{id}.
// 204 on success, 404 if missing.
//
// Audit row is recorded BEFORE the delete so the project_name_snapshot
// resolution still works inside record_audit (mirrors Python's pattern
// in delete_project). The audit row's project_id is set NULL by the FK
// on the cascade; the snapshot keeps the trail readable.
func (s *Server) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	p, err := s.Projects.Get(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	_ = s.Audit.Record(r.Context(), &audit.LogEntry{
		ProjectID:           p.ID,
		ProjectNameSnapshot: p.Name,
		Action:              audit.ActionProjectDeleted,
		Target:              p.Name,
		Detail: map[string]any{
			"default_scope": string(p.DefaultScope),
			"mode":          string(p.Mode),
			"organization":  p.Organization,
		},
	})
	if err := s.Projects.Delete(r.Context(), projectID); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleReport implements GET /api/v1/projects/{id}/report.
//
// Query parameter: format=json (default) | html | csv. JSON ships the
// raw bundle; HTML and CSV render through the report package. Returns
// 501 when entity or finding repos haven't been wired into the server.
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if s.Entities == nil || s.Findings == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody(
			"report endpoint not configured on this server"))
		return
	}
	projectID := r.PathValue("id")
	b, err := report.Generate(r.Context(), report.Deps{
		Projects: s.Projects,
		Entities: s.Entities,
		Findings: s.Findings,
		Runs:     s.Runs,
		Audit:    s.Audit,
	}, projectID, report.Options{})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	switch strings.ToLower(r.URL.Query().Get("format")) {
	case "", "json":
		writeJSON(w, http.StatusOK, b)
	case "html":
		out, err := report.RenderHTML(b)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	case "csv":
		out, err := report.RenderCSV(b)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		filename := fmt.Sprintf("lantern-report-%s.csv", b.Project.ID)
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	case "pdf":
		out, err := report.RenderPDF(b)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		filename := fmt.Sprintf("lantern-report-%s.pdf", b.Project.ID)
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	case "docx":
		out, err := report.RenderDOCX(b)
		if err != nil {
			s.writeError(w, r, err)
			return
		}
		filename := fmt.Sprintf("lantern-report-%s.docx", b.Project.ID)
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	default:
		writeJSON(w, http.StatusBadRequest, errorBody("format must be one of: json, html, csv, pdf, docx"))
	}
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
	pol, err := engine.LoadPolicy(r.Context(), s.Projects, s.Scopes, r.PathValue("id"))
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

// handleCreateRun implements POST /api/v1/projects/{id}/runs.
//
// Body: {phase, label?, parameters?, tools?}.
//
// Phase prerequisites are checked via engine.CanStartPhase (CTF mode
// short-circuits; SCOPE is satisfied by any ScopeRule). Failure is
// 409 with the human-readable reason from the engine package.
//
// Tool dispatch is NOT yet ported: an empty tools list takes the
// Python "intentional skip" path (mark COMPLETED inline so the
// operator can declare a phase done without running collectors), but a
// non-empty tools list returns 501 with a clear message that the job
// queue lands in Phase 5. This is deliberately distinct from a silent
// no-op so SPA flows that depend on queueing fail loudly.
func (s *Server) handleCreateRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	p, err := s.Projects.Get(r.Context(), projectID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	var req createRunRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}
	phase := workflow.Phase(strings.ToLower(strings.TrimSpace(req.Phase)))
	if !phase.Valid() {
		writeJSON(w, http.StatusBadRequest, errorBody(fmt.Sprintf("invalid phase %q", req.Phase)))
		return
	}

	ok, reason, err := engine.CanStartPhase(r.Context(), s.Projects, s.Scopes, s.Runs, projectID, phase)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if !ok {
		writeJSON(w, http.StatusConflict, errorBody(reason))
		return
	}

	params := req.Parameters
	if params == nil {
		params = map[string]any{}
	}
	ru := &run.Run{
		ProjectID:  projectID,
		Phase:      phase,
		Status:     run.StatusPending,
		Label:      strings.TrimSpace(req.Label),
		Parameters: params,
	}
	if err := s.Runs.Save(r.Context(), ru); err != nil {
		s.writeError(w, r, err)
		return
	}
	_ = s.Audit.Record(r.Context(), &audit.LogEntry{
		ProjectID:           projectID,
		ProjectNameSnapshot: p.Name,
		Action:              audit.ActionRunCreated,
		Target:              ru.ID,
		Detail: map[string]any{
			"phase": string(ru.Phase),
			"label": ru.Label,
		},
	})

	if len(req.Tools) == 0 {
		// Empty tools: Python's "intentional skip" shortcut. Mark
		// COMPLETED inline so phases like SCOPE (no collectors) can be
		// declared done without a queue round trip.
		now := time.Now().UTC()
		ru.Status = run.StatusCompleted
		ru.StartedAt = &now
		ru.FinishedAt = &now
		if err := s.Runs.Save(r.Context(), ru); err != nil {
			s.writeError(w, r, err)
			return
		}
		_ = s.Audit.Record(r.Context(), &audit.LogEntry{
			ProjectID:           projectID,
			ProjectNameSnapshot: p.Name,
			Action:              audit.ActionRunFinished,
			Target:              ru.ID,
			Detail: map[string]any{
				"status": string(ru.Status),
				"phase":  string(ru.Phase),
			},
		})
		writeJSON(w, http.StatusCreated, toRunDTO(ru))
		return
	}

	// Non-empty tools: enqueue for asynchronous dispatch. The run
	// stays PENDING until the worker picks it up; clients watch the
	// run's status via GET /runs/{id} (SSE event streams land later).
	if s.Enqueue == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody(
			"tool dispatch not configured on this server"))
		return
	}
	if err := s.Enqueue(r.Context(), ru.ID, req.Tools); err != nil {
		s.Logger.WarnContext(r.Context(), "enqueue failed",
			slog.String("run_id", ru.ID), slog.Any("err", err))
		// Roll back the optimistic Run state so a queue-full or
		// queue-shutting-down condition surfaces as 503 instead of
		// leaving a PENDING run that will never advance.
		ru.Status = run.StatusFailed
		now := time.Now().UTC()
		ru.FinishedAt = &now
		ru.ErrorSummary = fmt.Sprintf("enqueue failed: %v", err)
		_ = s.Runs.Save(r.Context(), ru)
		writeJSON(w, http.StatusServiceUnavailable, errorBody("queue unavailable"))
		return
	}
	writeJSON(w, http.StatusCreated, toRunDTO(ru))
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

// handleRunEvents implements GET /api/v1/runs/{id}/events as a
// Server-Sent Events stream. Subscribers see tool.started, entity.*,
// relation.*, evidence.*, finding.*, tool.finished, and run.finished;
// the stream closes after run.finished so clients can drain cleanly.
//
// If the run is already terminal when the connection opens, we emit a
// single synthetic run.finished frame and close — callers should then
// fall back to GET /runs/{id} for the snapshot.
//
// Returns 501 when the bus isn't wired into this server; the SPA falls
// back to polling.
func (s *Server) handleRunEvents(w http.ResponseWriter, r *http.Request) {
	if s.Bus == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody(
			"event stream not configured on this server"))
		return
	}
	runID := r.PathValue("id")
	ru, err := s.Runs.Get(r.Context(), runID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		// net/http's default ResponseWriter supports Flusher; this is
		// a safety belt for unusual wrappers.
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering when proxied
	w.WriteHeader(http.StatusOK)

	// Terminal-already short-circuit: emit one synthetic frame and
	// close, mirroring Python's behaviour.
	if ru.Status.IsTerminal() {
		payload, _ := json.Marshal(map[string]any{
			"phase":  string(ru.Phase),
			"status": string(ru.Status),
		})
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", events.KindRunFinished, payload)
		flusher.Flush()
		return
	}

	ch := s.Bus.Subscribe(runID)
	defer s.Bus.Unsubscribe(runID, ch)

	// Keepalive interval — same 15s the Python implementation uses
	// in production. Tests override via Server.SSEKeepalive to keep
	// the suite snappy. Browsers and proxies close idle connections;
	// a comment frame every interval keeps the channel open during
	// quiet stretches.
	keepalive := s.SSEKeepalive
	if keepalive <= 0 {
		keepalive = 15 * time.Second
	}
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case ev, open := <-ch:
			if !open {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				s.Logger.WarnContext(r.Context(), "sse: encode event failed",
					slog.String("run_id", runID), slog.Any("err", err))
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Kind, payload)
			flusher.Flush()
			if ev.Kind == events.KindRunFinished {
				return
			}
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			// Client disconnected.
			return
		}
	}
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

type createProjectRequest struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	Organization string `json:"organization,omitempty"`
	DefaultScope string `json:"default_scope,omitempty"`
	Mode         string `json:"mode,omitempty"`
	// Target is only honored when Mode is "ctf"; non-CTF modes ignore
	// it. See lantern/schemas/project.py for the rationale.
	Target string `json:"target,omitempty"`
}

type toolInvocation struct {
	Tool       string         `json:"tool"`
	Parameters map[string]any `json:"parameters,omitempty"`
}

type createRunRequest struct {
	Phase      string           `json:"phase"`
	Label      string           `json:"label,omitempty"`
	Parameters map[string]any   `json:"parameters,omitempty"`
	Tools      []toolInvocation `json:"tools,omitempty"`
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
