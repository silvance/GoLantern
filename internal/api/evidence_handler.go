package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/silvance/golantern/internal/audit"
	"github.com/silvance/golantern/internal/entity"
	"github.com/silvance/golantern/internal/evidence"
	"github.com/silvance/golantern/internal/finding"
)

// evidenceParserDTO is one item in the list-parsers response. The
// SPA uses this to populate the ingest-form dropdown.
type evidenceParserDTO struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleListEvidenceParsers(w http.ResponseWriter, _ *http.Request) {
	if s.EvidenceParsers == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody("evidence ingest not configured"))
		return
	}
	descs := s.EvidenceParsers.Describe()
	out := make([]evidenceParserDTO, 0, len(descs))
	for _, d := range descs {
		out = append(out, evidenceParserDTO{Name: d.Name, Description: d.Description})
	}
	writeJSON(w, http.StatusOK, out)
}

type evidenceIngestReq struct {
	Tool    string `json:"tool"`
	Content string `json:"content"`
	Target  string `json:"target"` // optional — IP/host the evidence pertains to
	Notes   string `json:"notes"`  // optional — operator's free-text label
}

type evidenceIngestResp struct {
	Tool             string `json:"tool"`
	Target           string `json:"target,omitempty"`
	EntitiesEmitted  int    `json:"entities_emitted"`
	FindingsEmitted  int    `json:"findings_emitted"`
	EvidenceEmitted  int    `json:"evidence_emitted"`
}

func (s *Server) handleEvidenceIngest(w http.ResponseWriter, r *http.Request) {
	if s.EvidenceParsers == nil || s.Entities == nil || s.Findings == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody("evidence ingest not configured"))
		return
	}
	projectID := r.PathValue("id")
	if projectID == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("missing project id"))
		return
	}
	// Confirm project exists so the operator gets a clean 404 instead
	// of orphan rows in the store.
	proj, err := s.Projects.Get(r.Context(), projectID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorBody(fmt.Sprintf("project %q not found", projectID)))
		return
	}

	var req evidenceIngestReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid json: "+err.Error()))
		return
	}
	req.Tool = strings.TrimSpace(req.Tool)
	req.Target = strings.TrimSpace(req.Target)
	if req.Tool == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("tool is required"))
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		writeJSON(w, http.StatusBadRequest, errorBody("content is required"))
		return
	}

	parser, err := s.EvidenceParsers.Get(req.Tool)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody(err.Error()))
		return
	}

	result, err := parser.Parse(req.Content, req.Target)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("parser error: "+err.Error()))
		return
	}

	// Persist via the same repositories the scan runner uses, but
	// without a ToolExecutionID — the data model already allows NULL
	// (tool_execution_id is nullable in the SQLite schema).
	persisted, err := s.persistEvidenceResult(r.Context(), projectID, parser.Name(), req, result)
	if err != nil {
		s.Logger.Error("evidence ingest persist failed",
			"project_id", projectID,
			"tool", req.Tool,
			"err", err)
		writeJSON(w, http.StatusInternalServerError, errorBody("persist failed: "+err.Error()))
		return
	}

	// Append-only audit row so the operator can review who ingested
	// what without scanning every evidence row. Mirrors the
	// project-created / run-created records elsewhere in this file.
	if err := s.Audit.Record(r.Context(), &audit.LogEntry{
		ProjectID:           projectID,
		ProjectNameSnapshot: proj.Name,
		Action:              audit.ActionEvidenceIngested,
		Target:              parser.Name(),
		Detail: map[string]any{
			"tool":             parser.Name(),
			"target":           req.Target,
			"entities_emitted": persisted.EntitiesEmitted,
			"findings_emitted": persisted.FindingsEmitted,
			"evidence_emitted": persisted.EvidenceEmitted,
			"raw_length":       len(req.Content),
			"notes":            req.Notes,
		},
	}); err != nil {
		s.Logger.WarnContext(r.Context(), "audit record failed",
			slog.String("action", audit.ActionEvidenceIngested),
			slog.Any("err", err))
	}

	writeJSON(w, http.StatusCreated, persisted)
}

// persistEvidenceResult writes the parser output into the entity /
// finding / evidence repositories. Returns a summary suitable for
// the HTTP response body.
//
// Entities are upserted first (so subsequent findings + evidence
// can FK to them). Each finding records its supporting entities
// as evidence rows in the same way collectors do via EmitFinding.
func (s *Server) persistEvidenceResult(
	ctx context.Context,
	projectID, toolName string,
	req evidenceIngestReq,
	result evidence.Result,
) (evidenceIngestResp, error) {
	resp := evidenceIngestResp{Tool: toolName, Target: req.Target}

	// Entity index: canonical-value -> entity-id. Used so supporting-
	// entity references on findings resolve to the same row we just
	// upserted.
	entityIDs := map[string]string{}

	for _, ef := range result.Entities {
		canonical := entity.Canonicalize(ef.Kind, ef.Value)
		if canonical == "" {
			continue
		}
		attrs := ef.Attributes
		if attrs == nil {
			attrs = map[string]any{}
		}
		if _, ok := attrs["ingested_via"]; !ok {
			attrs["ingested_via"] = "evidence_ingest"
		}
		if req.Notes != "" {
			attrs["operator_notes"] = req.Notes
		}
		id, err := s.Entities.Upsert(ctx, projectID, ef.Kind, canonical, attrs)
		if err != nil {
			return resp, fmt.Errorf("upsert entity %s/%s: %w", ef.Kind, canonical, err)
		}
		entityIDs[string(ef.Kind)+"|"+canonical] = id
		resp.EntitiesEmitted++
	}

	for _, ff := range result.Findings {
		attrs := ff.Attributes
		if attrs == nil {
			attrs = map[string]any{}
		}
		if req.Notes != "" {
			attrs["operator_notes"] = req.Notes
		}
		f := &finding.Finding{
			ProjectID:      projectID,
			Title:          ff.Title,
			Severity:       ff.Severity,
			Confidence:     defaultConf(ff.Confidence),
			Description:    ff.Description,
			Recommendation: ff.Recommendation,
			Category:       ff.Category,
			Attributes:     attrs,
		}
		if err := s.Findings.CreateFinding(ctx, f); err != nil {
			return resp, fmt.Errorf("create finding: %w", err)
		}
		resp.FindingsEmitted++

		// Wire supporting entities as evidence rows linking the
		// finding to the upserted entity (matching scan-runner
		// behaviour for EmitFinding).
		for _, ref := range ff.SupportingEntities {
			canonical := entity.Canonicalize(ref.Kind, ref.Value)
			if canonical == "" {
				continue
			}
			eid, ok := entityIDs[string(ref.Kind)+"|"+canonical]
			if !ok {
				// Auto-create the entity if a finding references it but
				// the parser didn't emit one explicitly (the common case
				// for the target host).
				id, err := s.Entities.Upsert(ctx, projectID, ref.Kind, canonical, map[string]any{
					"ingested_via": "evidence_ingest",
				})
				if err != nil {
					return resp, fmt.Errorf("upsert supporting entity: %w", err)
				}
				eid = id
				entityIDs[string(ref.Kind)+"|"+canonical] = eid
				resp.EntitiesEmitted++
			}
			if err := s.Findings.CreateEvidence(ctx, &finding.Evidence{
				ProjectID:      projectID,
				EntityID:       eid,
				FindingID:      f.ID,
				SourceTool:     toolName,
				SourceCategory: finding.SourceManual,
				Confidence:     defaultConf(ff.Confidence),
				Payload: map[string]any{
					"finding_title": ff.Title,
					"target":        req.Target,
				},
				Notes: req.Notes,
			}); err != nil {
				return resp, fmt.Errorf("create finding evidence: %w", err)
			}
			resp.EvidenceEmitted++
		}
	}

	for _, ev := range result.Evidence {
		payload := ev.Payload
		if payload == nil {
			payload = map[string]any{}
		}
		if req.Notes != "" {
			payload["operator_notes"] = req.Notes
		}
		var entityID string
		if ev.EntityValue != "" && ev.EntityKind != "" {
			canonical := entity.Canonicalize(ev.EntityKind, ev.EntityValue)
			if id, ok := entityIDs[string(ev.EntityKind)+"|"+canonical]; ok {
				entityID = id
			}
		}
		if err := s.Findings.CreateEvidence(ctx, &finding.Evidence{
			ProjectID:      projectID,
			EntityID:       entityID,
			SourceTool:     toolName,
			SourceCategory: finding.SourceManual,
			Confidence:     defaultConf(ev.Confidence),
			Payload:        payload,
			Notes:          req.Notes,
		}); err != nil {
			return resp, fmt.Errorf("create parser evidence: %w", err)
		}
		resp.EvidenceEmitted++
	}

	// Always record one operator-level evidence row so audit + report
	// surfaces show "this analyst pasted in tool X output at time T".
	if err := s.Findings.CreateEvidence(ctx, &finding.Evidence{
		ProjectID:      projectID,
		SourceTool:     toolName,
		SourceCategory: finding.SourceManual,
		Confidence:     finding.ConfidenceHigh,
		Payload: map[string]any{
			"ingested_via":     "evidence_ingest",
			"target":           req.Target,
			"entities_emitted": resp.EntitiesEmitted,
			"findings_emitted": resp.FindingsEmitted,
			"raw_length":       len(req.Content),
		},
		Notes: req.Notes,
	}); err != nil {
		return resp, fmt.Errorf("create ingest summary: %w", err)
	}
	resp.EvidenceEmitted++

	return resp, nil
}

func defaultConf(c finding.Confidence) finding.Confidence {
	if c == "" {
		return finding.ConfidenceMedium
	}
	return c
}
