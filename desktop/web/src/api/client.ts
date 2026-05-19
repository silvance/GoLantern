// Thin fetch wrapper. Every call goes through `request` so we have
// one place to standardize error handling, JSON parsing, and the API
// origin. Origin is window.location.origin in production (the same
// Go server serves both /api and the SPA) and proxied by Vite during
// `npm run dev`.

import type {
  Artifact,
  AssistantResponse,
  AuditLog,
  CreateRunRequest,
  Entity,
  Finding,
  Project,
  Run,
  ScopeKind,
  ScopeRule,
  ScopeTestResult,
  ToolExecution,
} from "./types";

// API_BASE selection:
//   - Browser visiting the Go server directly: same-origin, "" works.
//   - Vite dev server: "" hits the dev server, which proxies /api/* to
//     the backend (see vite.config.ts).
//   - Tauri webview: the webview origin is "tauri://localhost" (or the
//     OS-specific variant), so we have to point at the backend port
//     explicitly. The Tauri sidecar runs the backend at 127.0.0.1:8765
//     by default; if an operator overrides GOLANTERN_API_PORT they
//     also need to rebuild the SPA with VITE_GOLANTERN_API_BASE set.
const API_BASE = resolveApiBase();

function resolveApiBase(): string {
  const fromEnv = (import.meta as { env?: Record<string, string> }).env
    ?.VITE_GOLANTERN_API_BASE;
  if (fromEnv) return fromEnv;
  if (typeof window !== "undefined") {
    const w = window as unknown as Record<string, unknown>;
    if ("__TAURI__" in w || "__TAURI_INTERNALS__" in w) {
      return "http://127.0.0.1:8765";
    }
  }
  return "";
}

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, body: unknown, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const resp = await fetch(API_BASE + path, {
    headers: {
      Accept: "application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers || {}),
    },
    ...init,
  });
  const text = await resp.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!resp.ok) {
    const msg =
      body && typeof body === "object" && "error" in body
        ? String((body as { error: unknown }).error)
        : `HTTP ${resp.status}`;
    throw new ApiError(resp.status, body, msg);
  }
  return body as T;
}

export const api = {
  // ----- Projects -------------------------------------------------------
  listProjects: () => request<Project[]>("/api/v1/projects"),
  getProject: (id: string) => request<Project>(`/api/v1/projects/${id}`),
  createProject: (p: Partial<Project>) =>
    request<Project>("/api/v1/projects", {
      method: "POST",
      body: JSON.stringify(p),
    }),
  updateProject: (id: string, patch: Partial<Project>) =>
    request<Project>(`/api/v1/projects/${id}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  deleteProject: (id: string) =>
    request<void>(`/api/v1/projects/${id}`, { method: "DELETE" }),

  // ----- Scope rules ----------------------------------------------------
  listScopeRules: (projectID: string) =>
    request<ScopeRule[]>(`/api/v1/projects/${projectID}/scope-rules`),
  createScopeRule: (
    projectID: string,
    rule: { pattern: string; kind: ScopeKind; note?: string },
  ) =>
    request<ScopeRule>(`/api/v1/projects/${projectID}/scope-rules`, {
      method: "POST",
      body: JSON.stringify(rule),
    }),
  deleteScopeRule: (projectID: string, ruleID: string) =>
    request<void>(
      `/api/v1/projects/${projectID}/scope-rules/${ruleID}`,
      { method: "DELETE" },
    ),
  scopeTest: (projectID: string, target: string) =>
    request<ScopeTestResult>(
      `/api/v1/projects/${projectID}/scope/test?target=${encodeURIComponent(target)}`,
    ),

  // ----- Runs -----------------------------------------------------------
  listRuns: (projectID: string) =>
    request<Run[]>(`/api/v1/projects/${projectID}/runs`),
  getRun: (id: string) => request<Run>(`/api/v1/runs/${id}`),
  listToolExecutions: (runID: string) =>
    request<ToolExecution[]>(`/api/v1/runs/${runID}/tool-executions`),
  createRun: (projectID: string, req: CreateRunRequest) =>
    request<Run>(`/api/v1/projects/${projectID}/runs`, {
      method: "POST",
      body: JSON.stringify(req),
    }),
  runEventsURL: (runID: string) => `${API_BASE}/api/v1/runs/${runID}/events`,

  // ----- Findings / entities / artifacts --------------------------------
  // The server exposes findings + entities through the bundled report
  // endpoint when no dedicated list endpoint exists. We use the report
  // (format=json) as the read source for entities + findings.
  reportJSON: (projectID: string) =>
    request<{
      project: Project;
      summary: { entities_total: number; findings_total: number; runs_total: number };
      findings: Finding[];
      entities_by_kind: Record<string, Entity[]>;
      runs: Run[];
    }>(`/api/v1/projects/${projectID}/report?format=json`),

  listArtifacts: (projectID: string) =>
    request<Artifact[]>(`/api/v1/projects/${projectID}/artifacts`),
  artifactURL: (id: string) => `${API_BASE}/api/v1/artifacts/${id}`,

  listAuditLogs: (projectID: string) =>
    request<AuditLog[]>(`/api/v1/projects/${projectID}/audit-logs`),

  // ----- Assistant ------------------------------------------------------
  ask: (projectID: string, question: string, mode?: string) =>
    request<AssistantResponse>(
      `/api/v1/projects/${projectID}/assistant/ask`,
      { method: "POST", body: JSON.stringify({ question, mode }) },
    ),

  health: () => request<{ status: string }>("/healthz"),
};
