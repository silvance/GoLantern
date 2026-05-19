// Wire types mirroring the Go DTOs in internal/api/api.go. Kept hand-
// written rather than generated because the Go server doesn't emit
// OpenAPI and the surface is small enough to maintain by hand. When
// the API adds a field, add it here too.

export type Mode = "assessment" | "bug_bounty" | "ctf";
export type ScopeKind = "passive" | "light_active" | "full_active" | "deny";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high" | "confirmed";

export type Phase =
  | "scope"
  | "osint"
  | "asset_discovery"
  | "validation"
  | "exposure"
  | "enrichment"
  | "review"
  | "reporting";

export type RunStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type ToolStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled"
  | "skipped_out_of_scope";

export interface Project {
  id: string;
  name: string;
  description?: string;
  organization?: string;
  default_scope: ScopeKind;
  mode: Mode;
  report_template?: string;
}

export interface ScopeRule {
  id: string;
  project_id: string;
  pattern: string;
  kind: ScopeKind;
  note?: string;
}

export interface Run {
  id: string;
  project_id: string;
  phase: Phase;
  status: RunStatus;
  label?: string;
  parameters?: Record<string, unknown>;
  started_at?: string;
  finished_at?: string;
  error_summary?: string;
}

export interface ToolExecution {
  id: string;
  run_id: string;
  tool: string;
  status: ToolStatus;
  parameters?: Record<string, unknown>;
  result_summary?: Record<string, unknown>;
  started_at?: string;
  finished_at?: string;
  error_summary?: string;
  entities_emitted: number;
  evidence_emitted: number;
  findings_emitted: number;
}

export interface Finding {
  id: string;
  project_id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  description?: string;
  recommendation?: string;
  category?: string;
  attributes?: Record<string, unknown>;
}

export interface Entity {
  id: string;
  project_id: string;
  kind: string;
  value: string;
  attributes?: Record<string, unknown>;
}

export interface Artifact {
  id: string;
  project_id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  project_id?: string;
  actor: string;
  action: string;
  target?: string;
  detail?: Record<string, unknown>;
  created_at: string;
}

export interface ScopeTestResult {
  target: string;
  allowed: boolean;
  matched_pattern?: string;
  matched_kind?: ScopeKind;
}

export interface AssistantResponse {
  content: string;
  model: string;
  input_tokens?: number;
  output_tokens?: number;
}

export interface ToolInvocation {
  tool: string;
  parameters?: Record<string, unknown>;
}

export interface CreateRunRequest {
  phase: Phase;
  label?: string;
  tools?: ToolInvocation[];
}

export interface ParameterSpec {
  name: string;
  type: string;
  description?: string;
  required?: boolean;
  default?: unknown;
  choices?: string[];
  placeholder?: string;
}

export interface Collector {
  name: string;
  phase: Phase;
  required_scope: ScopeKind;
  description: string;
  source_category?: string;
  consumes: string[];
  produces: string[];
  triggers_on_services: string[];
  binary?: string;
  install_hint?: string;
  parameters: ParameterSpec[];
}

export interface RecommendedToolsResponse {
  phase: Phase;
  mode: Mode;
  tools: string[];
}

export interface DoctorEntry {
  name: string;
  phase: Phase;
  binary?: string;
  path?: string;
  status: "ok" | "missing" | "no_binary";
  install_hint?: string;
}

