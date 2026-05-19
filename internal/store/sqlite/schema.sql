-- GoLantern SQLite schema. Reflects the head of Lantern's Alembic
-- migration chain (after 0001 + 0004 + 0006: runs/tool_executions error
-- split, projects.mode column, repository entity kind) so the Go store
-- reads and writes the same DB the Python service uses.
--
-- Enum columns store the SQLAlchemy member NAME (uppercase, e.g.
-- 'LIGHT_ACTIVE'), not the .value used in HTTP responses. The store
-- maps lowercase Go values to uppercase DB names at write time. The
-- string values listed below match what SQLAlchemy's Enum() emits.
--
-- Idempotent: every CREATE uses IF NOT EXISTS so it's safe to run
-- against a Lantern DB that already has the tables.

CREATE TABLE IF NOT EXISTS projects (
    id            VARCHAR(32) PRIMARY KEY,
    name          VARCHAR(256) NOT NULL UNIQUE,
    description   TEXT,
    organization  VARCHAR(256),
    default_scope VARCHAR(16) NOT NULL
        CHECK (default_scope IN ('PASSIVE','LIGHT_ACTIVE','FULL_ACTIVE','DENY')),
    mode          VARCHAR(16) NOT NULL
        CHECK (mode IN ('ASSESSMENT','BUG_BOUNTY','CTF')),
    created_at    DATETIME NOT NULL,
    updated_at    DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id         VARCHAR(32) PRIMARY KEY,
    project_id VARCHAR(32) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    pattern    VARCHAR(512) NOT NULL,
    kind       VARCHAR(16) NOT NULL
        CHECK (kind IN ('PASSIVE','LIGHT_ACTIVE','FULL_ACTIVE','DENY')),
    note       TEXT,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CONSTRAINT uq_scope_rules_project_pattern UNIQUE (project_id, pattern)
);
CREATE INDEX IF NOT EXISTS ix_scope_rules_project ON scope_rules(project_id);

CREATE TABLE IF NOT EXISTS runs (
    id            VARCHAR(32) PRIMARY KEY,
    project_id    VARCHAR(32) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    phase         VARCHAR(32) NOT NULL
        CHECK (phase IN ('SCOPE','OSINT','ASSET_DISCOVERY','VALIDATION',
                         'EXPOSURE','ENRICHMENT','REVIEW','REPORTING')),
    status        VARCHAR(16) NOT NULL
        CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED','CANCELLED')),
    label         VARCHAR(256),
    parameters    TEXT NOT NULL DEFAULT '{}',  -- JSON
    started_at    DATETIME,
    finished_at   DATETIME,
    error_summary TEXT,
    error_debug   TEXT,
    created_at    DATETIME NOT NULL,
    updated_at    DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_runs_project_phase ON runs(project_id, phase);

CREATE TABLE IF NOT EXISTS tool_executions (
    id               VARCHAR(32) PRIMARY KEY,
    run_id           VARCHAR(32) NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    tool             VARCHAR(128) NOT NULL,
    status           VARCHAR(32) NOT NULL
        CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED',
                          'CANCELLED','SKIPPED_OUT_OF_SCOPE')),
    parameters       TEXT NOT NULL DEFAULT '{}',  -- JSON
    result_summary   TEXT NOT NULL DEFAULT '{}',  -- JSON
    started_at       DATETIME,
    finished_at      DATETIME,
    error_summary    TEXT,
    error_debug      TEXT,
    entities_emitted INTEGER NOT NULL DEFAULT 0,
    evidence_emitted INTEGER NOT NULL DEFAULT 0,
    findings_emitted INTEGER NOT NULL DEFAULT 0,
    created_at       DATETIME NOT NULL,
    updated_at       DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_tool_executions_run ON tool_executions(run_id);
CREATE INDEX IF NOT EXISTS ix_tool_executions_status ON tool_executions(status);

-- audit_logs survives project deletion: project_id goes NULL via the
-- ON DELETE SET NULL FK so the "who authorized what" trail can't be
-- wiped by deleting the project that an action targeted. The
-- project_name_snapshot column captures the project's name at write
-- time so the row stays human-readable after the FK clears.
CREATE TABLE IF NOT EXISTS audit_logs (
    id                    VARCHAR(32) PRIMARY KEY,
    project_id            VARCHAR(32) REFERENCES projects(id) ON DELETE SET NULL,
    project_name_snapshot VARCHAR(256),
    actor                 VARCHAR(128) NOT NULL DEFAULT 'system',
    action                VARCHAR(128) NOT NULL,
    target                VARCHAR(512),
    detail                TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at            DATETIME NOT NULL,
    updated_at            DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_logs_project ON audit_logs(project_id);

-- Entities: single-table polymorphism keyed by (project_id, kind,
-- value). Attributes is JSON; the runner merges on Upsert. Kind enum
-- matches the SQLAlchemy member names (uppercase) — same convention
-- as everywhere else in this schema.
CREATE TABLE IF NOT EXISTS entities (
    id         VARCHAR(32) PRIMARY KEY,
    project_id VARCHAR(32) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind       VARCHAR(32) NOT NULL
        CHECK (kind IN ('DOMAIN','SUBDOMAIN','IP','URL','EMAIL','PERSON',
                        'DOCUMENT','TECHNOLOGY','PORT','SERVICE',
                        'ORGANIZATION','REPOSITORY')),
    value      VARCHAR(1024) NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CONSTRAINT uq_entities_project_kind_value UNIQUE (project_id, kind, value)
);
CREATE INDEX IF NOT EXISTS ix_entities_project_kind ON entities(project_id, kind);

-- Entity relations: directed edges between two entities within ONE
-- project. project_id on the row is defense-in-depth (the runner only
-- emits same-project relations; the column lets queries filter
-- without joining through entities, and lets cascade-delete sweep
-- relations even when both endpoints are mid-detach). Same-project
-- invariant is enforced application-side because SQLite can't express
-- a composite FK across two columns without contortion.
CREATE TABLE IF NOT EXISTS entity_relations (
    id         VARCHAR(32) PRIMARY KEY,
    project_id VARCHAR(32) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    src_id     VARCHAR(32) NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    dst_id     VARCHAR(32) NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    kind       VARCHAR(32) NOT NULL
        CHECK (kind IN ('RESOLVES_TO','HOSTS','SERVES','BELONGS_TO','AUTHORED',
                        'USES_TECH','CHILD_OF','REFERENCES','DISCOVERED_FROM')),
    attributes TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CONSTRAINT uq_relation_src_dst_kind UNIQUE (src_id, dst_id, kind)
);
CREATE INDEX IF NOT EXISTS ix_entity_relations_src ON entity_relations(src_id);
CREATE INDEX IF NOT EXISTS ix_entity_relations_dst ON entity_relations(dst_id);
CREATE INDEX IF NOT EXISTS ix_entity_relations_project ON entity_relations(project_id);

-- Findings: analyst-facing. Severity / Confidence enums stored as
-- SQLAlchemy member names. The Python head schema carries reportable /
-- reviewed / cvss_* / reproduction_steps columns from later
-- migrations; the Go domain model doesn't surface those yet, so they
-- live on the table (NULLable / defaulted) for forward compatibility
-- with the Python service writing to the same DB.
CREATE TABLE IF NOT EXISTS findings (
    id             VARCHAR(32) PRIMARY KEY,
    project_id     VARCHAR(32) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title          VARCHAR(512) NOT NULL,
    description    TEXT,
    recommendation TEXT,
    severity       VARCHAR(16) NOT NULL
        CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    confidence     VARCHAR(16) NOT NULL
        CHECK (confidence IN ('LOW','MEDIUM','HIGH','CONFIRMED')),
    category       VARCHAR(128),
    reportable     INTEGER NOT NULL DEFAULT 1,
    reviewed       INTEGER NOT NULL DEFAULT 0,
    attributes     TEXT NOT NULL DEFAULT '{}',  -- JSON
    created_at     DATETIME NOT NULL,
    updated_at     DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_findings_project ON findings(project_id);

-- Evidence: a single observation linking an entity (or finding) back
-- to a tool execution. Either entity_id or finding_id may be set;
-- both, both nil, or just one is legal. tool_execution_id goes NULL
-- when the parent ToolExecution row is deleted so the evidence trail
-- survives.
CREATE TABLE IF NOT EXISTS evidence (
    id                VARCHAR(32) PRIMARY KEY,
    project_id        VARCHAR(32) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    entity_id         VARCHAR(32) REFERENCES entities(id) ON DELETE CASCADE,
    finding_id        VARCHAR(32) REFERENCES findings(id) ON DELETE CASCADE,
    tool_execution_id VARCHAR(32) REFERENCES tool_executions(id) ON DELETE SET NULL,
    source_tool       VARCHAR(128) NOT NULL,
    source_category   VARCHAR(32) NOT NULL
        CHECK (source_category IN ('PUBLIC_OSINT','PASSIVE_DNS','CERT_TRANSPARENCY',
                                   'BREACH_INTEL','DOC_METADATA','LIVE_PROBE',
                                   'ACTIVE_SCAN','MANUAL')),
    confidence        VARCHAR(16) NOT NULL
        CHECK (confidence IN ('LOW','MEDIUM','HIGH','CONFIRMED')),
    payload           TEXT NOT NULL DEFAULT '{}',  -- JSON
    artifact_uri      VARCHAR(1024),
    notes             TEXT,
    created_at        DATETIME NOT NULL,
    updated_at        DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_evidence_entity ON evidence(entity_id);
CREATE INDEX IF NOT EXISTS ix_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS ix_evidence_project ON evidence(project_id);

-- Artifacts: metadata row for a binary blob (screenshot, HTML body
-- capture, raw tool output dump, ...). The bytes themselves live in
-- whatever artifact.Store backs the runner; storage_uri points at them
-- and survives a Store swap because the URI scheme is "lantern://".
-- sha256 lets analysts dedupe / verify integrity. content_type is the
-- caller-asserted MIME type; we don't sniff.
CREATE TABLE IF NOT EXISTS artifacts (
    id           VARCHAR(32) PRIMARY KEY,
    project_id   VARCHAR(32) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    filename     VARCHAR(512) NOT NULL,
    content_type VARCHAR(128) NOT NULL,
    size_bytes   INTEGER NOT NULL,
    sha256       VARCHAR(64) NOT NULL,
    storage_uri  VARCHAR(1024) NOT NULL,
    created_at   DATETIME NOT NULL,
    updated_at   DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_artifacts_project ON artifacts(project_id);
