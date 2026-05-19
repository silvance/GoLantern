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
