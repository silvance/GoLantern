# GoLantern — Architectural analysis of Lantern and Go migration plan

Source under analysis: https://github.com/silvance/Lantern (`src/lantern/`,
~24.7 kLOC of Python, FastAPI + SQLAlchemy + asyncio).

This document is the planning artifact: identification of Lantern's
modules, the Python-specific assumptions that don't survive a literal
port, the proposed Go architecture, and the phased coexistence plan.
The first ported module lives in `internal/scope/` with tests.

---

## 1. Core domain modules in Lantern

Walking `src/lantern/` produces seven domains that are clearly cohesive
and four that are cross-cutting infrastructure.

### Domain modules

| Domain         | Python location              | Responsibility                                                                                |
|----------------|------------------------------|-----------------------------------------------------------------------------------------------|
| Project + scope | `models/project.py`, `workflow/scope.py` | Project entity, scope rules (PASSIVE / LIGHT_ACTIVE / FULL_ACTIVE / DENY), per-target authorization. |
| Workflow       | `workflow/engine.py`, `workflow/phases.py`, `workflow/modes.py` | Phase prerequisites graph (SCOPE → OSINT → ASSET_DISCOVERY → VALIDATION → EXPOSURE → ENRICHMENT → REVIEW → REPORTING), mode presets (assessment / bug_bounty / CTF). |
| Entities + facts | `models/entities.py`, `tools/base.py` (`EntityFact`, `RelationFact`, `EvidenceFact`, `FindingFact`) | Normalized graph: entities deduped by `(project, kind, value)`; relations as natural-key edges; evidence and findings attached. |
| Runs           | `models/runs.py`             | `Run` (a phase's batch of work), `ToolExecution` (one collector invocation), status machine, error summary/debug split. |
| Collectors (scan engine) | `tools/base.py`, `tools/registry.py`, `tools/runner.py`, `tools/<tool>.py` (~30 wrappers) | `BaseCollector` ABC, registry, `CollectorRunner` that owns the DB session, scope gate, fact merging, event emission. |
| Reporting      | `reports/base.py`, `reports/{html,pdf,docx,csv}_renderer.py` | Aggregation over entities/findings/runs and rendered outputs. |
| Audit          | `audit.py`, `models/runs.py::AuditLog` | Append-only audit trail of authorization decisions. |

### Cross-cutting infrastructure

| Concern        | Python location              | Notes                                                                              |
|----------------|------------------------------|------------------------------------------------------------------------------------|
| CLI            | `cli.py` (1,455 lines)       | `argparse`-based; subcommands wrap the same domain calls the API exposes.          |
| API            | `api/` (17 routers)          | FastAPI; routers map 1:1 to domain modules.                                        |
| Persistence    | `db.py`, `migrations.py`, `migrations/` | SQLAlchemy 2.0 + Alembic; SQLite default, Postgres supported.                       |
| Task queue     | `jobs/queue.py`              | In-process `asyncio.Queue` + N worker tasks; clamps to 1 on SQLite.                |
| Scheduling     | `scheduler.py`               | Periodic re-runs and entity-diff between runs.                                      |
| Events         | `events.py`                  | In-process pub/sub for run/tool/entity emitted events; consumed by SSE on the API. |
| Subprocess     | `subprocess.py`              | Wraps external CLI invocation with `BinaryNotFoundError`, timeouts.                 |
| Artifacts      | `artifacts/store.py`         | `lantern://artifacts/<id>` URI scheme over a filesystem-backed blob store.          |
| Config         | `config.py`                  | `pydantic-settings`; env-var driven.                                                |
| Security       | `security.py`                | Secret-shaped value redaction (api_key / token / password / …).                    |
| Assistant      | `assistant/`                 | Optional LLM (Anthropic/OpenAI) with prompt-injection defenses.                    |

---

## 2. Layer separation (CLI / API / persistence / scan engine / queue / reporting)

The Python layering is mostly clean already; the boundaries that matter
for Go are:

```
                  ┌──────────────────────────────────────────────────┐
                  │ Entry points                                     │
                  │   cli.py            api/*.py                     │
                  └──────────────┬──────────────┬────────────────────┘
                                 │              │
                                 ▼              ▼
                         ┌──────────────────────────────┐
                         │ Application services         │
                         │   workflow/engine.py         │
                         │   jobs/queue.py              │
                         │   reports/base.py            │
                         │   scheduler.py               │
                         └──────────────┬───────────────┘
                                        │
                          ┌─────────────┼──────────────┐
                          ▼             ▼              ▼
                   ┌────────────┐ ┌────────────┐ ┌──────────────┐
                   │ Scan       │ │ Domain     │ │ Persistence  │
                   │ engine     │ │ model      │ │  db.py +     │
                   │ tools/*    │ │ models/*   │ │  models/*    │
                   └─────┬──────┘ └────────────┘ └──────────────┘
                         │
                         ▼
                  external CLIs (nmap, nuclei, …)
```

Important observations:

* **CLI and API share services.** `cli.py` calls `WorkflowEngine` /
  registry / reports directly; the API does the same via FastAPI
  routers. Neither owns business logic. This is the single most
  important property to preserve.
* **The scan engine is the only thing that shells out.** All external
  process invocation flows through `lantern.subprocess` and concrete
  collectors. Nothing else in the codebase calls `subprocess`.
* **Persistence is leaky.** `WorkflowEngine`, `CollectorRunner`, and
  even some API routers take a `Session` directly. There is no
  repository layer. SQLAlchemy is everywhere.
* **The task queue is one process.** `JobQueue` is `asyncio.Queue` +
  worker tasks in the FastAPI lifespan. Cross-process work is
  explicitly out of scope (`# if we ever need cross-process workers we
  can swap in RQ/Arq behind the same JobQueue interface`).
* **Reporting is read-only.** Renderers consume the DB and produce
  bytes; they don't mutate anything.

---

## 3. Python-specific assumptions that should NOT be ported directly

These are the load-bearing-but-Pythonic patterns. Each needs a
deliberate Go translation rather than a 1:1 port.

1. **SQLAlchemy ORM + sessions threaded through every layer.**
   `WorkflowEngine.__init__(self, session)` and friends assume an
   ambient unit-of-work. Go idiom: explicit repository interfaces with
   `context.Context` and short-lived transactions; pass repositories,
   not sessions.

2. **Pydantic models doing double duty as DTOs and validation.**
   Schemas in `schemas/` are FastAPI request/response shapes *and* the
   normalisation layer. In Go these split into struct tags
   (`json:"..."`) for transport and explicit validation functions or
   `go-playground/validator` for rules.

3. **`asyncio` everywhere.** Every collector is `async def run(ctx)`;
   `JobQueue` uses `asyncio.Queue`; the API is FastAPI's event loop.
   Go has no async/await — it has goroutines. The mapping is:
   `asyncio.Queue` → buffered channel; `async def run` → `func Run(ctx
   context.Context, …) error`; `asyncio.gather` → `errgroup.Group`.
   Beware that Python's "1 worker on SQLite" workaround disappears: in
   Go we'd serialize writes via a single goroutine, not by capping
   concurrency.

4. **Dynamic collector registration via subclass import side-effects.**
   `tools/builtins.py::load_builtin_collectors()` imports each module
   so each `class FooCollector(BaseCollector): ...` registers itself.
   Go has no class statement and no import side-effects in this sense.
   Use explicit registration: `scan.Register(name, Factory)` called
   from `init()` of each collector package, or — preferred — a single
   `collectors.All()` slice constructed in one place.

5. **`fnmatch.fnmatchcase` for scope patterns.** Python's `fnmatch`
   has its own glob semantics (`*` matches across dots, no anchoring).
   Go's `path.Match` matches Unix shell semantics but doesn't cross
   path separators; for domain matching we'd want a small custom
   matcher (or `doublestar`). This is where literal-translation bugs
   typically hide. The Go port (see `internal/scope/`) re-implements
   the matcher and pins behaviour with tests against the same fixtures.

6. **`ipaddress.ip_network(p, strict=False)` doing CIDR coercion.**
   Python silently turns `192.0.2.5/24` into `192.0.2.0/24`. Go's
   `netip.ParsePrefix` requires the network-aligned form. We need to
   mask manually with `Prefix.Masked()`.

7. **`urlparse` quirks.** `urlparse("admin.example.com:8080").hostname`
   returns `None`, not `"admin.example.com"`, because it treats it as
   `scheme:opaque`. Python's normaliser has a special-case for that.
   Go's `net/url.Parse` has a different set of quirks. The matcher
   in `internal/scope/` documents each one.

8. **`dataclasses` with default factories.** `EntityFact`,
   `RelationFact`, etc. use `field(default_factory=dict)`. In Go you
   just declare `map[string]any` fields — but you must initialise them
   before `json.Marshal` or you get `null` instead of `{}`. Affects
   API response shape parity.

9. **`enum.Enum(str, ...)` instances comparing equal to strings.**
   `PhaseState.SCOPE == "scope"` is `True`. Go enums are typed
   constants; conversion is explicit. Don't auto-stringify; choose a
   convention (`(p PhaseState) String() string`) and stick to it.

10. **Pickle-free but JSON-soup attributes.** `entities.attributes`,
    `runs.parameters`, `evidence.payload` are all `JSON` columns
    holding arbitrary dicts. Go has no `dict[str, Any]`; use
    `map[string]any` at boundaries and named structs anywhere the
    shape is known. The merging logic in
    `_merge_attributes` (lists union, scalars prefer existing) must be
    re-implemented carefully — see ported code's required tests.

11. **In-process `events.py` pub/sub via module globals.**
    `get_event_bus()` returns a module-level singleton.
    Module globals translate badly. Use a `*Bus` carried by the
    application root and injected.

12. **`asyncio` cancellation == cooperative.** Collectors check no
    explicit cancellation token; the runtime cancels their tasks. In
    Go, `context.Context` is the cancellation token and every blocking
    call (HTTP, subprocess wait, DB query) must observe it.

13. **The CLI uses `argparse` with mutated `argparse.Namespace`
    objects.** Port as `cobra` (idiomatic) or `flag` with subcommand
    dispatch. Resist the urge to mirror the function-per-subcommand
    layout literally; let Go's package structure drive it.

14. **`pyproject.toml` optional extras.** `[msf]`, `[ai]`, `[pdf]`
    are runtime-optional. In Go this is build tags or just separate
    binaries / sub-packages that are nil-checked at runtime.

15. **PyInstaller / Tauri shell bundling.** Lantern ships as a desktop
    bundle. Go produces a single static binary — much simpler — and
    the Tauri shell can call the Go binary the same way it currently
    calls the Python entry point.

---

## 4. Proposed idiomatic Go architecture

Layout (`internal/` for everything not exported, `cmd/` per binary):

```
golantern/
├── cmd/
│   ├── golantern/        # main CLI; subcommands: serve, run, projects, …
│   └── golantern-worker/ # (later) standalone worker if we outgrow in-proc
├── internal/
│   ├── project/          # Project + ScopeRule domain types (pure, no DB)
│   ├── scope/            # ScopePolicy, normalization, matcher (FIRST PORT)
│   ├── entity/           # Entity, EntityKind, Relation, RelationKind
│   ├── fact/             # EntityFact, RelationFact, EvidenceFact, FindingFact
│   ├── run/              # Run, ToolExecution, status machine
│   ├── workflow/         # Phase graph, modes, engine
│   ├── scan/             # Collector interface, registry, runner, context
│   │   └── collectors/   # one sub-package per external tool
│   ├── jobs/             # In-process queue over channels
│   ├── events/           # Event bus (channel fan-out)
│   ├── audit/            # Audit log writer
│   ├── report/           # Aggregation + html/pdf/csv/docx renderers
│   ├── store/            # Persistence: interfaces + sqlite/pg impls
│   │   ├── sqlite/
│   │   └── pg/
│   ├── artifact/         # Blob store; lantern:// URI scheme
│   ├── api/              # HTTP handlers, OpenAPI definitions
│   ├── config/           # Env-var loading
│   └── subprocess/       # External CLI invocation w/ context + timeouts
├── migrations/           # Plain .sql files (golang-migrate)
├── api/openapi.yaml      # Generated/maintained spec
├── docs/
└── go.mod
```

Key design choices:

* **HTTP framework: `net/http` + `chi`**, not a framework that hides
  the request lifecycle. FastAPI's "depends" magic is more trouble than
  it's worth in Go; explicit middleware is fine.
* **DB: `database/sql` + `sqlc` or `pgx` + small handwritten
  repositories.** No ORM. Repositories live in `internal/store/<dialect>/`
  and implement interfaces declared next to the domain
  (`run.Repository`, `entity.Repository`, …).
* **Migrations: plain SQL files + `golang-migrate`.** Alembic
  autogenerate is irrelevant once the ORM is gone.
* **Validation: handwritten in constructors.** The domain types own
  their invariants (`NewScopePolicy(...)` returns an error if rules
  conflict). Transport-level validation is shallow.
* **Concurrency: explicit goroutines under an `errgroup.Group`,
  contexts everywhere, channels for the job queue.** No global
  worker pool. The queue owns its workers; `Shutdown(ctx)` waits.
* **Errors: sentinel errors at module boundaries**
  (`scope.ErrOutOfScope`, `workflow.ErrPrereqUnmet`), wrapped with
  `%w`. No exceptions to translate.
* **Logging: `log/slog`.** Structured, stdlib, no dependency churn.
* **Testing: stdlib `testing` + table tests.** No pytest-isms; Go's
  `t.Run` subtests are enough.
* **Domain types pure.** `internal/scope/`, `internal/project/`,
  `internal/run/`, etc. import nothing from `internal/store/` —
  repositories live behind interfaces declared in the domain
  package. This breaks SQLAlchemy's omnipresence.

---

## 5. Phased migration plan (Python and Go coexist)

The goal is a long, boring transition where the Tauri GUI and existing
operators never see breakage. We keep the Python server running and
peel modules out into Go behind shared HTTP / data contracts.

### Coexistence contract

* **Single shared SQLite/Postgres database.** Both Python and Go read
  and write the same tables. No second schema. Migrations live in one
  place — once Go is authoritative for migrations, Python uses
  `alembic stamp head` and stops applying any.
* **HTTP is the integration seam.** During migration, the Go binary
  runs alongside `lantern serve` and either:
  * fronts Python via reverse proxy and serves only the paths it has
    ported (strangler-fig pattern), or
  * is mounted under a sub-path (`/v2/...`) while the SPA migrates
    endpoint-by-endpoint.
* **No shared in-process state.** Event bus / job queue are
  per-process during migration; once the Go worker exists, Python
  enqueues by INSERTing a row that Go picks up. (A `jobs` table is
  introduced specifically to bridge this.)

### Phases

**Phase 0 — Skeleton (this commit).**
* `go.mod`, `docs/ARCHITECTURE.md` (this file), folder layout.
* First domain module ported with tests: `internal/scope/`.
* No binary yet — just the library.

**Phase 1 — Pure domain types in Go.**
Port modules that have *zero* I/O: scope (done), project, run,
entity/fact, workflow/phases, workflow/modes. Each gets exhaustive
tests against the Python behaviour fixtures. Still no DB, no HTTP. The
Python service is untouched. Deliverable: a Go library that another
service could consume.

**Phase 2 — Read-side parity behind a Go HTTP server.**
Stand up `cmd/golantern serve` reading the same DB the Python service
writes. Implement only GET endpoints (projects list, project show,
runs list, entities list, scope test). Repositories in
`internal/store/sqlite/`. SPA can optionally call Go for reads to
verify correctness. Python remains authoritative.

**Phase 3 — Write-side parity for one slice.**
Port one vertical slice end-to-end: **scope rules CRUD**. Go owns
`/api/v1/projects/{id}/scope-rules*` writes; Python proxies them
through. Audit-log writes go through the Go audit package and land in
the same `audit_logs` table. Once stable, repeat for project CRUD,
then run creation.

**Phase 4 — Scan engine in Go.**
The biggest module. Port `BaseCollector` and `CollectorRunner` first
with the small set of collectors that have no external CLI dependency
(httpx-style HTTP probers, fixtures, OSINT fetchers via `net/http`).
External-tool wrappers (nmap, nuclei, …) get ported one by one — each
wraps `internal/subprocess` and parses the tool's text/XML/JSON
output. Python collectors are removed as their Go equivalents land.

**Phase 5 — Task queue in Go.**
Replace `asyncio.Queue` with a `jobs` table + Go worker pool. Both
Python (during the overlap) and Go can enqueue; only Go dequeues.
Concurrency is now real, so the SQLite-clamp-to-1 trick is replaced
by a single write goroutine on SQLite or a switch to Postgres.

**Phase 6 — Reporting + assistant.**
HTML / CSV are easy ports. PDF moves to `chromedp` or `gotenberg`
(WeasyPrint has no good Go equivalent). DOCX uses `unidoc` or a
template-based renderer. Assistant integration is rewritten against
the Anthropic Go SDK.

**Phase 7 — Decommission Python.**
Drop the FastAPI service. Update the Tauri shell to launch the Go
binary. Final cleanup: remove the bridge `jobs` table column that
distinguished producers, drop Python migrations, archive
`src/lantern/`.

### Rollback strategy

Every phase is reversible because both implementations talk to the
same DB and the same HTTP contracts. If a Go endpoint regresses we
flip the reverse-proxy rule back to Python; the data stays consistent.

---

## 6. First module ported: `internal/scope/`

Picked first because:

* No DB, no HTTP, no external process — pure logic.
* Foundational: every collector calls `is_allowed` / `require`. The
  Go implementation can be exercised by a CLI subcommand (`golantern
  scope test`) without standing up the rest of the stack.
* High-risk for literal-port bugs (`fnmatch` semantics, IP coercion,
  URL host extraction) — exactly the place we want tests in first.

See `internal/scope/scope.go` and `internal/scope/scope_test.go`.
The test suite mirrors `tests/test_workflow_scope.py` plus extra
table-tests for the Python quirks called out in §3.
