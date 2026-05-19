# GoLantern

A Go port of [Lantern](https://github.com/silvance/Lantern), the workflow
engine for limited cyber vulnerability assessment (LCVA) and OSINT-driven
attack-surface discovery. Same data model, same scope-rule semantics,
same audit invariants — running natively as a single static binary.

See `docs/ARCHITECTURE.md` for the design analysis and migration plan.

## What you get

- HTTP API at `:8000` covering projects, scope rules, runs, scan
  results, audit log, and reports.
- 21 working collectors spanning every workflow phase (OSINT → Asset
  Discovery → Validation → Exposure → Enrichment). See
  `docs/COLLECTORS.md` for the full list and the documented set of
  Python collectors GoLantern deliberately doesn't port.
- In-process scan queue with N workers. Scan output is persisted; a
  server restart keeps your data.
- Server-Sent Events stream at `/api/v1/runs/{id}/events` for live run
  progress.
- HTML / CSV / JSON report renderer.
- SQLite backend with the same on-disk schema Lantern's Python service
  uses, so the two can share a database during migration.

---

## Installing

### What you need

- **Go 1.25 or newer.** That's the only dependency. The SQLite driver
  is pure Go (`modernc.org/sqlite`), so there's no C compiler, no
  CGO, no system SQLite library to install.

  Check your version:
  ```
  go version
  ```
  If that command says "command not found" or shows an older version,
  grab the latest from [go.dev/dl](https://go.dev/dl/) and follow the
  installer for your OS. On Linux, the official tarball into
  `/usr/local/go` plus `export PATH=$PATH:/usr/local/go/bin` is enough.

- **Git** if you're cloning the repo. Many systems already have it.

That's all. No database server, no Python, nothing else.

### Option A: clone and build (recommended for development)

```sh
git clone https://github.com/silvance/golantern.git
cd golantern
go build -o golantern ./cmd/golantern
./golantern help
```

`go build` reads `go.sum` and downloads dependencies on first run
(takes about 30s on a clean machine). The resulting `golantern` binary
is fully self-contained: you can copy it to another box and run it
there as long as the target OS / CPU architecture matches.

### Option B: `go install` (no clone, no build directory)

```sh
go install github.com/silvance/golantern/cmd/golantern@latest
```

This drops the binary into `$(go env GOPATH)/bin/golantern`. Add that
directory to your `PATH` if you haven't already:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Cross-compiling

Want a Linux binary built on macOS, or an ARM binary built on x86?

```sh
GOOS=linux  GOARCH=amd64 go build -o golantern-linux  ./cmd/golantern
GOOS=darwin GOARCH=arm64 go build -o golantern-mac    ./cmd/golantern
```

No CGO means cross-compilation works out of the box for every
platform Go supports.

---

## Running

### Start the server

The simplest invocation:

```sh
./golantern serve
```

That binds to `127.0.0.1:8000` with an in-memory store (everything
disappears on restart — fine for a tour, useless for real work). Hit
`Ctrl-C` to stop; the queue drains gracefully.

### With persistence

Point at a SQLite file and your data survives restarts:

```sh
./golantern serve --db ./golantern.db
```

The file is created on first run with the full schema. The schema is
compatible with the Python service's, so you can also point at an
existing `lantern.db` and Go will read it.

### All flags

```sh
./golantern serve --help
```

| Flag           | Default              | What it does |
|----------------|----------------------|--------------|
| `--addr`       | `127.0.0.1:8000`     | Listen address. Use `0.0.0.0:8000` to accept LAN traffic. |
| `--db`         | (empty)              | SQLite path. Empty uses an in-memory store. |
| `--workers`    | `2`                  | Number of scan-engine workers running in parallel. |
| `--seed-demo`  | `false`              | Pre-create a demo project + scope rules + a completed OSINT run. |

### A quick demo

In one terminal:

```sh
./golantern serve --db demo.db --seed-demo
```

In another:

```sh
# What projects do we have?
curl -s localhost:8000/api/v1/projects | jq

# Grab the seeded project's ID.
PID=$(curl -s localhost:8000/api/v1/projects | jq -r '.[0].id')

# What scope rules are configured?
curl -s "localhost:8000/api/v1/projects/$PID/scope-rules" | jq

# Does scope policy allow a probe against api.acme.example?
curl -s "localhost:8000/api/v1/projects/$PID/scope/test?target=api.acme.example" | jq

# Queue a real OSINT run via the crt.sh collector against your own domain.
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"phase":"asset_discovery","tools":[{"tool":"crtsh","parameters":{"domain":"acme.example"}}]}' \
  "localhost:8000/api/v1/projects/$PID/runs"

# Render a report.
curl -s "localhost:8000/api/v1/projects/$PID/report?format=html" > report.html
open report.html   # macOS — Linux: xdg-open report.html
```

### Live event stream

Watch a run unfold in real time:

```sh
RID=...  # a run ID from POST /runs
curl -N "localhost:8000/api/v1/runs/$RID/events"
```

`-N` disables curl's output buffering so SSE frames render as they
arrive.

---

## Project structure

If you want to poke around:

```
cmd/golantern/        — main binary entry point and CLI flag parsing
internal/
  api/                — HTTP handlers (chi-free; stdlib net/http)
  audit/              — append-only audit log
  engine/             — run-level orchestrator (LoadPolicy, ExecuteRun)
  entity/             — Entity / Relation domain + canonicalization
  events/             — pub/sub event bus
  fact/               — collector-emitted DTOs + attribute merge
  finding/            — Severity / Confidence / Finding / Evidence
  jobs/               — channel-backed worker queue
  project/            — Project value type + repository interface
  report/             — bundle assembler + HTML / CSV renderers
  run/                — Run / ToolExecution + status state machine
  scan/               — Collector framework + Runner
    collectors/       — concrete collectors
      fixture/        — synthetic, for tests
      crtsh/          — certificate transparency
      emailsec/       — SPF / DMARC / DKIM / MX
      githubrepos/    — GitHub org repository enumeration
      httpxprobe/     — HTTP liveness + tech detection (wraps httpx CLI)
      nmap/           — port + service discovery (wraps the nmap CLI)
  scope/              — scope policy matcher
  subprocess/         — shared CLI invocation: timeout, BinaryNotFoundError, stderr-tail
  store/
    memory/           — in-memory repository implementations
    sqlite/           — SQLite implementations + embedded schema
  workflow/           — Phase enum, mode presets
docs/
  ARCHITECTURE.md     — analysis of the Python codebase + migration plan
```

---

## Tests

```sh
go test ./...              # full suite
go test -race ./...        # with the race detector
go test ./internal/scope   # one package
```

The suite runs offline — collectors that talk to the network use the
stdlib `httptest` server and a fake DNS resolver. Expect under 10s on
a developer laptop.

---

## Troubleshooting

**"command not found: go"** — Go isn't installed. See the
[Installing](#installing) section.

**"go: cannot find main module"** — You're outside the project
directory. `cd` into the cloned `golantern` folder before running
`go build`.

**"address already in use"** — Something else is bound to
`127.0.0.1:8000`. Pass `--addr 127.0.0.1:18080` (or any free port).

**The Python Lantern service uses my database while GoLantern is
running** — that's expected and supported. Both services write the
same enum values and respect the same constraints. Schema migrations
are still driven from Python (Alembic); GoLantern's `IF NOT EXISTS`
bootstraps just ensure a fresh DB has the tables it needs.
