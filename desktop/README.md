# GoLantern desktop shell

Tauri 2 wrapper that hosts the GoLantern backend as a sidecar process.
The shell's only responsibilities are:

1. Spawn the Go backend on startup.
2. Wait for `/healthz` to come up.
3. Open the main webview pointed at the bundled HTML frontend.
4. Tear the backend down cleanly when the window closes.

All product logic lives in the Go backend; the desktop binary stays
thin so iterating on the analyst experience never requires rebuilding
native code.

## Two execution modes

| Mode    | When                                       | Backend invocation                        |
| ------- | ------------------------------------------ | ----------------------------------------- |
| Bundled | A `golantern` binary sits next to the exe  | `golantern serve --addr ...`              |
| Dev     | No bundled binary present                  | `go run ./cmd/golantern serve --addr ...` |

The bundled-mode lookup checks `$GOLANTERN_BACKEND_BIN` (explicit
override) → `golantern(.exe)` next to the desktop binary →
`Resources/golantern` (macOS bundle layout). If none exist, the shell
falls back to `go run ./cmd/golantern serve`, which is what
`cargo tauri dev` gets for free during development as long as Go is
on `$PATH`.

## Cutover from Python

The Lantern Python codebase shipped a PyInstaller-frozen
`lantern-backend` plus a Python-interpreter dev fallback. GoLantern is
one static binary so the desktop shell is dramatically simpler:

- No PyInstaller. Build with `go build` and copy the result into
  `src-tauri/binaries/`.
- No Python interpreter resolution. The "dev fallback" is just
  `go run`, which is one binary on `$PATH` instead of the
  python / python3 / py.exe / `LANTERN_PYTHON` matrix.
- No Windows-specific WSL recommendation. Cross-compilation with
  `GOOS=windows GOARCH=amd64 go build` produces a working binary
  without any Windows-side dependencies.

If you're migrating an existing install, the only operator-facing env
var rename is:

| Lantern (Python)        | GoLantern               |
| ----------------------- | ----------------------- |
| `LANTERN_BACKEND_BIN`   | `GOLANTERN_BACKEND_BIN` |
| `LANTERN_API_HOST`      | `GOLANTERN_API_HOST`    |
| `LANTERN_API_PORT`      | `GOLANTERN_API_PORT`    |
| `LANTERN_PYTHON`        | (dropped — no interpreter) |

The default API port stays `8765` so SPA code that hardcoded that
value doesn't need changes.

## Layout

```
desktop/
├── src-tauri/                  # Rust shell
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── build.rs
│   ├── icons/                  # source.svg + generated PNG/ICO/ICNS
│   ├── binaries/               # `go build` output staged here pre-bundle
│   └── src/
│       ├── main.rs             # Entrypoint, manages window + sidecar lifetime
│       └── sidecar.rs          # Spawn/probe/shutdown of the backend process
└── dist/                       # Frontend served inside the webview
    ├── index.html              # Placeholder; real SPA lands later
    └── assets/
        ├── app.css
        └── app.js
```

## Prerequisites

- Rust stable (1.77+) and the Tauri CLI 2.x:
  `cargo install tauri-cli --version "^2.0"`
- Go 1.25+ for both bundled builds and the dev fallback.
- Linux needs WebKit + GTK build deps; see the Tauri docs for the
  current apt list (`webkit2gtk-4.1`, `librsvg2-dev`, etc.).

## Run in development

```bash
# From this directory:
cd src-tauri
cargo tauri dev
```

`cargo tauri dev` invokes `go run ./cmd/golantern serve --addr 127.0.0.1:8765`,
waits for the backend, then opens the main window pointing at
`../dist`.

### Environment overrides

| Variable                | Default        | Purpose                                     |
| ----------------------- | -------------- | ------------------------------------------- |
| `GOLANTERN_GO`          | `go`           | Go binary used for the dev fallback         |
| `GOLANTERN_BACKEND_BIN` | _unset_        | Override the bundled-binary path            |
| `GOLANTERN_API_HOST`    | `127.0.0.1`    | Backend bind host                           |
| `GOLANTERN_API_PORT`    | `8765`         | Backend bind port                           |

## Build a release bundle

```bash
# From the repo root:
go build -o desktop/src-tauri/binaries/golantern ./cmd/golantern

# Then from desktop/src-tauri:
cargo tauri build
```

Cross-compile for other platforms before bundling:

```bash
GOOS=windows GOARCH=amd64 go build -o desktop/src-tauri/binaries/golantern.exe ./cmd/golantern
GOOS=darwin  GOARCH=arm64 go build -o desktop/src-tauri/binaries/golantern     ./cmd/golantern
```

This produces a platform-native installer under
`desktop/src-tauri/target/release/bundle/`:

| Host    | Outputs                              |
| ------- | ------------------------------------ |
| Windows | `nsis/*.exe`, `msi/*.msi`            |
| macOS   | `dmg/*.dmg`, `macos/*.app`           |
| Linux   | `appimage/*.AppImage`, `deb/*.deb`   |

## What still needs work

- **Real frontend**: `dist/` is a placeholder probe page. A future
  commit replaces it with a React + Vite SPA.
- **Icons**: `icons/` is empty. Add `source.svg` and run a generator
  (or `tauri icon source.svg`) before producing a public bundle.
- **Code-signing**: `cargo tauri build` produces unsigned bundles.
  Windows users will see a SmartScreen warning; macOS users a
  Gatekeeper prompt. Sign with a real Developer ID before public
  distribution.
