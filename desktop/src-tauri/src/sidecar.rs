// Sidecar lifecycle: spawn the GoLantern backend as a child process,
// wait until /healthz reports ready, and provide a graceful shutdown
// path tied to the desktop window's close event.
//
// Two execution modes (much simpler than the Lantern Python era —
// GoLantern is one static binary, no interpreter dance):
//
//   - Bundled (release): the cross-compiled `golantern` binary ships
//     alongside the desktop executable. Invoke it directly; no Go
//     toolchain required on the user's machine.
//   - Dev fallback: when the bundled binary isn't found (typical for
//     `cargo run` against a source checkout), invoke `go run
//     ./cmd/golantern serve` instead. Requires Go on PATH.
//
// Lookup order: $GOLANTERN_BACKEND_BIN explicit override → bundled
// binary next to the desktop exe (with .exe / Resources/ variants
// for the platform layouts Tauri produces) → `go run ./cmd/golantern`.
// An explicit override always wins so packagers can point at a custom
// path during smoke tests without rebuilding.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

const DEFAULT_BACKEND_HOST: &str = "127.0.0.1";
const DEFAULT_BACKEND_PORT: u16 = 8765;
const READINESS_TIMEOUT: Duration = Duration::from_secs(20);
const READINESS_POLL: Duration = Duration::from_millis(250);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

pub struct SidecarHandle {
    child: Child,
}

impl SidecarHandle {
    /// Send the child a graceful kill and wait briefly for it to exit.
    /// On timeout we fall back to a hard kill so the desktop process
    /// can terminate without leaving an orphaned backend behind.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(id) = self.child.id() {
            tracing::info!(pid = id, "shutting down golantern sidecar");
        }
        // tokio's Child::kill is async on Unix and Windows alike; it
        // sends SIGKILL on Unix. GoLantern's `serve` handles SIGTERM
        // gracefully but tokio's cross-platform API doesn't expose
        // signal sending today; SIGKILL + WaitDelay is the best we
        // get without going OS-specific.
        let _ = self.child.start_kill();
        match timeout(SHUTDOWN_GRACE, self.child.wait()).await {
            Ok(Ok(status)) => {
                tracing::info!(?status, "sidecar exited");
                Ok(())
            }
            Ok(Err(err)) => Err(err.into()),
            Err(_) => {
                tracing::warn!("sidecar did not exit within {SHUTDOWN_GRACE:?}; forcing");
                let _ = self.child.kill().await;
                Ok(())
            }
        }
    }
}

/// Locate the bundled backend binary, if present.
///
/// In a packaged build, the cross-compiled `golantern` is placed next
/// to the desktop executable at install time. Filename varies by
/// platform (`.exe` on Windows; macOS bundles drop it under
/// `Resources/`). Returns `None` when none of the candidates exist —
/// the caller falls back to `go run` from a source checkout, which is
/// the right behavior for `cargo run` during development.
fn locate_bundled_backend() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("GOLANTERN_BACKEND_BIN") {
        let p = PathBuf::from(explicit);
        if p.exists() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidates = [
        dir.join("golantern"),
        dir.join("golantern.exe"),
        // macOS bundle layout: binaries land under Resources/.
        dir.join("Resources").join("golantern"),
    ];
    candidates.into_iter().find(|c| c.exists())
}

/// Pre-flight check: is Go on PATH? Returns the binary name we'll use
/// (defaulting to `go`). When Go is missing we produce an actionable
/// error tailored to the OS rather than letting the spawn attempt fail
/// with a generic "command not found".
async fn resolve_go() -> Result<String> {
    let candidate = std::env::var("GOLANTERN_GO").unwrap_or_else(|_| "go".to_string());
    let ok = Command::new(&candidate)
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(candidate)
    } else {
        Err(anyhow!(format_go_missing_error(&candidate)))
    }
}

fn format_go_missing_error(tried: &str) -> String {
    format!(
        "GoLantern's desktop dev mode could not find Go on PATH (tried: {tried}).\n\n\
Install Go 1.25+ from https://go.dev/dl/ and re-launch the desktop, \
or skip the toolchain entirely by building the bundled backend:\n\
  go build -o desktop/src-tauri/binaries/golantern ./cmd/golantern\n\
The bundled binary is what end-users get; the dev fallback exists \
only for source checkouts."
    )
}

pub async fn spawn() -> Result<SidecarHandle> {
    let host = std::env::var("GOLANTERN_API_HOST").unwrap_or_else(|_| DEFAULT_BACKEND_HOST.into());
    let port: u16 = std::env::var("GOLANTERN_API_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BACKEND_PORT);
    let base_url = format!("http://{host}:{port}");

    // Pre-flight: refuse to spawn when the port is already taken. A
    // stale `golantern` from a previous run that didn't shut down
    // cleanly (Ctrl-C race, crash, sigkill) can hold the port long
    // enough to fool the TCP-probe readiness check below into
    // attaching the webview to the *old* backend. Visible symptom is
    // "I rebuilt but my changes don't appear" — the new sidecar dies
    // on bind, the operator never sees an error, and the webview
    // happily talks to a zombie. Bailing here surfaces the actual
    // problem with an actionable message.
    if probe_tcp(&base_url).await {
        return Err(anyhow!(
            "port {port} on {host} is already bound. A previous golantern is \
probably still running. Stop it before relaunching:\n\n  pkill -f golantern\n\n\
Or set GOLANTERN_API_PORT to a different port if you intentionally want a \
second instance."
        ));
    }

    let mut command = if let Some(bin) = locate_bundled_backend() {
        tracing::info!(?bin, %host, port, "spawning bundled golantern backend");
        let mut c = Command::new(&bin);
        c.arg("serve")
            .arg("--addr")
            .arg(format!("{host}:{port}"));
        c
    } else {
        let go = resolve_go().await?;
        tracing::info!(
            %go, %host, port,
            "no bundled backend found; falling back to `go run`"
        );
        let mut c = Command::new(&go);
        // Run from the repo root so the relative path resolves. The
        // desktop crate sits at desktop/src-tauri; the cmd/ package
        // is two levels up.
        c.current_dir("../..");
        c.arg("run")
            .arg("./cmd/golantern")
            .arg("serve")
            .arg("--addr")
            .arg(format!("{host}:{port}"));
        c
    };
    command.kill_on_drop(true);

    let child = command
        .spawn()
        .context("failed to launch golantern backend (set RUST_LOG=info for details)")?;

    let mut handle = SidecarHandle { child };

    wait_for_ready(&base_url, &mut handle.child).await?;
    Ok(handle)
}

/// Poll until the backend's port responds or the readiness budget runs
/// out. Also watches the spawned child so a crash during startup
/// surfaces as an actionable error rather than a 20-second timeout.
async fn wait_for_ready(base_url: &str, child: &mut Child) -> Result<()> {
    let url = format!("{base_url}/healthz");
    let deadline = tokio::time::Instant::now() + READINESS_TIMEOUT;

    loop {
        // If the child has exited, no amount of probing will succeed.
        // try_wait returns Ok(Some(_)) on exit, Ok(None) while alive.
        if let Some(status) = child.try_wait()? {
            return Err(anyhow!(
                "golantern backend exited during startup with status {:?}; \
check the stderr output above for the underlying cause (common: port \
already bound, schema migration failure, missing $LANTERN_ASSISTANT_API_KEY \
when assistant is enabled)",
                status
            ));
        }
        if probe_tcp(base_url).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "golantern backend failed to become ready at {url} within {:?}",
                READINESS_TIMEOUT
            ));
        }
        sleep(READINESS_POLL).await;
    }
}

async fn probe_tcp(base_url: &str) -> bool {
    let stripped = base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let addr = match stripped.parse::<std::net::SocketAddr>() {
        Ok(addr) => addr,
        Err(_) => match stripped.split_once('/') {
            Some((host_port, _)) => match host_port.parse::<std::net::SocketAddr>() {
                Ok(a) => a,
                Err(_) => return false,
            },
            None => return false,
        },
    };
    tokio::net::TcpStream::connect(addr).await.is_ok()
}
