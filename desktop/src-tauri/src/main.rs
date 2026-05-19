// GoLantern desktop shell entrypoint.
//
// The shell's job is small and well-defined:
//   1. Spawn the GoLantern backend as a child process (sidecar).
//   2. Wait for it to become reachable on its loopback port.
//   3. Open the main webview pointed at the bundled frontend, which
//      talks to the backend over loopback HTTP.
//   4. Tear the backend down cleanly when the window closes or the
//      app exits.
//
// All product logic lives in the Go backend; this binary is
// intentionally thin so changes to the analyst experience don't
// require rebuilding native code.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod sidecar;

use anyhow::Result;
use std::sync::Arc;
// `Manager` is the trait that exposes `app_handle()` on Window;
// without it in scope, the field is invisible to user code.
use tauri::Manager;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use sidecar::SidecarHandle;

/// Shared state held by Tauri so the sidecar lives for the app lifetime.
struct AppState {
    sidecar: Arc<Mutex<Option<SidecarHandle>>>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let sidecar = runtime.block_on(async { sidecar::spawn().await })?;

    let state = AppState {
        sidecar: Arc::new(Mutex::new(Some(sidecar))),
    };

    tauri::Builder::default()
        .manage(state)
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let app_handle = window.app_handle().clone();
                let state: tauri::State<AppState> = app_handle.state();
                let sidecar = state.sidecar.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(handle) = sidecar.lock().await.take() {
                        if let Err(err) = handle.shutdown().await {
                            tracing::warn!(?err, "sidecar shutdown reported error");
                        }
                    }
                });
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to run GoLantern desktop");

    Ok(())
}
