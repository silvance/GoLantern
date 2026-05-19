// Tiny placeholder UI. Just enough to verify the webview / browser
// reaches the GoLantern backend. A real SPA replaces this dist/
// wholesale; this file's value is "stop here and write fetch
// wrappers, not in component code."
//
// The API lives at the same origin we were served from. When the Go
// binary serves this dist/ itself that's "http://127.0.0.1:<port>";
// the Tauri shell preserves the same equivalence by pointing the
// webview at the backend port via the sidecar. Either way, relative
// URLs would also work — we keep the absolute form so the Network
// tab shows the backend explicitly.

const API_BASE = window.location.origin;
document.getElementById("api-base").textContent = API_BASE;

async function call(path, opts = {}) {
  const resp = await fetch(API_BASE + path, opts);
  const text = await resp.text();
  return { status: resp.status, body: text };
}

document.getElementById("probe-btn").addEventListener("click", async () => {
  const out = document.getElementById("probe-out");
  out.textContent = "...";
  try {
    const r = await call("/healthz");
    out.textContent = `HTTP ${r.status}\n${r.body}`;
  } catch (err) {
    out.textContent = "ERROR: " + err.message;
  }
});

async function loadProjects() {
  const ul = document.getElementById("project-list");
  const sel = document.getElementById("artifact-project");
  ul.innerHTML = "<li>loading...</li>";
  try {
    const r = await call("/api/v1/projects");
    if (r.status !== 200) {
      ul.innerHTML = `<li>HTTP ${r.status}: ${r.body}</li>`;
      return;
    }
    const projects = JSON.parse(r.body);
    if (!projects.length) {
      ul.innerHTML = `<li><em>No projects yet. Create one via <code>POST /api/v1/projects</code>.</em></li>`;
      sel.innerHTML = `<option value="">(no projects)</option>`;
      return;
    }
    ul.innerHTML = "";
    sel.innerHTML = "";
    for (const p of projects) {
      const li = document.createElement("li");
      li.textContent = `${p.name} (${p.mode}, default_scope=${p.default_scope})`;
      ul.appendChild(li);
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = p.name;
      sel.appendChild(opt);
    }
    // Auto-load the first project's artifacts so the panel has
    // something to show without a second click.
    if (projects.length > 0) {
      loadArtifacts();
    }
  } catch (err) {
    ul.innerHTML = `<li>ERROR: ${err.message}</li>`;
  }
}

async function loadArtifacts() {
  const grid = document.getElementById("artifact-grid");
  const status = document.getElementById("artifact-status");
  const sel = document.getElementById("artifact-project");
  const projectId = sel.value;
  grid.innerHTML = "";
  if (!projectId) {
    status.textContent = "Select a project to see its artifacts.";
    return;
  }
  status.textContent = "loading...";
  try {
    const r = await call(`/api/v1/projects/${encodeURIComponent(projectId)}/artifacts`);
    if (r.status === 501) {
      status.textContent = "Artifact storage is not configured on this server. Restart with --artifacts-dir.";
      return;
    }
    if (r.status !== 200) {
      status.textContent = `HTTP ${r.status}: ${r.body}`;
      return;
    }
    const rows = JSON.parse(r.body);
    if (!rows.length) {
      status.textContent = "No artifacts yet. Run a gowitness collector to capture screenshots.";
      return;
    }
    status.textContent = `${rows.length} artifact${rows.length === 1 ? "" : "s"}.`;
    for (const a of rows) {
      const tile = document.createElement("div");
      tile.className = "artifact-tile";
      const href = `${API_BASE}/api/v1/artifacts/${encodeURIComponent(a.id)}`;
      const isImage = (a.content_type || "").startsWith("image/");
      tile.innerHTML = `
        <a href="${href}" target="_blank" rel="noopener">
          ${isImage
            ? `<img src="${href}" alt="${escapeHTML(a.filename)}" loading="lazy">`
            : `<div class="meta">${escapeHTML(a.content_type || "binary")}</div>`}
        </a>
        <div class="meta">${escapeHTML(a.filename)}<br>${a.size_bytes} bytes</div>
      `;
      grid.appendChild(tile);
    }
  } catch (err) {
    status.textContent = "ERROR: " + err.message;
  }
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);
}

document.getElementById("reload-projects").addEventListener("click", loadProjects);
document.getElementById("reload-artifacts").addEventListener("click", loadArtifacts);
document.getElementById("artifact-project").addEventListener("change", loadArtifacts);
loadProjects();
