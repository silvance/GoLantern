// Tiny placeholder UI. Just enough to verify the Tauri webview
// reaches the GoLantern backend over loopback. A real SPA replaces
// this dist/ wholesale; this file's value is "stop here and write
// fetch wrappers, not in component code."

const API_BASE = "http://127.0.0.1:8765";
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
      return;
    }
    ul.innerHTML = "";
    for (const p of projects) {
      const li = document.createElement("li");
      li.textContent = `${p.name} (${p.mode}, default_scope=${p.default_scope})`;
      ul.appendChild(li);
    }
  } catch (err) {
    ul.innerHTML = `<li>ERROR: ${err.message}</li>`;
  }
}

document.getElementById("reload-projects").addEventListener("click", loadProjects);
loadProjects();
