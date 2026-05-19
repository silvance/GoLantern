// Package desktop embeds the placeholder SPA bundle so the Go API
// server can serve it at /. Embedding lives next to the dist/ tree
// because //go:embed paths can't traverse parent directories.
//
// The same bundle is what the Tauri shell ships; serving it from the
// Go binary as well means `golantern serve` opens a useable browser
// UI without a separate static-file step, and removes the surprise
// of getting "404 page not found" at the root URL.
//
// When the real SPA replaces desktop/dist wholesale, this file
// keeps working: the embed directive picks up whatever is in dist/
// at build time.
package desktop

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var files embed.FS

// FS returns the embedded SPA bundle rooted at index.html.
func FS() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		// The embed directive ensures dist/ exists at build time;
		// reaching this is a build-invariant violation, not a runtime
		// condition.
		panic("desktop: embedded dist subtree missing: " + err.Error())
	}
	return sub
}

// Handler returns an http.Handler that serves the embedded SPA.
// "/" resolves to index.html; static assets resolve under /assets/*.
// Unknown paths return 404 — we deliberately do NOT SPA-fallback
// every miss to index.html, because that would mask real 404s from
// the API layer.
func Handler() http.Handler {
	return http.FileServerFS(FS())
}
