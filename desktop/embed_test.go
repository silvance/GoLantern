package desktop_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/silvance/golantern/desktop"
)

// TestEmbedHasIndexAndAssets fails the build if the SPA dist
// regressed (forgot to run `npm run build`, or vite emitted to the
// wrong path). Catches the cycle where Go's binary serves stale
// assets because the developer changed the SPA source but didn't
// regenerate the dist.
func TestEmbedHasIndexAndAssets(t *testing.T) {
	root := desktop.FS()

	// index.html must be at the root and reference an asset script.
	b, err := fs.ReadFile(root, "index.html")
	if err != nil {
		t.Fatalf("index.html missing from embedded dist: %v", err)
	}
	html := string(b)
	if !strings.Contains(html, "<script") {
		t.Fatalf("index.html has no <script tag — did the SPA build run?")
	}
	if !strings.Contains(html, "/assets/") {
		t.Fatalf("index.html doesn't reference /assets/ — vite outDir misconfigured?")
	}

	// Walk the assets directory and assert at least one JS and one CSS
	// bundle made it in.
	var sawJS, sawCSS bool
	_ = fs.WalkDir(root, "assets", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		switch filepath.Ext(path) {
		case ".js":
			sawJS = true
		case ".css":
			sawCSS = true
		}
		return nil
	})
	if !sawJS {
		t.Error("no .js asset in embedded dist/assets")
	}
	if !sawCSS {
		t.Error("no .css asset in embedded dist/assets")
	}
}
