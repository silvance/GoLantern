import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// Build output goes straight into ../dist (committed) so the Go
// binary's //go:embed directive at desktop/embed.go picks it up
// without any cross-directory copy step.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    // Inline asset threshold low so big SVGs / icons end up as files,
    // not base64 in JS — easier to debug and cheaper to cache.
    assetsInlineLimit: 4096,
    sourcemap: false,
  },
  server: {
    // `npm run dev` proxies API calls through to the Go backend, so
    // the SPA dev-server lives at :5173 while the API runs at :8000.
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/healthz": "http://127.0.0.1:8000",
    },
  },
});
