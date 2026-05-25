import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const apiTarget = process.env.VITE_API_BASE || 'http://localhost:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // Audit L-UI-1: don't ship sourcemaps in the production Tauri bundle.
    // The webview is offline-only in normal use, but the bundle is also
    // checked into the Tauri resource glob and would otherwise let any
    // process with read access to the install dir reconstruct the original
    // TypeScript source (including key-handling code paths).
    sourcemap: false,
  },
  server: {
    proxy: {
      '/auth': apiTarget,
      '/ingest': apiTarget,
      '/datasets': apiTarget,
      '/key': apiTarget,
      '/v1': apiTarget,
    },
  },
})
