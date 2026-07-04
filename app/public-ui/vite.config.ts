import { defineConfig } from 'vite'
import babel from '@rolldown/plugin-babel'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Default proxy target matches DEV_API_PORT in src-tauri/src/server/mod.rs.
// NOTE: This proxy is ONLY used as a fallback — the primary 'cargo tauri dev'
// flow uses Tauri IPC (get_api_port command) to discover the real backend port
// dynamically, so it works even if the backend falls back to an ephemeral port.
// Override via VITE_API_BASE if running plain-browser Vite dev (pnpm dev opened
// directly in a browser tab) AND the backend fell back to an ephemeral port
// (e.g., 3737 was already in use). Example: VITE_API_BASE=http://127.0.0.1:54321
const apiTarget = process.env.VITE_API_BASE || 'http://127.0.0.1:3737'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const enableReactCompiler = mode === 'compiler'

  return {
    plugins: [
      react(),
      tailwindcss(),
      ...(enableReactCompiler
        ? [
            babel({
              plugins: [['babel-plugin-react-compiler', {}]],
            }),
          ]
        : []),
    ],
    build: {
      // Audit L-UI-1: don't ship sourcemaps in the production Tauri bundle.
      // The webview is offline-only in normal use, but the bundle is also
      // checked into the Tauri resource glob and would otherwise let any
      // process with read access to the install dir reconstruct the original
      // TypeScript source (including key-handling code paths).
      sourcemap: false,
    },
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: {
        '/health': apiTarget,
        '/auth': apiTarget,
        '/ingest': apiTarget,
        '/datasets': apiTarget,
        '/key': apiTarget,
        '/v1': apiTarget,
        '/zk': apiTarget,
        '/redaction': apiTarget,
        '/admin': apiTarget,
        '/api': apiTarget,
        '/credentials': apiTarget,
      },
    },
  }
})
