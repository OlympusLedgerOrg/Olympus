import { defineConfig } from 'vite'
import babel from '@rolldown/plugin-babel'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

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
