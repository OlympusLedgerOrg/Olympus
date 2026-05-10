import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const apiTarget = process.env.VITE_API_BASE || 'http://localhost:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
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
