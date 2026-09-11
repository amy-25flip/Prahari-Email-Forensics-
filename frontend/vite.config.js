import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
// Backend runs on 8010, not 8000: 8000 is reserved for Splunk's own web UI when
// running the local live-SIEM-demo setup (see backend/serve_local.py).
export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:8010' } },
})
