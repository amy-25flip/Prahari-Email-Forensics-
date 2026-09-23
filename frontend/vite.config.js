import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
// Backend runs on 8010, not 8000: 8000 is reserved for Splunk's own web UI when
// running the local live-SIEM-demo setup (see backend/serve_local.py).
export default defineConfig({
  plugins: [react()],
  server: { host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:8010' } },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('leaflet') || id.includes('d3-geo') || id.includes('topojson-client') || id.includes('world-atlas')) {
              return 'vendor-maps'
            }
            if (id.includes('lucide-react')) {
              return 'vendor-icons'
            }
            if (id.includes('react') || id.includes('react-dom')) {
              return 'vendor-react'
            }
            return 'vendor'
          }
        }
      }
    }
  }
})
