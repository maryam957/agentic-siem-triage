import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 1574,
    // Proxy backend calls through the dev server so the browser only ever
    // talks to localhost:1574 — avoids CORS entirely.
    proxy: {
      '/alerts': 'http://localhost:8000',
      '/review': 'http://localhost:8000',
      '/approve': 'http://localhost:8000',
      '/override': 'http://localhost:8000',
      '/reinvestigate': 'http://localhost:8000',
      '/alert': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})
