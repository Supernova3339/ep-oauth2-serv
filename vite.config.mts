import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  root: 'frontend',
  build: {
    outDir: '../public',
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    proxy: {
      '/api': { target: 'http://localhost:3100' },
      '/oauth': { target: 'http://localhost:3100' },
      '/login': {
        target: 'http://localhost:3100',
        bypass: (req) => req.method === 'GET' ? req.url : undefined,
      },
      '/logout': { target: 'http://localhost:3100' },
      '/twoFactor': { target: 'http://localhost:3100' },
      '/device/verify': { target: 'http://localhost:3100' },
      '/openapi.json': { target: 'http://localhost:3100' },
      '/assets': { target: 'http://localhost:3100' },
    }
  }
})
