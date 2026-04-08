import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Tauri serves the frontend at `tauri://localhost/`, so absolute paths work
  // natively and are the Tauri-recommended setting.
  base: '/',
  // Match the exact dev server port Tauri expects in tauri.conf.json
  server: {
    port: 5173,
    strictPort: true,
  },
  // Ship a smaller build + source maps for debugging
  build: {
    target: 'es2021',
    minify: true,
    sourcemap: true,
  },
  // Prevent Vite from trying to open a browser on dev start
  clearScreen: false,
})
