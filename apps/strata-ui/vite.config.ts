import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  // Use relative asset paths so the built index.html works under the Tauri
  // webview protocol (which doesn't always treat leading `/` as the dist root).
  base: './',
  plugins: [react()],
})
