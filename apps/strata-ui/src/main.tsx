import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

function showBootError(message: string) {
  const boot = document.getElementById('boot-msg')
  if (!boot) return
  boot.innerHTML = `
    <div style="color:#b84040;font-size:13px;font-weight:700;letter-spacing:0.15em;">
      STRATA CRASHED DURING BOOT
    </div>
    <div style="color:#e0a0a0;font-size:10px;max-width:720px;font-family:monospace;white-space:pre-wrap;text-align:left;padding:16px;background:#1a0606;border:1px solid #3a0a0a;border-radius:6px;">
      ${String(message).replace(/</g, '&lt;')}
    </div>
  `
}

window.addEventListener('error', (e) => {
  showBootError(`${e.message}\n    at ${e.filename}:${e.lineno}:${e.colno}`)
})
window.addEventListener('unhandledrejection', (e) => {
  showBootError(`Unhandled promise rejection: ${e.reason}`)
})

try {
  const rootEl = document.getElementById('root')
  if (!rootEl) throw new Error("Root element #root not found in document")
  createRoot(rootEl).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
  // Hide the boot message once React has mounted.
  const boot = document.getElementById('boot-msg')
  if (boot) boot.style.display = 'none'
} catch (err) {
  showBootError(err instanceof Error ? `${err.message}\n${err.stack ?? ''}` : String(err))
}
