import { useState } from 'react'
import { useAppStore } from '../store/appStore'
import { activateLicense, startTrial } from '../ipc'
import WolfMark from './WolfMark'
import DevSkip from './DevSkip'

export default function SplashScreen() {
  const setGate = useAppStore((s) => s.setGate)
  const setLicenseResult = useAppStore((s) => s.setLicenseResult)
  const isDevMode = useAppStore((s) => s.isDevMode)

  const [key, setKey] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleStartTrial = async () => {
    setLoading(true)
    setError('')
    const result = await startTrial()
    setLicenseResult(result)
    setLoading(false)
    setGate('examiner')
  }

  const handleActivate = async () => {
    if (!key.trim()) {
      setError('Enter a license key')
      return
    }
    setLoading(true)
    setError('')
    const result = await activateLicense(key.trim())
    if (result.valid) {
      setLicenseResult(result)
      setLoading(false)
      setGate('examiner')
    } else {
      setError(result.error ?? 'Invalid license')
      setLoading(false)
    }
  }

  const hasKey = key.trim().length > 0

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background:
          'radial-gradient(ellipse 55% 45% at 50% 38%, #161616 0%, #0a0a0a 100%)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      {/* Brand block */}
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <div
          style={{
            animation: 'wolfPulse 700ms ease-out forwards',
            opacity: 0,
          }}
        >
          <WolfMark size={128} />
        </div>

        <div
          style={{
            marginTop: 22,
            fontSize: 56,
            fontWeight: 700,
            letterSpacing: '0.28em',
            color: '#f0f0f0',
            animation: 'gateFade 500ms 200ms ease-out forwards',
            opacity: 0,
          }}
        >
          STRATA
        </div>

        <div
          style={{
            marginTop: 8,
            fontSize: 14,
            color: '#606060',
            letterSpacing: '0.14em',
            animation: 'gateFade 500ms 350ms ease-out forwards',
            opacity: 0,
          }}
        >
          Forensic Intelligence Platform
        </div>

        <div
          style={{
            marginTop: 5,
            fontSize: 11,
            color: '#303030',
            letterSpacing: '0.06em',
            animation: 'gateFade 500ms 450ms ease-out forwards',
            opacity: 0,
          }}
        >
          v0.4.0 {'\u00B7'} Wolfmark Systems
        </div>
      </div>

      {/* Divider */}
      <div
        style={{
          margin: '32px 0',
          width: 400,
          height: 1,
          background:
            'linear-gradient(to right, transparent, #282828, transparent)',
          animation: 'gateFade 500ms 500ms ease-out forwards',
          opacity: 0,
        }}
      />

      {/* License section */}
      <div
        style={{
          width: 420,
          display: 'flex',
          flexDirection: 'column',
          animation: 'gateFade 500ms 600ms ease-out forwards',
          opacity: 0,
        }}
      >
        <div
          style={{
            fontSize: 10,
            color: '#606060',
            textTransform: 'uppercase',
            letterSpacing: '0.14em',
            textAlign: 'center',
            marginBottom: 8,
          }}
        >
          License Key
        </div>

        <input
          type="text"
          value={key}
          onChange={(e) => {
            setKey(e.target.value)
            setError('')
          }}
          placeholder="STRATA-XXXX-XXXX-XXXX-XXXX"
          style={{
            width: '100%',
            height: 46,
            background: '#111111',
            borderStyle: 'solid',
            borderWidth: 1,
            borderColor: error ? 'var(--flag)' : '#282828',
            borderRadius: 'var(--radius-md)',
            padding: '0 18px',
            color: '#b0b0b0',
            fontSize: 13,
            fontFamily: 'monospace',
            textAlign: 'center',
            letterSpacing: '0.04em',
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
        />

        <div
          style={{
            fontSize: 11,
            color: 'var(--flag)',
            textAlign: 'center',
            minHeight: 18,
            marginTop: 4,
          }}
        >
          {error}
        </div>

        <button
          onClick={handleStartTrial}
          disabled={loading}
          style={{
            marginTop: 10,
            width: '100%',
            height: 48,
            background: '#e8e8e8',
            color: '#0a0a0a',
            fontSize: 14,
            fontWeight: 700,
            fontFamily: 'monospace',
            letterSpacing: '0.08em',
            border: 'none',
            borderRadius: 'var(--radius-md)',
            cursor: loading ? 'not-allowed' : 'pointer',
            opacity: loading ? 0.7 : 1,
            transition: 'opacity 0.15s, background 0.15s',
          }}
          onMouseEnter={(e) => {
            if (!loading) e.currentTarget.style.background = '#d0d0d0'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = '#e8e8e8'
          }}
        >
          {loading ? 'Starting...' : '\u25B6  START 30-DAY TRIAL'}
        </button>

        <button
          onClick={handleActivate}
          disabled={loading}
          style={{
            marginTop: 8,
            width: '100%',
            height: 42,
            background: 'transparent',
            color: hasKey ? '#e8e8e8' : '#606060',
            borderStyle: 'solid',
            borderWidth: 1,
            borderColor: hasKey ? '#a8a8a8' : '#282828',
            borderRadius: 'var(--radius-md)',
            fontSize: 12,
            fontFamily: 'monospace',
            letterSpacing: '0.06em',
            cursor: loading ? 'not-allowed' : 'pointer',
            transition: 'all 0.15s',
          }}
        >
          {hasKey ? `Activate ${'\u2192'}` : 'Activate License Key'}
        </button>
      </div>

      {/* Footer */}
      <div
        style={{
          marginTop: 28,
          fontSize: 9,
          color: '#303030',
          letterSpacing: '0.06em',
          textAlign: 'center',
          animation: 'gateFade 500ms 750ms ease-out forwards',
          opacity: 0,
        }}
      >
        {'\u00A9'} 2026 Wolfmark Systems {'\u00B7'} All Rights Reserved
      </div>

      {isDevMode && <DevSkip onClick={() => setGate('examiner')} />}
    </div>
  )
}
