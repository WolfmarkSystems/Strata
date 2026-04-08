import { useState, useEffect } from 'react'
import { useAppStore } from '../store/appStore'
import { listDrives, selectEvidenceDrive } from '../ipc'
import type { DriveInfo } from '../ipc'
import GateBackground from './GateBackground'
import DevSkip from './DevSkip'

export default function DriveSelection() {
  const setGate = useAppStore((s) => s.setGate)
  const setSelectedDrive = useAppStore((s) => s.setSelectedDrive)
  const isDevMode = useAppStore((s) => s.isDevMode)

  const [drives, setDrives] = useState<DriveInfo[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const loadDrives = async () => {
    setLoading(true)
    const result = await listDrives()
    setDrives(result)
    setLoading(false)
  }

  useEffect(() => {
    loadDrives()
  }, [])

  const selectedDrive = drives.find((d) => d.id === selectedId)

  const handleBegin = async () => {
    if (!selectedId) return
    const path = await selectEvidenceDrive(selectedId)
    setSelectedDrive(selectedId, path)
    setGate('main')
  }

  const handleDevSkip = () => {
    setSelectedDrive(
      'drive-t7',
      '/Volumes/Wolfmark Systems Backup/cases/new-case',
    )
    setGate('main')
  }

  return (
    <GateBackground>
      <div
        style={{
          width: 520,
          background: 'var(--bg-panel)',
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: 'var(--border)',
          borderRadius: 12,
          padding: '36px 40px',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: 20 }}>
          <div
            style={{
              fontSize: 22,
              fontWeight: 700,
              color: 'var(--text-1)',
              margin: '8px 0 4px',
            }}
          >
            Select Evidence Drive
          </div>
          <div
            style={{
              fontSize: 13,
              color: 'var(--text-muted)',
              lineHeight: 1.5,
            }}
          >
            Evidence must be stored on a dedicated external drive.
            <br />
            System and boot volumes are not permitted.
          </div>
        </div>

        {/* Drive list */}
        <div style={{ marginBottom: 4 }}>
          {loading ? (
            <div
              style={{
                textAlign: 'center',
                padding: 20,
                color: 'var(--text-muted)',
                fontSize: 12,
              }}
            >
              Loading drives...
            </div>
          ) : (
            drives.map((drive) => (
              <DriveRow
                key={drive.id}
                drive={drive}
                selected={selectedId === drive.id}
                onClick={() => {
                  if (drive.is_permitted) setSelectedId(drive.id)
                }}
              />
            ))
          )}
        </div>

        <button
          onClick={loadDrives}
          style={{
            background: 'transparent',
            color: 'var(--text-muted)',
            borderStyle: 'solid',
            borderWidth: 1,
            borderColor: 'var(--border)',
            borderRadius: 4,
            padding: '5px 12px',
            fontSize: 11,
            fontFamily: 'monospace',
            cursor: 'pointer',
            alignSelf: 'flex-start',
          }}
        >
          {'\u21BB'} Refresh Drives
        </button>

        {/* Evidence path preview */}
        {selectedDrive && (
          <div
            style={{
              fontSize: 11,
              color: 'var(--text-muted)',
              fontFamily: 'monospace',
              marginTop: 12,
            }}
          >
            Evidence Path: {selectedDrive.mount_point}/cases/new-case
          </div>
        )}

        <button
          onClick={handleBegin}
          disabled={!selectedId}
          style={{
            height: 46,
            marginTop: 20,
            background: selectedId
              ? 'linear-gradient(135deg, #c8d8e8 0%, #d8e2ec 50%, #c8d8e8 100%)'
              : 'var(--bg-elevated)',
            color: selectedId ? '#070809' : 'var(--text-off)',
            fontSize: 14,
            fontWeight: 700,
            fontFamily: 'monospace',
            letterSpacing: '0.06em',
            border: 'none',
            borderRadius: 6,
            cursor: selectedId ? 'pointer' : 'not-allowed',
            transition: 'opacity 0.15s',
          }}
        >
          Begin Examination {'\u2192'}
        </button>

        <div
          onClick={() => setGate('examiner')}
          style={{
            textAlign: 'center',
            marginTop: 12,
            fontSize: 11,
            color: 'var(--text-muted)',
            cursor: 'pointer',
          }}
        >
          {'\u2190'} Back to examiner profile
        </div>
      </div>

      {isDevMode && <DevSkip onClick={handleDevSkip} />}
    </GateBackground>
  )
}

function DriveRow({
  drive,
  selected,
  onClick,
}: {
  drive: DriveInfo
  selected: boolean
  onClick: () => void
}) {
  const [hover, setHover] = useState(false)
  const permitted = drive.is_permitted

  let bg = 'var(--bg-elevated)'
  let borderColor = 'var(--border)'
  if (!permitted) {
    bg = 'var(--bg-panel)'
  } else if (selected) {
    bg = 'var(--bg-elevated)'
    borderColor = 'var(--accent-2)'
  } else if (hover) {
    borderColor = 'var(--accent-muted)'
  }

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => permitted && setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        padding: '12px 14px',
        borderRadius: 6,
        borderStyle: 'solid',
        borderWidth: 1,
        borderColor,
        marginBottom: 8,
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        cursor: permitted ? 'pointer' : 'not-allowed',
        transition: 'all 0.15s',
        background: bg,
        opacity: permitted ? 1 : 0.6,
      }}
    >
      <div style={{ fontSize: 20 }}>
        {drive.is_system ? '\u{1F5A5}' : '\u{1F4BF}'}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: 13,
            fontWeight: 700,
            color: 'var(--text-2)',
          }}
        >
          {drive.name} {'\u2014'} {drive.free_gb.toFixed(0)} GB / {drive.total_gb.toFixed(0)} GB free
        </div>
        <div
          style={{
            fontSize: 10,
            fontFamily: 'monospace',
            color: 'var(--text-muted)',
            marginTop: 2,
          }}
        >
          {drive.mount_point}
        </div>
        {!permitted && drive.reason && (
          <div
            style={{
              fontSize: 11,
              color: 'var(--flag)',
              marginTop: 2,
            }}
          >
            {drive.reason}
          </div>
        )}
      </div>
      <div style={{ flexShrink: 0 }}>
        {permitted && selected && (
          <span style={{ color: 'var(--clean)', fontSize: 16 }}>{'\u2713'}</span>
        )}
        {!permitted && (
          <span style={{ color: 'var(--flag)', fontSize: 14 }}>{'\u2717'}</span>
        )}
      </div>
    </div>
  )
}
