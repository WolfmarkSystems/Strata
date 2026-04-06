import { useEffect, useCallback } from 'react'
import { useAppStore } from '../store/appStore'
import PluginCard from '../components/PluginCard'
import PluginDetailPane from '../components/PluginDetailPane'
import { runPlugin, runAllPlugins, onPluginProgress, getPluginStatuses } from '../ipc'
import { PLUGIN_DATA } from '../types'

export default function PluginsView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const selectedPlugin = useAppStore((s) => s.selectedPluginId)
  const setSelectedPlugin = useAppStore((s) => s.setSelectedPlugin)
  const pluginStatuses = useAppStore((s) => s.pluginStatuses)
  const setPluginStatus = useAppStore((s) => s.setPluginStatus)
  const setStats = useAppStore((s) => s.setStats)

  // Load initial statuses on mount
  useEffect(() => {
    getPluginStatuses().then((statuses) => {
      statuses.forEach((s) => setPluginStatus(s.name, s))
    })
  }, [setPluginStatus])

  // Listen for plugin progress events
  useEffect(() => {
    const unlistenPromise = onPluginProgress((data) => {
      setPluginStatus(data.name, {
        name: data.name,
        status: data.status,
        progress: data.progress,
        artifact_count: data.artifact_count ?? 0,
      })
    })
    return () => {
      unlistenPromise.then((fn) => fn())
    }
  }, [setPluginStatus])

  // Roll up artifacts total into stats
  useEffect(() => {
    const total = Object.values(pluginStatuses).reduce(
      (sum, s) => sum + (s.status === 'complete' ? s.artifact_count : 0),
      0,
    )
    setStats({ artifacts: total })
  }, [pluginStatuses, setStats])

  const handleRun = useCallback(
    async (pluginName: string) => {
      if (!evidenceId) return
      setPluginStatus(pluginName, {
        name: pluginName,
        status: 'running',
        progress: 0,
        artifact_count: 0,
      })
      await runPlugin(pluginName, evidenceId)
    },
    [evidenceId, setPluginStatus],
  )

  const handleRunAll = useCallback(async () => {
    if (!evidenceId) return
    await runAllPlugins(evidenceId)
  }, [evidenceId])

  const selectedPluginData = PLUGIN_DATA.find((p) => p.name === selectedPlugin) ?? null
  const selectedStatus = selectedPlugin ? pluginStatuses[selectedPlugin] : undefined

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        flex: 1,
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '10px 16px',
          borderBottom: '1px solid var(--border-sub)',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          flexShrink: 0,
          background: 'var(--bg-surface)',
        }}
      >
        <span
          style={{
            fontSize: 13,
            fontWeight: 700,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            color: 'var(--text-2)',
          }}
        >
          Analysis Plugins
        </span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>11 plugins</span>
        <button
          onClick={handleRunAll}
          disabled={!evidenceLoaded}
          style={{
            marginLeft: 8,
            padding: '5px 12px',
            background: evidenceLoaded ? 'var(--bg-elevated)' : 'transparent',
            border: '1px solid var(--border)',
            borderRadius: 4,
            color: evidenceLoaded ? 'var(--text-2)' : 'var(--text-off)',
            fontSize: 11,
            fontFamily: 'monospace',
            fontWeight: 700,
            cursor: evidenceLoaded ? 'pointer' : 'not-allowed',
            letterSpacing: '0.06em',
          }}
        >
          RUN ALL PLUGINS
        </button>
      </div>

      {/* Body: grid + detail */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Plugin Grid */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 12 }}>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: 10,
            }}
          >
            {PLUGIN_DATA.map((plugin) => (
              <PluginCard
                key={plugin.name}
                plugin={plugin}
                status={pluginStatuses[plugin.name]}
                isSelected={selectedPlugin === plugin.name}
                onSelect={() => setSelectedPlugin(plugin.name)}
                onRun={() => handleRun(plugin.name)}
                evidenceLoaded={evidenceLoaded}
              />
            ))}
          </div>
        </div>

        {/* Detail Pane */}
        <PluginDetailPane
          plugin={selectedPluginData}
          status={selectedStatus}
          onRun={() => selectedPlugin && handleRun(selectedPlugin)}
          evidenceLoaded={evidenceLoaded}
        />
      </div>
    </div>
  )
}
