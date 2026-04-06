import EmptyState from '../components/EmptyState'

export default function PluginsView() {
  return (
    <EmptyState
      icon={"\u{1F50C}"}
      title="Analysis Plugins"
      subtitle="11 plugins ready"
      hint="Load evidence to enable plugins"
    />
  )
}
