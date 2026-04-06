import EmptyState from '../components/EmptyState'

export default function ArtifactsView() {
  return (
    <EmptyState
      icon={"\u{1F5C2}"}
      title="Artifact Analysis"
      subtitle="Run plugins to discover artifacts"
    />
  )
}
