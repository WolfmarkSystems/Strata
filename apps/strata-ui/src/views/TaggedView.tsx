import EmptyState from '../components/EmptyState'

export default function TaggedView() {
  return (
    <EmptyState
      icon={"\u{1F3F7}"}
      title="Tagged Evidence"
      subtitle="Tag files during examination"
      hint="Right-click any file to add a tag"
    />
  )
}
