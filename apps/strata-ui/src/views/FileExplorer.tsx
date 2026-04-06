import EmptyState from '../components/EmptyState'

export default function FileExplorer() {
  return (
    <EmptyState
      icon={"\u{1F4C1}"}
      title="File Explorer"
      subtitle="Load evidence to begin"
      hint="Click + Open Evidence in the top bar"
    />
  )
}
