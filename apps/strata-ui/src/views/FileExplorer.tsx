import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'
import EvidenceTree from '../components/EvidenceTree'
import FileListing from '../components/FileListing'
import DetailPane from '../components/DetailPane'
import EmptyState from '../components/EmptyState'
import { getFiles } from '../ipc'
import type { FileEntry } from '../types'

export default function FileExplorer() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const selectedNodeId = useAppStore((s) => s.selectedNodeId)
  const selectedFileId = useAppStore((s) => s.selectedFileId)
  const setSelectedFile = useAppStore((s) => s.setSelectedFile)

  const [files, setFiles] = useState<FileEntry[]>([])

  useEffect(() => {
    if (selectedNodeId && evidenceId) {
      getFiles(selectedNodeId).then(setFiles)
    } else {
      setFiles([])
    }
  }, [selectedNodeId, evidenceId])

  if (!evidenceLoaded) {
    return (
      <EmptyState
        icon={'\u{1F4C1}'}
        title="File Explorer"
        subtitle="Load evidence to begin"
        hint="Click + Open Evidence in the top bar"
      />
    )
  }

  return (
    <div
      style={{
        display: 'flex',
        flex: 1,
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      <EvidenceTree />
      <FileListing
        files={files}
        selectedFileId={selectedFileId}
        onFileSelect={(f) => setSelectedFile(f.id)}
      />
      <DetailPane fileId={selectedFileId} />
    </div>
  )
}
