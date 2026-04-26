import { useEffect, useState } from 'react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
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
    <PanelGroup
      direction="horizontal"
      style={{
        flex: 1,
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      <Panel defaultSize={18} minSize={12} maxSize={35}>
        <EvidenceTree />
      </Panel>

      <PanelResizeHandle className="resize-handle" />

      <Panel defaultSize={55} minSize={25}>
        <FileListing
          files={files}
          selectedFileId={selectedFileId}
          onFileSelect={(f) => setSelectedFile(f.id)}
        />
      </Panel>

      <PanelResizeHandle className="resize-handle" />

      <Panel defaultSize={27} minSize={18} maxSize={50}>
        <DetailPane fileId={selectedFileId} evidenceId={evidenceId} />
      </Panel>
    </PanelGroup>
  )
}
