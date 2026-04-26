import { useState, useEffect } from 'react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import { useAppStore } from '../store/appStore'
import ArtifactCategories from '../components/ArtifactCategories'
import ArtifactResults from '../components/ArtifactResults'
import ArtifactDetail from '../components/ArtifactDetail'
import EmptyState from '../components/EmptyState'
import { getArtifactCategories, getArtifacts, getFlaggedArtifacts } from '../ipc'
import type { ArtifactCategory, Artifact } from '../ipc'

export default function ArtifactsView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const evidenceId = useAppStore((s) => s.evidenceId)
  const selectedArtifactCat = useAppStore((s) => s.selectedArtifactCat)
  const setSelectedArtifactCat = useAppStore((s) => s.setSelectedArtifactCat)
  const selectedArtifactId = useAppStore((s) => s.selectedArtifactId)
  const setSelectedArtifactId = useAppStore((s) => s.setSelectedArtifactId)

  const [categories, setCategories] = useState<ArtifactCategory[]>([])
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [pluginsNotRun, setPluginsNotRun] = useState(false)
  const [loading, setLoading] = useState(false)
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const [flaggedIds, setFlaggedIds] = useState<Set<string>>(new Set())

  // Load categories when evidence loaded
  useEffect(() => {
    if (!evidenceId) {
      setCategories([])
      return
    }
    getArtifactCategories(evidenceId).then(setCategories)
    const refreshFlagged = () => getFlaggedArtifacts(evidenceId).then((notes) => {
      setFlaggedIds(new Set(notes.map((note) => note.artifact_id)))
    })
    void refreshFlagged()
    window.addEventListener('strata-artifact-note-saved', refreshFlagged)
    return () => window.removeEventListener('strata-artifact-note-saved', refreshFlagged)
  }, [evidenceId])

  // Load artifacts when category changes
  useEffect(() => {
    if (!evidenceId || !selectedArtifactCat) {
      setArtifacts([])
      setPluginsNotRun(false)
      return
    }
    setLoading(true)
    setArtifacts([])
    setPluginsNotRun(false)
    setSelectedArtifactId(null)
    getArtifacts(evidenceId, selectedArtifactCat).then((data) => {
      setArtifacts(data.artifacts)
      setPluginsNotRun(data.plugins_not_run)
      setLoading(false)
    })
  }, [selectedArtifactCat, evidenceId, setSelectedArtifactId])

  const selectedArtifact = artifacts.find((a) => a.id === selectedArtifactId) ?? null
  const selectedCategory = categories.find((c) => c.name === selectedArtifactCat) ?? null
  const visibleArtifacts = flaggedOnly
    ? artifacts.filter((artifact) => flaggedIds.has(artifact.id))
    : artifacts

  if (!evidenceLoaded) {
    return (
      <EmptyState
        icon={'\u{1F5C2}'}
        title="Artifact Analysis"
        subtitle="Load evidence and run plugins to discover artifacts"
      />
    )
  }

  return (
    <PanelGroup
      direction="horizontal"
      style={{ flex: 1, overflow: 'hidden', background: 'var(--bg-base)' }}
    >
      <Panel defaultSize={18} minSize={12} maxSize={35}>
        <ArtifactCategories
          categories={categories}
          selectedCat={selectedArtifactCat}
          onSelect={setSelectedArtifactCat}
        />
      </Panel>
      <PanelResizeHandle className="resize-handle" />
      <Panel defaultSize={52} minSize={25}>
        <ArtifactResults
          category={selectedCategory}
          artifacts={visibleArtifacts}
          pluginsNotRun={pluginsNotRun}
          selectedId={selectedArtifactId}
          onSelect={(a) => setSelectedArtifactId(a.id)}
          loading={loading}
          flaggedOnly={flaggedOnly}
          onToggleFlagged={() => setFlaggedOnly((v) => !v)}
        />
      </Panel>
      <PanelResizeHandle className="resize-handle" />
      <Panel defaultSize={30} minSize={18} maxSize={55}>
        <ArtifactDetail artifact={selectedArtifact} />
      </Panel>
    </PanelGroup>
  )
}
