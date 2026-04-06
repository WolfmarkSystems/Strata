import { useState, useEffect } from 'react'
import { useAppStore } from '../store/appStore'
import ArtifactCategories from '../components/ArtifactCategories'
import ArtifactResults from '../components/ArtifactResults'
import ArtifactDetail from '../components/ArtifactDetail'
import EmptyState from '../components/EmptyState'
import { getArtifactCategories, getArtifacts } from '../ipc'
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
  const [loading, setLoading] = useState(false)

  // Load categories when evidence loaded
  useEffect(() => {
    if (!evidenceId) {
      setCategories([])
      return
    }
    getArtifactCategories(evidenceId).then(setCategories)
  }, [evidenceId])

  // Load artifacts when category changes
  useEffect(() => {
    if (!evidenceId || !selectedArtifactCat) {
      setArtifacts([])
      return
    }
    setLoading(true)
    setArtifacts([])
    setSelectedArtifactId(null)
    getArtifacts(evidenceId, selectedArtifactCat).then((data) => {
      setArtifacts(data)
      setLoading(false)
    })
  }, [selectedArtifactCat, evidenceId, setSelectedArtifactId])

  const selectedArtifact = artifacts.find((a) => a.id === selectedArtifactId) ?? null
  const selectedCategory = categories.find((c) => c.name === selectedArtifactCat) ?? null

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
    <div
      style={{
        display: 'flex',
        flex: 1,
        overflow: 'hidden',
        background: 'var(--bg-base)',
      }}
    >
      <ArtifactCategories
        categories={categories}
        selectedCat={selectedArtifactCat}
        onSelect={setSelectedArtifactCat}
      />
      <ArtifactResults
        category={selectedCategory}
        artifacts={artifacts}
        selectedId={selectedArtifactId}
        onSelect={(a) => setSelectedArtifactId(a.id)}
        loading={loading}
      />
      <ArtifactDetail artifact={selectedArtifact} />
    </div>
  )
}
