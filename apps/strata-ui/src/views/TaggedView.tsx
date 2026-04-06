import { useState, useEffect, useCallback } from 'react'
import { useAppStore } from '../store/appStore'
import EmptyState from '../components/EmptyState'
import { getTagSummaries, getTaggedFiles, untagFile } from '../ipc'
import type { TagSummary, TaggedFile } from '../ipc'

const TAG_DEFS: Array<{ name: string; color: string }> = [
  { name: 'Critical Evidence', color: '#a84040' },
  { name: 'Suspicious',        color: '#b87840' },
  { name: 'Needs Review',      color: '#b8a840' },
  { name: 'Confirmed Clean',   color: '#487858' },
  { name: 'Key Artifact',      color: '#4a7890' },
  { name: 'Excluded',          color: '#3a4858' },
]

function hexToRgba(hex: string, alpha: number): string {
  const h = hex.replace('#', '')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

export default function TaggedView() {
  const evidenceLoaded = useAppStore((s) => s.evidenceLoaded)
  const selectedTag = useAppStore((s) => s.selectedTag)
  const setSelectedTag = useAppStore((s) => s.setSelectedTag)
  const taggedFiles = useAppStore((s) => s.taggedFiles)
  const removeFileTag = useAppStore((s) => s.removeFileTag)

  const [summaries, setSummaries] = useState<TagSummary[]>([])
  const [files, setFiles] = useState<TaggedFile[]>([])
  const [selectedFile, setSelectedFile] = useState<TaggedFile | null>(null)

  const refreshSummaries = useCallback(() => {
    getTagSummaries().then(setSummaries)
  }, [])

  useEffect(() => {
    refreshSummaries()
  }, [taggedFiles, refreshSummaries])

  useEffect(() => {
    if (!selectedTag) {
      setFiles([])
      return
    }
    getTaggedFiles(selectedTag).then(setFiles)
    setSelectedFile(null)
  }, [selectedTag, taggedFiles])

  if (!evidenceLoaded) {
    return (
      <EmptyState
        icon={'\u{1F3F7}'}
        title="Tagged Evidence"
        subtitle="Load evidence to begin tagging"
        hint="Right-click any file in the File Explorer to add a tag"
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
      {/* Left: tag list */}
      <div
        style={{
          width: 180,
          minWidth: 180,
          background: '#0a0c12',
          borderRightStyle: 'solid',
          borderRightWidth: 1,
          borderRightColor: 'var(--border-sub)',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
        }}
      >
        <div
          style={{
            padding: '7px 10px',
            fontSize: 9,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            borderBottomStyle: 'solid',
            borderBottomWidth: 1,
            borderBottomColor: 'var(--border-sub)',
          }}
        >
          Tagged Evidence
        </div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {TAG_DEFS.map((tag) => {
            const summary = summaries.find((s) => s.name === tag.name)
            const count = summary?.count ?? 0
            const isSelected = selectedTag === tag.name
            return (
              <TagListRow
                key={tag.name}
                tag={tag}
                count={count}
                isSelected={isSelected}
                onClick={() => setSelectedTag(tag.name)}
              />
            )
          })}
        </div>
      </div>

      {/* Center: files list */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '8px 12px',
            fontSize: 10,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            borderBottomStyle: 'solid',
            borderBottomWidth: 1,
            borderBottomColor: 'var(--border-sub)',
            background: 'var(--bg-surface)',
            flexShrink: 0,
          }}
        >
          {selectedTag
            ? `${selectedTag} \u2014 ${files.length} file${files.length !== 1 ? 's' : ''}`
            : 'Select a tag category'}
        </div>

        {selectedTag && files.length > 0 && (
          <div
            style={{
              display: 'flex',
              background: '#0a0c12',
              borderBottomStyle: 'solid',
              borderBottomWidth: 1,
              borderBottomColor: 'var(--border-sub)',
              flexShrink: 0,
            }}
          >
            {[
              { h: 'Name',      flex: 3 },
              { h: 'Size',      flex: 1 },
              { h: 'Modified',  flex: 1 },
              { h: 'Tagged At', flex: 1 },
              { h: 'Note',      flex: 2 },
            ].map((col) => (
              <div
                key={col.h}
                style={{
                  padding: '7px 10px',
                  fontSize: 10,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  flex: col.flex,
                }}
              >
                {col.h}
              </div>
            ))}
          </div>
        )}

        <div style={{ overflowY: 'auto', flex: 1 }}>
          {!selectedTag ? (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                fontSize: 13,
                color: 'var(--text-muted)',
                flexDirection: 'column',
                gap: 8,
              }}
            >
              <div style={{ fontSize: 24 }}>{'\u{1F3F7}'}</div>
              Select a tag to view files
            </div>
          ) : files.length === 0 ? (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: 200,
                fontSize: 13,
                color: 'var(--text-muted)',
                flexDirection: 'column',
                gap: 8,
                textAlign: 'center',
                padding: 20,
              }}
            >
              <div>
                No files tagged as {selectedTag}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-off)' }}>
                Right-click files in the File Explorer to add tags
              </div>
            </div>
          ) : (
            files.map((file) => (
              <TaggedFileRow
                key={file.file_id}
                file={file}
                selected={selectedFile?.file_id === file.file_id}
                onClick={() => setSelectedFile(file)}
              />
            ))
          )}
        </div>
      </div>

      {/* Right: file detail */}
      <div
        style={{
          width: 240,
          minWidth: 240,
          background: '#0a0c12',
          borderLeftStyle: 'solid',
          borderLeftWidth: 1,
          borderLeftColor: 'var(--border-sub)',
          display: 'flex',
          flexDirection: 'column',
          flexShrink: 0,
        }}
      >
        <div
          style={{
            padding: '7px 10px',
            fontSize: 9,
            color: 'var(--text-muted)',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            borderBottomStyle: 'solid',
            borderBottomWidth: 1,
            borderBottomColor: 'var(--border-sub)',
            flexShrink: 0,
          }}
        >
          File Detail
        </div>
        {!selectedFile ? (
          <div
            style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: 13,
              color: 'var(--text-muted)',
            }}
          >
            Select a file
          </div>
        ) : (
          <div style={{ overflowY: 'auto', flex: 1, padding: 12 }}>
            <div
              style={{
                padding: '6px 10px',
                borderRadius: 4,
                marginBottom: 10,
                background: hexToRgba(selectedFile.tag_color, 0.1),
                borderStyle: 'solid',
                borderWidth: 1,
                borderColor: hexToRgba(selectedFile.tag_color, 0.3),
                fontSize: 11,
                fontWeight: 700,
                color: selectedFile.tag_color,
              }}
            >
              {selectedFile.tag}
            </div>

            <DetailRow k="Name" v={selectedFile.name} />
            <DetailRow k="Size" v={selectedFile.size_display} />
            <DetailRow k="Modified" v={selectedFile.modified} />
            <DetailRow k="Tagged" v={selectedFile.tagged_at} />

            <div
              style={{
                fontSize: 10,
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                marginTop: 4,
                marginBottom: 2,
              }}
            >
              Path
            </div>
            <div
              style={{
                fontFamily: 'monospace',
                fontSize: 10,
                color: 'var(--text-2)',
                wordBreak: 'break-all',
                marginBottom: 6,
              }}
            >
              {selectedFile.full_path}
            </div>

            {selectedFile.note && (
              <>
                <div
                  style={{
                    height: 1,
                    background: 'var(--border-sub)',
                    margin: '8px 0',
                  }}
                />
                <div
                  style={{
                    fontSize: 10,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    marginBottom: 6,
                  }}
                >
                  Examiner Note
                </div>
                <div
                  style={{
                    fontSize: 12,
                    color: 'var(--text-2)',
                    lineHeight: 1.5,
                    fontStyle: 'italic',
                  }}
                >
                  {selectedFile.note}
                </div>
              </>
            )}

            <div
              style={{
                height: 1,
                background: 'var(--border-sub)',
                margin: '12px 0 10px',
              }}
            />
            <button
              onClick={async () => {
                await untagFile(selectedFile.file_id)
                removeFileTag(selectedFile.file_id)
                setSelectedFile(null)
                refreshSummaries()
                if (selectedTag) {
                  getTaggedFiles(selectedTag).then(setFiles)
                }
              }}
              style={{
                width: '100%',
                padding: '7px',
                background: 'transparent',
                borderStyle: 'solid',
                borderWidth: 1,
                borderColor: 'var(--flag)',
                borderRadius: 4,
                color: 'var(--flag)',
                fontSize: 11,
                fontFamily: 'monospace',
                fontWeight: 700,
                cursor: 'pointer',
                letterSpacing: '0.06em',
              }}
            >
              REMOVE TAG
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function TagListRow({
  tag,
  count,
  isSelected,
  onClick,
}: {
  tag: { name: string; color: string }
  count: number
  isSelected: boolean
  onClick: () => void
}) {
  const [hover, setHover] = useState(false)
  const hasResults = count > 0

  let bg = 'transparent'
  if (isSelected) bg = '#0f1e30'
  else if (hover) bg = '#0f1420'

  const badgeBg = hasResults ? hexToRgba(tag.color, 0.15) : 'var(--bg-elevated)'
  const badgeBorder = hasResults ? hexToRgba(tag.color, 0.3) : 'var(--border)'
  const badgeColor = hasResults ? tag.color : 'var(--text-off)'

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        padding: '8px 12px',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        cursor: 'pointer',
        fontSize: 12,
        color: isSelected ? 'var(--text-1)' : 'var(--text-muted)',
        background: bg,
        borderBottomStyle: 'solid',
        borderBottomWidth: 1,
        borderBottomColor: 'rgba(18,22,32,0.5)',
        transition: 'background 0.1s',
      }}
    >
      <div
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: tag.color,
          flexShrink: 0,
        }}
      />
      <span style={{ flex: 1, fontWeight: hasResults ? 700 : 400 }}>{tag.name}</span>
      <span
        style={{
          fontSize: 10,
          fontFamily: 'monospace',
          fontWeight: 700,
          padding: '1px 6px',
          borderRadius: 3,
          background: badgeBg,
          color: badgeColor,
          borderStyle: 'solid',
          borderWidth: 1,
          borderColor: badgeBorder,
        }}
      >
        {count}
      </span>
    </div>
  )
}

function TaggedFileRow({
  file,
  selected,
  onClick,
}: {
  file: TaggedFile
  selected: boolean
  onClick: () => void
}) {
  const [hover, setHover] = useState(false)
  let bg = 'transparent'
  if (selected) bg = '#0f1e30'
  else if (hover) bg = '#0f1420'

  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex',
        alignItems: 'center',
        minHeight: 30,
        borderBottomStyle: 'solid',
        borderBottomWidth: 1,
        borderBottomColor: '#0d1018',
        cursor: 'pointer',
        background: bg,
        transition: 'background 0.1s',
      }}
    >
      <div
        style={{
          padding: '6px 10px',
          flex: 3,
          fontSize: 12,
          color: 'var(--text-2)',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: file.tag_color,
            flexShrink: 0,
          }}
        />
        <span
          style={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {file.name}
        </span>
      </div>
      <div
        style={{
          padding: '6px 10px',
          flex: 1,
          fontSize: 12,
          color: 'var(--text-muted)',
        }}
      >
        {file.size_display}
      </div>
      <div
        style={{
          padding: '6px 10px',
          flex: 1,
          fontSize: 11,
          color: 'var(--text-muted)',
          fontFamily: 'monospace',
        }}
      >
        {file.modified}
      </div>
      <div
        style={{
          padding: '6px 10px',
          flex: 1,
          fontSize: 11,
          color: 'var(--text-muted)',
          fontFamily: 'monospace',
        }}
      >
        {file.tagged_at}
      </div>
      <div
        style={{
          padding: '6px 10px',
          flex: 2,
          fontSize: 11,
          color: 'var(--text-muted)',
          fontStyle: file.note ? 'normal' : 'italic',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {file.note ?? '\u2014'}
      </div>
    </div>
  )
}

function DetailRow({ k, v }: { k: string; v: string }) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginBottom: 8,
        gap: 8,
      }}
    >
      <span
        style={{
          fontSize: 10,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          flexShrink: 0,
        }}
      >
        {k}
      </span>
      <span
        style={{
          fontSize: 12,
          color: 'var(--text-2)',
          textAlign: 'right',
          wordBreak: 'break-all',
        }}
      >
        {v}
      </span>
    </div>
  )
}
