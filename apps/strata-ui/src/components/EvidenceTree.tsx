import { useEffect, useState } from 'react'
import { useAppStore } from '../store/appStore'
import { getTreeRoot, getTreeChildren } from '../ipc'
import type { TreeNode } from '../types'

export default function EvidenceTree() {
  const evidenceId = useAppStore((s) => s.evidenceId)
  const selectedNodeId = useAppStore((s) => s.selectedNodeId)
  const setSelectedNode = useAppStore((s) => s.setSelectedNode)
  const treeExpanded = useAppStore((s) => s.treeExpanded)
  const toggleTreeNode = useAppStore((s) => s.toggleTreeNode)

  const [rootNodes, setRootNodes] = useState<TreeNode[]>([])
  const [childrenMap, setChildrenMap] = useState<Map<string, TreeNode[]>>(new Map())
  const [filter, setFilter] = useState('')

  // Load root on evidence change
  useEffect(() => {
    if (!evidenceId) {
      setRootNodes([])
      setChildrenMap(new Map())
      return
    }
    getTreeRoot(evidenceId).then((nodes) => {
      setRootNodes(nodes)
      // Auto-expand the root
      nodes.forEach((n) => {
        if (!treeExpanded.has(n.id)) toggleTreeNode(n.id)
      })
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [evidenceId])

  // When a node expands and we don't have its children yet, load them
  useEffect(() => {
    treeExpanded.forEach((id) => {
      if (!childrenMap.has(id)) {
        getTreeChildren(id).then((kids) => {
          setChildrenMap((prev) => {
            const next = new Map(prev)
            next.set(id, kids)
            return next
          })
        })
      }
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [treeExpanded])

  // Flatten tree into a render list
  const flatNodes: TreeNode[] = []
  const walk = (nodes: TreeNode[]) => {
    for (const n of nodes) {
      flatNodes.push(n)
      if (treeExpanded.has(n.id)) {
        const kids = childrenMap.get(n.id) ?? []
        walk(kids)
      }
    }
  }
  walk(rootNodes)

  const visibleNodes = filter
    ? flatNodes.filter((n) =>
        n.name.toLowerCase().includes(filter.toLowerCase()),
      )
    : flatNodes

  // Volume count for header badge
  const volumeCount = rootNodes.length

  return (
    <div
      style={{
        width: 220,
        minWidth: 220,
        background: '#0a0c12',
        borderRight: '1px solid var(--border-sub)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '7px 10px',
          fontSize: 9,
          color: 'var(--text-muted)',
          textTransform: 'uppercase',
          letterSpacing: '0.1em',
          borderBottom: '1px solid var(--border-sub)',
          display: 'flex',
          justifyContent: 'space-between',
          flexShrink: 0,
        }}
      >
        <span>Evidence Tree</span>
        <span>{volumeCount}</span>
      </div>

      {/* Filter */}
      <div
        style={{
          padding: '6px 8px',
          borderBottom: '1px solid var(--border-sub)',
          flexShrink: 0,
        }}
      >
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter..."
          style={{
            width: '100%',
            fontSize: 11,
            padding: '4px 8px',
          }}
        />
      </div>

      {/* Tree scroll area */}
      <div
        style={{
          flex: 1,
          overflowY: 'auto',
          overflowX: 'hidden',
        }}
      >
        {visibleNodes.length === 0 && (
          <div
            style={{
              padding: 12,
              fontSize: 11,
              color: 'var(--text-muted)',
              textAlign: 'center',
            }}
          >
            {evidenceId ? 'No matches' : 'No evidence loaded'}
          </div>
        )}
        {visibleNodes.map((node) => (
          <TreeNodeRow
            key={node.id}
            node={node}
            expanded={treeExpanded.has(node.id)}
            selected={selectedNodeId === node.id}
            onToggle={() => toggleTreeNode(node.id)}
            onSelect={() => setSelectedNode(node.id)}
          />
        ))}
      </div>
    </div>
  )
}

function TreeNodeRow({
  node,
  expanded,
  selected,
  onToggle,
  onSelect,
}: {
  node: TreeNode
  expanded: boolean
  selected: boolean
  onToggle: () => void
  onSelect: () => void
}) {
  const [hover, setHover] = useState(false)

  const icon = (() => {
    switch (node.node_type) {
      case 'evidence':
        return '\u{1F4BF}' // 💿
      case 'volume':
        return '\u{1F4C0}' // 📀
      case 'folder':
        return expanded ? '\u{1F4C2}' : '\u{1F4C1}' // 📂 / 📁
      default:
        return ''
    }
  })()

  let textColor: string = 'var(--text-2)'
  if (node.is_flagged) textColor = 'var(--flag)'
  else if (node.is_suspicious) textColor = 'var(--sus)'
  if (selected) textColor = 'var(--text-1)'

  let bg = 'transparent'
  if (selected) bg = '#0f1e30'
  else if (hover) bg = '#0f1420'

  return (
    <div
      onClick={onSelect}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        minHeight: 28,
        paddingLeft: node.depth * 14 + 10,
        paddingRight: 10,
        display: 'flex',
        alignItems: 'center',
        gap: 5,
        cursor: 'pointer',
        fontSize: 12,
        color: textColor,
        background: bg,
        transition: 'background 0.1s',
      }}
    >
      {node.has_children ? (
        <span
          onClick={(e) => {
            e.stopPropagation()
            onToggle()
          }}
          style={{
            fontSize: 9,
            color: 'var(--text-muted)',
            width: 12,
            flexShrink: 0,
            textAlign: 'center',
          }}
        >
          {expanded ? '\u25BC' : '\u25B6'}
        </span>
      ) : (
        <span style={{ width: 12, flexShrink: 0 }} />
      )}
      {icon && <span style={{ fontSize: 12, flexShrink: 0 }}>{icon}</span>}
      <span
        style={{
          flex: 1,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {node.name}
      </span>
      <span
        style={{
          marginLeft: 'auto',
          fontSize: 10,
          color: 'var(--text-muted)',
          flexShrink: 0,
        }}
      >
        {node.count.toLocaleString()}
      </span>
    </div>
  )
}
