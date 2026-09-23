import { useEffect, useState, useMemo } from 'react'
import api from './api'
import { Network, Globe, Mail, Link2, Hash, MessageSquare, Info, Shield } from 'lucide-react'

const TYPE_CONFIG = {
  case: { label: 'Case', color: '#a3e635', icon: Shield, radius: 18 },
  sender_address: { label: 'Sender', color: '#38bdf8', icon: Mail, radius: 14 },
  sender_domain: { label: 'Domain', color: '#fbbf24', icon: Globe, radius: 14 },
  reported_ip: { label: 'Relay IP', color: '#c084fc', icon: Globe, radius: 14 },
  url: { label: 'URL', color: '#fb923c', icon: Link2, radius: 14 },
  attachment_hash: { label: 'Attachment Hash', color: '#f87171', icon: Hash, radius: 14 },
  reply_address: { label: 'Reply-To', color: '#34d399', icon: Mail, radius: 14 },
  thread_id: { label: 'Thread ID', color: '#818cf8', icon: MessageSquare, radius: 14 },
}

export default function EvidenceGraph({ openCase }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [selectedNode, setSelectedNode] = useState(null)
  const [typeFilter, setTypeFilter] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    let active = true
    api.get('/campaigns/graph')
      .then(res => { if (active) setData(res.data) })
      .catch(() => { if (active) setError('Evidence graph unavailable') })
    return () => { active = false }
  }, [])

  const filteredNodes = useMemo(() => {
    if (!data?.nodes) return []
    return data.nodes.filter(n => {
      const matchType = typeFilter === 'all' || n.type === typeFilter || (typeFilter === 'indicators' && n.type !== 'case')
      const matchSearch = !searchQuery.trim() || String(n.value).toLowerCase().includes(searchQuery.trim().toLowerCase())
      return matchType && matchSearch
    })
  }, [data, typeFilter, searchQuery])

  const visibleNodeIds = useMemo(() => new Set(filteredNodes.map(n => n.id)), [filteredNodes])

  const filteredEdges = useMemo(() => {
    if (!data?.edges) return []
    return data.edges.filter(e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target))
  }, [data, visibleNodeIds])

  // Compute node positions: layout cases in an inner ring, indicators in outer ring
  const layout = useMemo(() => {
    const nodes = filteredNodes
    if (!nodes.length) return {}
    const cases = nodes.filter(n => n.type === 'case')
    const indicators = nodes.filter(n => n.type !== 'case')
    const pos = {}

    const cx = 450
    const cy = 250

    cases.forEach((n, i) => {
      const angle = (i * 2 * Math.PI) / (cases.length || 1) - Math.PI / 2
      const r = cases.length === 1 ? 0 : Math.min(120, 40 + cases.length * 15)
      pos[n.id] = [cx + Math.cos(angle) * r, cy + Math.sin(angle) * r]
    })

    indicators.forEach((n, i) => {
      const angle = (i * 2 * Math.PI) / (indicators.length || 1) - Math.PI / 2
      const r = 210
      pos[n.id] = [cx + Math.cos(angle) * r, cy + Math.sin(angle) * r]
    })

    return pos
  }, [filteredNodes])

  if (error) return <p role="alert" style={{ color: '#f87171' }}>{error}</p>
  if (!data) return <p role="status" style={{ color: '#9ca3b0' }}>Loading evidence graph...</p>

  const counts = (data.nodes || []).reduce((acc, n) => {
    acc[n.type] = (acc[n.type] || 0) + 1
    return acc
  }, {})

  const connectedEdges = selectedNode
    ? (data.edges || []).filter(e => e.source === selectedNode.id || e.target === selectedNode.id)
    : []

  const connectedNodeIds = new Set(connectedEdges.flatMap(e => [e.source, e.target]))

  return (
    <section className="ps-section" aria-label="Typed Evidence Graph">
      <div className="section-head" style={{ marginBottom: 12 }}>
        <h2>Cross-Case Entity Evidence Graph</h2>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span className="badge good">{data.nodes.length} entities</span>
          <span className="badge">{data.edges.length} connections</span>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {[['all', 'All'], ['case', 'Cases'], ['indicators', 'Indicators'], ['sender_domain', 'Domains'], ['reported_ip', 'IPs'], ['url', 'URLs'], ['attachment_hash', 'Hashes']].map(([key, label]) => (
            <button
              key={key}
              className={`secondary ${typeFilter === key ? 'chosen' : ''}`}
              style={{ padding: '4px 10px', fontSize: 11, background: typeFilter === key ? '#a3e63518' : undefined, borderColor: typeFilter === key ? '#a3e635' : undefined }}
              onClick={() => setTypeFilter(key)}
            >
              {label} {key === 'all' ? `(${data.nodes.length})` : counts[key] ? `(${counts[key]})` : ''}
            </button>
          ))}
        </div>
        <input
          type="text"
          placeholder="Filter indicator / case ID..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          style={{ maxWidth: 220, padding: '6px 10px', fontSize: 11, background: '#11141c', border: '1px solid #2f3442', borderRadius: 6, color: '#e6e8ef' }}
        />
      </div>

      {filteredNodes.length > 0 ? (
        <div style={{ background: '#0a0d14', border: '1px solid #242936', borderRadius: 10, overflow: 'hidden', position: 'relative' }}>
          <svg viewBox="0 0 900 500" style={{ width: '100%', height: 'auto', display: 'block', maxHeight: 520 }}>
            <defs>
              <radialGradient id="graph-bg" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#121824" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#080a10" stopOpacity="1" />
              </radialGradient>
            </defs>
            <rect width="900" height="500" fill="url(#graph-bg)" />

            {/* Edges */}
            {filteredEdges.map((e, i) => {
              const p1 = layout[e.source]
              const p2 = layout[e.target]
              if (!p1 || !p2) return null
              const isHighlighted = selectedNode && (e.source === selectedNode.id || e.target === selectedNode.id)
              const strokeColor = isHighlighted
                ? '#a3e635'
                : e.confidence === 'strong'
                ? '#4ade8055'
                : '#64748b33'
              return (
                <line
                  key={i}
                  x1={p1[0]}
                  y1={p1[1]}
                  x2={p2[0]}
                  y2={p2[1]}
                  stroke={strokeColor}
                  strokeWidth={isHighlighted ? 2.5 : e.confidence === 'strong' ? 1.5 : 1}
                  strokeDasharray={e.confidence === 'context_only' ? '4 3' : undefined}
                />
              )
            })}

            {/* Nodes */}
            {filteredNodes.map(n => {
              const p = layout[n.id]
              if (!p) return null
              const cfg = TYPE_CONFIG[n.type] || TYPE_CONFIG.case
              const isSelected = selectedNode?.id === n.id
              const isConnected = selectedNode && connectedNodeIds.has(n.id)
              const isDimmed = selectedNode && !isSelected && !isConnected

              const shortLabel = String(n.value).length > 18
                ? String(n.value).slice(0, 16) + '…'
                : String(n.value)

              return (
                <g
                  key={n.id}
                  style={{ cursor: 'pointer', opacity: isDimmed ? 0.25 : 1, transition: 'opacity 0.15s' }}
                  onClick={() => setSelectedNode(isSelected ? null : n)}
                  tabIndex={0}
                  role="button"
                  aria-label={`${cfg.label}: ${n.value}`}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') setSelectedNode(isSelected ? null : n) }}
                >
                  <circle
                    cx={p[0]}
                    cy={p[1]}
                    r={cfg.radius + (isSelected ? 4 : 0)}
                    fill="#111622"
                    stroke={isSelected ? '#ffffff' : cfg.color}
                    strokeWidth={isSelected ? 3 : 2}
                  />
                  {n.type === 'case' ? (
                    <text x={p[0]} y={p[1] + 4} textAnchor="middle" fill="#e6e8ef" fontSize="10" fontFamily="Consolas, monospace" fontWeight="600">
                      {String(n.value).slice(0, 6)}
                    </text>
                  ) : null}
                  <text
                    x={p[0]}
                    y={p[1] + cfg.radius + 12}
                    textAnchor="middle"
                    fill={isSelected ? '#ffffff' : '#9ca3b0'}
                    fontSize="9"
                    fontFamily="Consolas, monospace"
                  >
                    {shortLabel}
                  </text>
                  <title>{`${cfg.label}: ${n.value}`}</title>
                </g>
              )
            })}
          </svg>

          {/* Node detail callout card */}
          {selectedNode && (
            <div style={{ position: 'absolute', bottom: 12, left: 12, right: 12, padding: '12px 16px', background: '#111520ee', border: '1px solid #303748', borderRadius: 8, backdropFilter: 'blur(6px)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="badge" style={{ borderColor: TYPE_CONFIG[selectedNode.type]?.color, color: TYPE_CONFIG[selectedNode.type]?.color }}>
                    {TYPE_CONFIG[selectedNode.type]?.label || selectedNode.type}
                  </span>
                  <strong className="mono" style={{ fontSize: 12, color: '#f1f5f9', wordBreak: 'break-all' }}>
                    {selectedNode.value}
                  </strong>
                </div>
                <div style={{ fontSize: 11, color: '#9ca3b0', marginTop: 4 }}>
                  Connected to {connectedEdges.length} entity connection{connectedEdges.length === 1 ? '' : 's'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                {selectedNode.type === 'case' && (
                  <button className="primary" style={{ padding: '5px 12px', fontSize: 11 }} onClick={() => openCase(selectedNode.value)}>
                    Open Case {selectedNode.value}
                  </button>
                )}
                <button className="secondary" style={{ padding: '5px 10px', fontSize: 11 }} onClick={() => setSelectedNode(null)}>
                  Close
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="empty" style={{ padding: '36px 12px' }}>
          <Network size={28} />
          <p>No matching entities found. Analyze cases to populate session entity relationships.</p>
        </div>
      )}

      {data.policy && (
        <p className="caveat" style={{ fontSize: 11, color: '#9ca3b0', marginTop: 12 }}>
          <Info size={13} style={{ display: 'inline', verticalAlign: 'text-bottom', marginRight: 4 }} />
          {data.policy}
        </p>
      )}
    </section>
  )
}
