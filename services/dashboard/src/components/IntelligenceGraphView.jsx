import React, { useEffect, useMemo, useState, useRef } from 'react'
import { getApiUrl } from '../config'

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }

// Cores e brilhos neon por tipo de nó
const nodeStyles = {
  asset: { color: '#60a5fa', glow: 'rgba(96, 165, 250, 0.6)', radius: 14 },
  vulnerability: { color: '#ef4444', glow: 'rgba(239, 68, 68, 0.6)', radius: 12 },
  cve: { color: '#ef4444', glow: 'rgba(239, 68, 68, 0.6)', radius: 12 },
  service: { color: '#c084fc', glow: 'rgba(192, 132, 252, 0.6)', radius: 11 },
  control: { color: '#34d399', glow: 'rgba(52, 211, 153, 0.6)', radius: 11 },
  technique: { color: '#fbbf24', glow: 'rgba(251, 191, 36, 0.6)', radius: 11 },
  intel: { color: '#a855f7', glow: 'rgba(168, 85, 247, 0.6)', radius: 11 },
  default: { color: '#94a3b8', glow: 'rgba(148, 163, 184, 0.6)', radius: 10 }
}

export default function IntelligenceGraphView() {
  const [graph, setGraph] = useState({ summary: {}, nodes: [], edges: [] })
  const [correlations, setCorrelations] = useState([])
  const [paths, setPaths] = useState([])
  const [nodeType, setNodeType] = useState('all')
  const [error, setError] = useState('')

  // Estados de visualização do grafo
  const [selectedNode, setSelectedNode] = useState(null)
  const [zoom, setZoom] = useState(1.0)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [tick, setTick] = useState(0) // Trigger para renderizações do canvas

  // Referências para física e interatividade
  const containerRef = useRef(null)
  const isDraggingCanvasRef = useRef(false)
  const dragStartRef = useRef({ x: 0, y: 0 })
  const draggedNodeIdRef = useRef(null)
  const nodePositionsRef = useRef({}) // { id: { x, y, vx, vy } }

  // Carregar dados da API
  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const [graphResponse, correlationResponse, pathResponse] = await Promise.all([
          fetch(getApiUrl('/api/knowledge-graph?limit=800')),
          fetch(getApiUrl('/api/correlations?limit=100')),
          fetch(getApiUrl('/api/attack-paths?limit=100'))
        ])
        if (!graphResponse.ok || !correlationResponse.ok || !pathResponse.ok) throw new Error('Knowledge Graph API indisponível')
        const [graphData, correlationData, pathData] = await Promise.all([
          graphResponse.json(), correlationResponse.json(), pathResponse.json()
        ])
        if (active) {
          setGraph(graphData)
          setCorrelations(correlationData)
          setPaths(pathData)
          setError('')

          // Inicializar ou sincronizar posições físicas dos nós
          const currentPositions = nodePositionsRef.current
          const width = containerRef.current?.clientWidth || 800
          const height = containerRef.current?.clientHeight || 520

          const updatedPositions = {}
          graphData.nodes.forEach((node, index) => {
            if (currentPositions[node.id]) {
              updatedPositions[node.id] = currentPositions[node.id]
            } else {
              // Posicionamento espiral inicial centralizado
              const angle = index * 0.45
              const radius = 30 + index * 6
              updatedPositions[node.id] = {
                x: width / 2 + Math.cos(angle) * radius,
                y: height / 2 + Math.sin(angle) * radius,
                vx: 0,
                vy: 0
              }
            }
          })
          nodePositionsRef.current = updatedPositions
        }
      } catch (err) {
        if (active) setError(err.message)
      }
    }
    load()
    const timer = window.setInterval(load, 15000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  // Loop de simulação física (Force-Directed Graph)
  useEffect(() => {
    let animationFrameId
    const step = () => {
      const positions = nodePositionsRef.current
      const nodes = graph.nodes
      const edges = graph.edges
      
      if (!nodes || nodes.length === 0) {
        animationFrameId = requestAnimationFrame(step)
        return
      }

      const width = containerRef.current?.clientWidth || 800
      const height = containerRef.current?.clientHeight || 520
      const cx = width / 2
      const cy = height / 2

      // 1. Repulsão entre todos os nós (Lei de Coulomb modificada)
      for (let i = 0; i < nodes.length; i++) {
        const nodeA = positions[nodes[i].id]
        if (!nodeA) continue
        for (let j = i + 1; j < nodes.length; j++) {
          const nodeB = positions[nodes[j].id]
          if (!nodeB) continue

          const dx = nodeB.x - nodeA.x
          const dy = nodeB.y - nodeA.y
          const distSq = dx * dx + dy * dy + 0.1
          const dist = Math.sqrt(distSq)

          if (dist < 260) {
            // Força de repulsão
            const force = 350 / distSq
            const fx = (dx / dist) * force
            const fy = (dy / dist) * force

            // Aplicar velocidades contrárias
            if (nodes[i].id !== draggedNodeIdRef.current) {
              nodeA.vx -= fx
              nodeA.vy -= fy
            }
            if (nodes[j].id !== draggedNodeIdRef.current) {
              nodeB.vx += fx
              nodeB.vy += fy
            }
          }
        }
      }

      // 2. Atração de mola entre nós conectados (Lei de Hooke)
      edges.forEach(edge => {
        const nodeA = positions[edge.source]
        const nodeB = positions[edge.target]
        if (!nodeA || !nodeB) return

        const dx = nodeB.x - nodeA.x
        const dy = nodeB.y - nodeA.y
        const dist = Math.sqrt(dx * dx + dy * dy) + 0.1
        const targetDist = 90.0 // distância ideal de mola
        
        // Força proporcional ao deslocamento do comprimento ideal
        const force = (dist - targetDist) * 0.035
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force

        if (edge.source !== draggedNodeIdRef.current) {
          nodeA.vx += fx
          nodeA.vy += fy
        }
        if (edge.target !== draggedNodeIdRef.current) {
          nodeB.vx -= fx
          nodeB.vy -= fy
        }
      });

      // 3. Gravidade central e atualização de coordenadas
      nodes.forEach(node => {
        const pos = positions[node.id]
        if (!pos || node.id === draggedNodeIdRef.current) return

        // Atração gravitacional central para não dispersar
        const dx = cx - pos.x
        const dy = cy - pos.y
        pos.vx += dx * 0.0015
        pos.vy += dy * 0.0015

        // Amortecimento (fricção)
        pos.vx *= 0.82
        pos.vy *= 0.82

        // Atualizar coordenadas
        pos.x += pos.vx
        pos.y += pos.vy
      })

      // Forçar atualização visual do React
      setTick(t => t + 1)
      animationFrameId = requestAnimationFrame(step)
    }

    animationFrameId = requestAnimationFrame(step)
    return () => cancelAnimationFrame(animationFrameId)
  }, [graph])

  // Processar dados computados
  const nodeTypes = useMemo(() => Object.keys(graph.summary?.node_types || {}), [graph.summary])
  const topCorrelations = useMemo(() => [...correlations].sort((a, b) => {
    const severityDelta = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)
    return severityDelta || Number(b.confidence || 0) - Number(a.confidence || 0)
  }).slice(0, 12), [correlations])

  // Filtrar nós visíveis no SVG
  const filteredNodes = useMemo(() => {
    return graph.nodes.filter(node => nodeType === 'all' || node.type === nodeType)
  }, [graph.nodes, nodeType])

  // Mapear conexões válidas baseadas nos nós visíveis
  const filteredEdges = useMemo(() => {
    const nodeIds = new Set(filteredNodes.map(n => n.id))
    return graph.edges.filter(edge => nodeIds.has(edge.source) && nodeIds.has(edge.target))
  }, [graph.edges, filteredNodes])

  // Interação do mouse no cenário (Fundo do SVG)
  const handleCanvasMouseDown = (e) => {
    if (e.target.tagName === 'svg') {
      isDraggingCanvasRef.current = true
      dragStartRef.current = { x: e.clientX - pan.x, y: e.clientY - pan.y }
    }
  }

  const handleCanvasMouseMove = (e) => {
    const positions = nodePositionsRef.current
    
    if (isDraggingCanvasRef.current) {
      setPan({
        x: e.clientX - dragStartRef.current.x,
        y: e.clientY - dragStartRef.current.y
      })
    } else if (draggedNodeIdRef.current) {
      // Movimentar nó arrastado (converter coordenadas do mouse para o espaço do SVG com Pan e Zoom)
      const rect = containerRef.current.getBoundingClientRect()
      const mouseX = e.clientX - rect.left
      const mouseY = e.clientY - rect.top
      
      const nodeX = (mouseX - pan.x) / zoom
      const nodeY = (mouseY - pan.y) / zoom

      const pos = positions[draggedNodeIdRef.current]
      if (pos) {
        pos.x = nodeX
        pos.y = nodeY
        pos.vx = 0
        pos.vy = 0
      }
    }
  }

  const handleCanvasMouseUp = () => {
    isDraggingCanvasRef.current = false
    draggedNodeIdRef.current = null
  }

  const handleZoom = (factor) => {
    setZoom(z => Math.max(0.2, Math.min(3.0, z * factor)))
  }

  const handleResetView = () => {
    setZoom(1.0)
    setPan({ x: 0, y: 0 })
    setSelectedNode(null)
  }

  const handleNodeMouseDown = (e, id) => {
    e.stopPropagation()
    draggedNodeIdRef.current = id
  }

  const handleNodeClick = (e, node) => {
    e.stopPropagation()
    setSelectedNode(node)
  }

  return (
    <div>
      <h2 className="section-heading">Asset Intelligence & Knowledge Graph</h2>
      <p className="section-subtitle">Relações explicáveis entre ativos, serviços, CPEs, CVEs, ATT&CK, controles, inteligência e remediações.</p>

      {error && <div className="error-banner">{error}</div>}

      <div className="metric-grid graph-metrics">
        <GraphMetric label="Nós" value={graph.summary?.nodes || 0} />
        <GraphMetric label="Relações" value={graph.summary?.edges || 0} />
        <GraphMetric label="Correlações" value={graph.summary?.correlations || 0} warning />
        <GraphMetric label="Caminhos" value={graph.summary?.attack_paths || 0} critical />
      </div>

      <div className="graph-layout">
        <section className="card">
          <div className="graph-title-row">
            <h3 className="card-title">Top correlações de risco</h3>
            <span className="graph-meta">{graph.summary?.critical_correlations || 0} críticas</span>
          </div>
          {topCorrelations.length === 0 && <div className="empty-state">Nenhuma correlação materializada ainda. O agente reconstrói o grafo periodicamente.</div>}
          <div className="correlation-list">
            {topCorrelations.map(item => (
              <article key={item.correlation_id} className={`correlation-card correlation-${item.severity || 'medium'}`}>
                <div className="correlation-head">
                  <strong>{item.title}</strong>
                  <span className={`risk-badge risk-${item.severity || 'medium'}`}>{item.severity || 'medium'}</span>
                </div>
                <div className="correlation-meta">Confiança {Math.round(Number(item.confidence || 0) * 100)}% • {item.asset || '—'} {item.cve_id ? `• ${item.cve_id}` : ''}</div>
                <div className="correlation-rationale">{(item.rationale || []).join(' · ')}</div>
              </article>
            ))}
          </div>
        </section>

        <section className="card">
          <h3 className="card-title">Caminhos de ataque defensivos</h3>
          <div className="path-list">
            {paths.slice(0, 12).map(path => (
              <div key={path.path_id} className="path-card">
                <div className="path-score">{Number(path.risk_score || 0).toFixed(1)}</div>
                <div>
                  <strong>{path.asset} → {path.service} → {path.cve_id}</strong>
                  <div className="graph-meta">{path.technique_id || 'ATT&CK não mapeado'} • {path.cisa_kev ? 'CISA KEV • ' : ''}{path.control_coverage ? 'controle mapeado' : 'gap de controle'}</div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="card" style={{ position: 'relative' }}>
        <div className="graph-title-row">
          <h3 className="card-title">Explorador Gráfico de Entidades</h3>
          <select className="graph-select" value={nodeType} onChange={event => setNodeType(event.target.value)}>
            <option value="all">Todos os tipos</option>
            {nodeTypes.map(type => <option key={type} value={type}>{type}</option>)}
          </select>
        </div>

        {/* Viewport do Grafo SVG */}
        <div className="graph-canvas-container" ref={containerRef}>
          <div className="graph-ctrl-panel">
            <button className="graph-ctrl-btn" title="Mais Zoom" onClick={() => handleZoom(1.2)}>＋</button>
            <button className="graph-ctrl-btn" title="Menos Zoom" onClick={() => handleZoom(0.8)}>－</button>
            <button className="graph-ctrl-btn" title="Reiniciar Foco" onClick={handleResetView}>🎯</button>
          </div>

          <svg
            className="graph-svg"
            onMouseDown={handleCanvasMouseDown}
            onMouseMove={handleCanvasMouseMove}
            onMouseUp={handleCanvasMouseUp}
            onMouseLeave={handleCanvasMouseUp}
          >
            <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
              {/* Linhas (Arestas/Links) */}
              {filteredEdges.map((edge, index) => {
                const posA = nodePositionsRef.current[edge.source]
                const posB = nodePositionsRef.current[edge.target]
                if (!posA || !posB) return null

                const isCritical = edge.type === 'exploits' || edge.type === 'targets'
                const key = `edge-${edge.source}-${edge.target}-${index}`

                return (
                  <line
                    key={key}
                    className={`graph-link ${isCritical ? 'graph-link-critical' : ''}`}
                    x1={posA.x}
                    y1={posA.y}
                    x2={posB.x}
                    y2={posB.y}
                  />
                )
              })}

              {/* Nós (Entidades) */}
              {filteredNodes.map(node => {
                const pos = nodePositionsRef.current[node.id]
                if (!pos) return null

                const style = nodeStyles[node.type] || nodeStyles.default
                const isSelected = selectedNode?.id === node.id

                return (
                  <g
                    key={node.id}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onMouseDown={(e) => handleNodeMouseDown(e, node.id)}
                    onClick={(e) => handleNodeClick(e, node)}
                  >
                    <circle
                      className={`graph-node ${isSelected ? 'graph-node-selected' : ''}`}
                      r={style.radius}
                      fill={style.color}
                      style={{ '--node-glow': style.glow }}
                    />
                    <text className="graph-label" dy={style.radius + 12} textAnchor="middle">
                      {node.label}
                    </text>
                  </g>
                )
              })}
            </g>
          </svg>

          {/* Gaveta Lateral de Detalhes (Drawer) */}
          <div className={`graph-drawer ${selectedNode ? 'open' : ''}`}>
            {selectedNode && (
              <>
                <button className="drawer-close" onClick={() => setSelectedNode(null)}>×</button>
                <div className="drawer-type" style={{ color: (nodeStyles[selectedNode.type] || nodeStyles.default).color }}>
                  {selectedNode.type}
                </div>
                <h4 className="drawer-title">{selectedNode.label}</h4>
                
                <div className="drawer-content">
                  {selectedNode.properties?.description && (
                    <p style={{ marginBottom: '14px' }}>{selectedNode.properties.description}</p>
                  )}
                  
                  <div className="drawer-metric">
                    <span className="drawer-metric-label">ID da Entidade</span>
                    <span className="drawer-metric-value" style={{ fontSize: '10px' }}>{selectedNode.id}</span>
                  </div>

                  {selectedNode.risk_score !== undefined && (
                    <div className="drawer-metric">
                      <span className="drawer-metric-label">Risco Contextual</span>
                      <span className="drawer-metric-value" style={{ color: '#fbbf24' }}>
                        {Number(selectedNode.risk_score).toFixed(1)} / 10
                      </span>
                    </div>
                  )}

                  {selectedNode.properties && Object.entries(selectedNode.properties).map(([key, val]) => {
                    if (key === 'description' || val === null || val === undefined) return null
                    const displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val)
                    return (
                      <div className="drawer-metric" key={key}>
                        <span className="drawer-metric-label">{key.replace(/_/g, ' ')}</span>
                        <span className="drawer-metric-value">{displayVal}</span>
                      </div>
                    )
                  })}
                </div>
              </>
            )}
          </div>
        </div>
      </section>
    </div>
  )
}

function GraphMetric({ label, value, warning, critical }) {
  return (
    <div className={`metric-card ${critical ? 'metric-critical' : warning ? 'metric-warning' : ''}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
    </div>
  )
}
