import React, { useEffect, useMemo, useState } from 'react'

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }

export default function IntelligenceGraphView() {
  const [graph, setGraph] = useState({ summary: {}, nodes: [], edges: [] })
  const [correlations, setCorrelations] = useState([])
  const [paths, setPaths] = useState([])
  const [nodeType, setNodeType] = useState('all')
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const [graphResponse, correlationResponse, pathResponse] = await Promise.all([
          fetch('/api/knowledge-graph?limit=800'),
          fetch('/api/correlations?limit=100'),
          fetch('/api/attack-paths?limit=100')
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
        }
      } catch (err) {
        if (active) setError(err.message)
      }
    }
    load()
    const timer = window.setInterval(load, 10000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  const nodeTypes = useMemo(() => Object.keys(graph.summary?.node_types || {}), [graph.summary])
  const visibleNodes = useMemo(() => graph.nodes.filter(node => nodeType === 'all' || node.type === nodeType).slice(0, 120), [graph.nodes, nodeType])
  const topCorrelations = useMemo(() => [...correlations].sort((a, b) => {
    const severityDelta = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)
    return severityDelta || Number(b.confidence || 0) - Number(a.confidence || 0)
  }).slice(0, 12), [correlations])

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

      <section className="card">
        <div className="graph-title-row">
          <h3 className="card-title">Explorador de entidades</h3>
          <select className="graph-select" value={nodeType} onChange={event => setNodeType(event.target.value)}>
            <option value="all">Todos os tipos</option>
            {nodeTypes.map(type => <option key={type} value={type}>{type}</option>)}
          </select>
        </div>
        <div className="entity-grid">
          {visibleNodes.map(node => (
            <div key={node.id} className="entity-chip">
              <span className="entity-type">{node.type}</span>
              <strong>{node.label}</strong>
              {Number(node.risk_score || 0) > 0 && <span className="entity-risk">risco {Number(node.risk_score).toFixed(1)}</span>}
            </div>
          ))}
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
