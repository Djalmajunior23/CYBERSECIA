import React, { useEffect, useMemo, useState } from 'react'
import { getApiUrl } from '../config'

const severityToPriority = {
  critical: 'p1',
  high: 'p2',
  medium: 'p3',
  low: 'p4',
  info: 'p4'
}

export default function IncidentView() {
  const [filter, setFilter] = useState('all')
  const [incidents, setIncidents] = useState([])
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const response = await fetch(getApiUrl('/api/incidents'))
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const data = await response.json()
        if (active) {
          setIncidents(data)
          setError('')
        }
      } catch (err) {
        if (active) setError(`Não foi possível carregar incidentes: ${err.message}`)
      }
    }
    load()
    const timer = window.setInterval(load, 5000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  const normalized = useMemo(() => incidents.map(incident => ({
    ...incident,
    priority: severityToPriority[incident.severity || incident.alert?.severity] || 'p4',
    title: incident.title || incident.alert?.title || incident.incident_id,
    source: incident.source || incident.alert?.source || 'unknown'
  })), [incidents])

  const filtered = filter === 'all' ? normalized : normalized.filter(i => i.priority === filter)

  return (
    <div>
      <h2 style={{ marginBottom: '20px', color: '#e2e8f0' }}>Incidentes</h2>
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
        {['all', 'p1', 'p2', 'p3', 'p4'].map(f => (
          <button key={f} onClick={() => setFilter(f)} className={`filter-btn ${filter === f ? 'active' : ''}`}>
            {f === 'all' ? 'Todos' : f.toUpperCase()}
          </button>
        ))}
      </div>
      {error && <div className="error-banner">{error}</div>}
      {!error && filtered.length === 0 && <div className="empty-state">Nenhum incidente para este filtro.</div>}
      {filtered.map(inc => (
        <div key={inc.incident_id} className="incident-row">
          <span className={`severity-${inc.priority}`}>{inc.priority.toUpperCase()}</span>
          <span style={{ color: '#e2e8f0', fontWeight: 500 }}>{inc.title}</span>
          <span style={{ color: '#94a3b8', fontSize: '13px' }}>{inc.status}</span>
          <span style={{ color: '#64748b', fontSize: '12px' }}>
            {inc.start_time ? new Date(inc.start_time).toLocaleString() : '—'}
          </span>
          <span style={{ color: '#64748b', fontSize: '12px' }}>{inc.source}</span>
        </div>
      ))}
    </div>
  )
}
