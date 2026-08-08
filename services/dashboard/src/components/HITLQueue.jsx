import React, { useEffect, useState } from 'react'
import { getApiUrl } from '../config'

export default function HITLQueue() {
  const [queue, setQueue] = useState([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')

  const loadQueue = async () => {
    try {
      const response = await fetch(getApiUrl('/api/hitl'))
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      setQueue(await response.json())
      setError('')
    } catch (err) {
      setError(`Não foi possível carregar a fila HITL: ${err.message}`)
    }
  }

  useEffect(() => {
    loadQueue()
    const timer = window.setInterval(loadQueue, 4000)
    return () => window.clearInterval(timer)
  }, [])

  const decide = async (item, decision) => {
    let token = window.sessionStorage.getItem('cybersec_admin_token')
    if (!token) {
      token = window.prompt('Informe o API_ADMIN_TOKEN para autorizar esta decisão:')
      if (!token) return
      window.sessionStorage.setItem('cybersec_admin_token', token)
    }

    setBusy(item.request_id)
    try {
      const response = await fetch(getApiUrl(`/api/hitl/${encodeURIComponent(item.request_id)}/decision`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': token },
        body: JSON.stringify({
          decision,
          approver: 'dashboard_operator',
          reason: decision === 'approve' ? 'Approved through HITL dashboard' : 'Denied through HITL dashboard'
        })
      })
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}))
        if (response.status === 401) window.sessionStorage.removeItem('cybersec_admin_token')
        throw new Error(payload.detail || `HTTP ${response.status}`)
      }
      await loadQueue()
    } catch (err) {
      setError(`Falha ao registrar decisão HITL: ${err.message}`)
    } finally {
      setBusy('')
    }
  }

  return (
    <div>
      <h2 style={{ marginBottom: '20px', color: '#e2e8f0' }}>Fila de Aprovação Humana (HITL)</h2>
      <p style={{ color: '#94a3b8', marginBottom: '16px' }}>
        {queue.length} item(s) aguardando aprovação. Ações críticas exigem uma decisão humana autenticada.
      </p>
      {error && <div className="error-banner">{error}</div>}
      {!error && queue.length === 0 && <div className="empty-state">Nenhuma ação aguardando aprovação.</div>}
      {queue.map(item => (
        <div key={item.request_id} className="hitl-item critical">
          <div>
            <div style={{ fontWeight: '600', color: '#e2e8f0' }}>{item.request_id} — {item.task_type}</div>
            <div style={{ fontSize: '13px', color: '#94a3b8', marginTop: '4px' }}>
              Agente: {item.agent_id} | Status: {item.status}
            </div>
            <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>
              {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Sem timestamp'}
            </div>
          </div>
          <div className="hitl-actions">
            <button className="btn btn-details" onClick={() => window.alert(JSON.stringify(item, null, 2))}>Detalhes</button>
            <button className="btn btn-approve" disabled={busy === item.request_id} onClick={() => decide(item, 'approve')}>Aprovar</button>
            <button className="btn btn-deny" disabled={busy === item.request_id} onClick={() => decide(item, 'deny')}>Negar</button>
          </div>
        </div>
      ))}
    </div>
  )
}
