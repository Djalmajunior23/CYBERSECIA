import React, { useEffect, useState } from 'react'

export default function AgentStatus() {
  const [agents, setAgents] = useState([])
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const response = await fetch('/api/agents')
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const data = await response.json()
        if (active) {
          setAgents(data)
          setError('')
        }
      } catch (err) {
        if (active) setError(`Não foi possível carregar os agentes: ${err.message}`)
      }
    }
    load()
    const timer = window.setInterval(load, 5000)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [])

  return (
    <div>
      <h2 style={{ marginBottom: '20px', color: '#e2e8f0' }}>Status dos Agentes</h2>
      {error && <div className="error-banner">{error}</div>}
      {!error && agents.length === 0 && <div className="empty-state">Nenhuma telemetria disponível ainda.</div>}
      {agents.map(agent => (
        <div key={agent.id} className="agent-card">
          <div className={`agent-status ${agent.status || 'unknown'}`} />
          <div className="agent-info">
            <div className="agent-name">{agent.name}</div>
            <div className="agent-type">
              {agent.type} • {agent.capabilities?.length || 0} capabilities • {agent.status || 'unknown'}
            </div>
            {agent.last_heartbeat && <div className="agent-heartbeat">Heartbeat: {new Date(agent.last_heartbeat).toLocaleString()}</div>}
          </div>
          <div className="agent-load">Load: {agent.load ?? 0}</div>
        </div>
      ))}
    </div>
  )
}
