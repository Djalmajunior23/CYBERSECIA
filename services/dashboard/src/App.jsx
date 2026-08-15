import React, { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard'
import HITLQueue from './components/HITLQueue'
import AgentStatus from './components/AgentStatus'
import IncidentView from './components/IncidentView'
import VulnerabilityView from './components/VulnerabilityView'
import IntelligenceGraphView from './components/IntelligenceGraphView'
import SOARPlaybookView from './components/SOARPlaybookView'
import { getWsUrl, getApiUrl, getStoredBackendUrl, setStoredBackendUrl } from './config'
import './styles.css'

function App() {
  const [activeTab, setActiveTab] = useState('dashboard')
  const [wsConnected, setWsConnected] = useState(false)
  const [serverKey, setServerKey] = useState(0) // Trigger para reconectar WS
  const [stats, setStats] = useState({
    agents: 16,
    healthy: 0,
    alerts: 0,
    incidents: 0,
    hitl: 0,
    assets: 0,
    vulnerabilities: 0,
    critical_vulnerabilities: 0,
    remediation_open: 0,
    graph_nodes: 0,
    graph_edges: 0,
    correlations: 0
  })

  // Conexão WebSocket
  useEffect(() => {
    let ws
    let reconnectTimer
    let stopped = false

    const connect = () => {
      try {
        ws = new WebSocket(getWsUrl())

        ws.onopen = () => setWsConnected(true)
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            if (data.type === 'stats') setStats(data.payload)
          } catch (error) {
            console.error('Mensagem WebSocket inválida', error)
          }
        }
        ws.onclose = () => {
          setWsConnected(false)
          if (!stopped) reconnectTimer = window.setTimeout(connect, 3000)
        }
        ws.onerror = () => {
          setWsConnected(false)
          if (ws && ws.readyState < WebSocket.CLOSING) ws.close()
        }
      } catch (err) {
        setWsConnected(false)
        if (!stopped) reconnectTimer = window.setTimeout(connect, 4000)
      }
    }

    connect()
    return () => {
      stopped = true
      window.clearTimeout(reconnectTimer)
      if (ws && ws.readyState < WebSocket.CLOSING) ws.close()
    }
  }, [serverKey])

  // Fallback HTTP de Estatísticas caso o WebSocket esteja desconectado
  useEffect(() => {
    let active = true
    const fetchStatsFallback = async () => {
      try {
        const res = await fetch(getApiUrl('/api/stats'))
        if (res.ok) {
          const data = await res.json()
          if (active) setStats(data)
        }
      } catch (err) {
        // Silencioso se o websocket cuidar disso
      }
    }
    fetchStatsFallback()
    const timer = setInterval(fetchStatsFallback, 8000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [serverKey])

  const handleConfigServer = () => {
    const current = getStoredBackendUrl() || getApiUrl('').replace(/\/api$/, '')
    const input = window.prompt(
      'Informe a URL completa do seu backend no Render (ex: https://cybersecia-api.onrender.com):',
      current
    )
    if (input !== null) {
      setStoredBackendUrl(input.trim())
      setServerKey(k => k + 1) // Força reconexão
    }
  }

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: '📊' },
    { id: 'playbooks', label: 'Playbooks SOAR', icon: '⚡' },
    { id: 'hitl', label: 'Fila HITL', icon: '👤' },
    { id: 'agents', label: 'Agentes', icon: '🤖' },
    { id: 'vulnerabilities', label: 'Vulnerabilidades', icon: '🧩' },
    { id: 'intelligence', label: 'Intelligence Graph', icon: '🕸️' },
    { id: 'incidents', label: 'Incidentes', icon: '🚨' }
  ]

  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <span className="shield">🛡️</span>
          <h1>CyberSec AI Ecosystem</h1>
        </div>
        <div className="status-bar">
          <button 
            className="filter-btn" 
            onClick={handleConfigServer} 
            title="Configurar URL do Backend Render"
            style={{ padding: '4px 10px', fontSize: '12px' }}
          >
            ⚙️ Servidor
          </button>
          <span className={`ws-indicator ${wsConnected ? 'online' : 'offline'}`}>
            {wsConnected ? '🟢 Conectado' : '🔴 Desconectado'}
          </span>
          <span className="version">v1.4.0</span>
        </div>
      </header>

      <nav className="sidebar">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`nav-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="nav-icon">{tab.icon}</span>
            <span className="nav-label">{tab.label}</span>
          </button>
        ))}

        <div className="stats-panel">
          <div className="stat-item">
            <span className="stat-value">{stats.agents}</span>
            <span className="stat-label">Agentes</span>
          </div>
          <div className="stat-item">
            <span className="stat-value healthy">{stats.healthy}</span>
            <span className="stat-label">Healthy</span>
          </div>
          <div className="stat-item">
            <span className="stat-value alert">{stats.alerts}</span>
            <span className="stat-label">Alertas</span>
          </div>
          <div className="stat-item">
            <span className="stat-value critical">{stats.incidents}</span>
            <span className="stat-label">Incidentes</span>
          </div>
        </div>
      </nav>

      <main className="content">
        {activeTab === 'dashboard' && <Dashboard stats={stats} wsConnected={wsConnected} />}
        {activeTab === 'playbooks' && <SOARPlaybookView />}
        {activeTab === 'hitl' && <HITLQueue />}
        {activeTab === 'agents' && <AgentStatus />}
        {activeTab === 'vulnerabilities' && <VulnerabilityView />}
        {activeTab === 'intelligence' && <IntelligenceGraphView />}
        {activeTab === 'incidents' && <IncidentView />}
      </main>
    </div>
  )
}

export default App
