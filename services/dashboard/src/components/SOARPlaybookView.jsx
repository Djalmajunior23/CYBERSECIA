import React, { useEffect, useState, useMemo } from 'react'
import { getApiUrl } from '../config'

export default function SOARPlaybookView() {
  const [playbooks, setPlaybooks] = useState([])
  const [executions, setExecutions] = useState([])
  const [category, setCategory] = useState('all')
  const [selectedPlaybook, setSelectedPlaybook] = useState(null)
  const [targetHost, setTargetHost] = useState('192.168.1.105')
  const [executing, setExecuting] = useState(false)
  const [executionProgress, setExecutionProgress] = useState(0)
  const [activeStepIndex, setActiveStepIndex] = useState(-1)
  const [logs, setLogs] = useState([])
  const [error, setError] = useState('')
  const [lastResult, setLastResult] = useState(null)

  // Carregar Playbooks e Execuções
  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const [pbRes, execRes] = await Promise.all([
          fetch(getApiUrl('/api/playbooks')),
          fetch(getApiUrl('/api/playbooks/executions'))
        ])
        if (!pbRes.ok) throw new Error('Não foi possível carregar o catálogo de playbooks')
        const pbData = await pbRes.json()
        const execData = execRes.ok ? await execRes.json() : []

        if (active) {
          setPlaybooks(pbData)
          setExecutions(execData)
          setError('')
        }
      } catch (err) {
        if (active) setError(err.message)
      }
    }
    load()
    const timer = setInterval(load, 12000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [])

  const filteredPlaybooks = useMemo(() => {
    return playbooks.filter(pb => {
      if (category === 'all') return true
      return pb.category === category || pb.severity === category
    })
  }, [playbooks, category])

  // Simular/Disparar Execução de Playbook SOAR
  const handleExecute = async (pb, mode = 'simulation') => {
    setSelectedPlaybook(pb)
    setExecuting(true)
    setExecutionProgress(0)
    setActiveStepIndex(0)
    setLastResult(null)
    setLogs([`[${new Date().toLocaleTimeString()}] 🚀 Inicializando SOAR Engine no modo [${mode.toUpperCase()}]`])

    try {
      // Disparar requisição de execução na API
      const res = await fetch(getApiUrl(`/api/playbooks/${pb.id}/execute`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_host: targetHost,
          operator: 'Operador SOC Admin',
          mode: mode
        })
      })
      const result = await res.json()
      setLastResult(result)

      // Simulação visual de passos encadeados
      const totalSteps = pb.steps.length
      for (let i = 0; i < totalSteps; i++) {
        await new Promise(r => setTimeout(r, 900))
        const step = pb.steps[i]
        setActiveStepIndex(i)
        setExecutionProgress(Math.round(((i + 1) / totalSteps) * 100))
        
        setLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] Step ${i + 1}/${totalSteps} (${step.action}): ${step.name} -> ${step.auth === 'hitl' ? '🟡 Retido para Aprovação HITL' : '🟢 Concluído com Sucesso'}`
        ])

        if (step.auth === 'hitl' && mode === 'live') {
          setLogs(prev => [
            ...prev,
            `[${new Date().toLocaleTimeString()}] ⚠️ Pausando playbook. Solicitando autorização do operador L3 na Fila HITL...`
          ])
          break
        }
      }

      setLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] ✅ Execução do Playbook "${pb.title}" finalizada!`
      ])

      // Atualizar lista de histórico de execuções
      const execRes = await fetch(getApiUrl('/api/playbooks/executions'))
      if (execRes.ok) {
        const updatedExecs = await execRes.json()
        setExecutions(updatedExecs)
      }

    } catch (err) {
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ❌ Erro ao disparar playbook: ${err.message}`])
    } finally {
      setExecuting(false)
    }
  }

  return (
    <div className="soar-view">
      <div className="soar-header">
        <div>
          <h2>SOAR Automation & Playbook Studio</h2>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px' }}>
            Orquestração automatizada de respostas a incidentes, isolamento ativo de ameaças e simulações em Sandbox.
          </p>
        </div>

        <div className="target-selector">
          <label style={{ fontSize: '13px', color: '#cbd5e1' }}>Alvo de Resposta (Target Host/IP):</label>
          <input
            type="text"
            className="target-input"
            value={targetHost}
            onChange={e => setTargetHost(e.target.value)}
            placeholder="ex: 192.168.1.105"
          />
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Barra de Filtros */}
      <div className="filter-toolbar">
        {[
          { id: 'all', label: 'Todos os Playbooks' },
          { id: 'critical', label: '🔴 Severidade Crítica' },
          { id: 'incident_response', label: '🛡️ Resposta a Incidentes' },
          { id: 'ai_security', label: '🤖 Segurança de IA' },
          { id: 'behavioral_threat', label: '👤 Ameaça Comportamental' },
          { id: 'containment', label: '🔒 Contenção & Isolamento' }
        ].map(f => (
          <button
            key={f.id}
            className={`filter-btn ${category === f.id ? 'active' : ''}`}
            onClick={() => setCategory(f.id)}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Modal/Console de Execução Ativa */}
      {selectedPlaybook && (
        <div className="execution-console card" style={{ borderColor: selectedPlaybook.severity === 'critical' ? '#ef4444' : '#3b82f6' }}>
          <div className="console-header">
            <div>
              <span className="console-badge">EXECUÇÃO ATIVA</span>
              <h3 style={{ margin: '6px 0 2px 0', color: '#f8fafc' }}>{selectedPlaybook.title}</h3>
              <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                Alvo: <strong style={{ color: '#60a5fa' }}>{targetHost}</strong> | SLA Alvo: {selectedPlaybook.sla_minutes} min
              </div>
            </div>
            <button className="filter-btn" onClick={() => setSelectedPlaybook(null)} disabled={executing}>
              ✖ Fechar Console
            </button>
          </div>

          {/* Barra de Progresso */}
          <div className="progress-container" style={{ margin: '16px 0 12px 0' }}>
            <div className="progress-label">
              <span>Progresso do Playbook</span>
              <span>{executionProgress}%</span>
            </div>
            <div className="progress-track" style={{ height: '8px' }}>
              <div
                className="progress-value"
                style={{
                  width: `${executionProgress}%`,
                  backgroundColor: executionProgress === 100 ? '#10b981' : '#3b82f6',
                  transition: 'width 0.4s ease'
                }}
              />
            </div>
          </div>

          {/* Pipeline de Passos em Tempo Real */}
          <div className="steps-pipeline">
            {selectedPlaybook.steps.map((step, idx) => {
              const isDone = activeStepIndex > idx || executionProgress === 100
              const isCurrent = activeStepIndex === idx && executing
              const isPending = activeStepIndex < idx && !isDone
              const isHitl = step.auth === 'hitl'

              return (
                <div
                  key={step.id}
                  className={`pipeline-step ${isDone ? 'step-done' : ''} ${isCurrent ? 'step-active' : ''} ${isPending ? 'step-pending' : ''} ${isHitl ? 'step-hitl' : ''}`}
                >
                  <div className="step-number">{idx + 1}</div>
                  <div className="step-info">
                    <div className="step-name">{step.name}</div>
                    <div className="step-meta">
                      {step.action} {isHitl && <span className="hitl-pill">HITL</span>}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Log de Terminal */}
          <div className="terminal-window">
            <div className="terminal-header">
              <span className="dot red"></span>
              <span className="dot yellow"></span>
              <span className="dot green"></span>
              <span style={{ fontSize: '12px', color: '#94a3b8', marginLeft: '8px' }}>SOAR Execution Audit Log</span>
            </div>
            <div className="terminal-body">
              {logs.map((log, i) => (
                <div key={i} className="terminal-line">{log}</div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Grid de Playbooks */}
      <div className="playbook-grid">
        {filteredPlaybooks.map(pb => (
          <div key={pb.id} className={`playbook-card ${pb.severity === 'critical' ? 'critical-glow' : ''}`}>
            <div className="playbook-header">
              <span className={`risk-badge risk-${pb.severity}`}>{pb.severity.toUpperCase()}</span>
              <span className="version-tag">v{pb.version}</span>
            </div>

            <h3 className="playbook-title">{pb.title}</h3>
            <p className="playbook-desc">{pb.description}</p>

            <div className="trigger-box">
              <div style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '4px' }}>CONDIÇÃO DE GATILHO:</div>
              <code>{pb.trigger}</code>
            </div>

            <div className="playbook-meta-grid">
              <div>
                <span className="meta-label">SLA de Resposta</span>
                <span className="meta-value">{pb.sla_minutes} min</span>
              </div>
              <div>
                <span className="meta-label">Execução Auto</span>
                <span className="meta-value">{pb.auto_execute ? 'Sim' : 'Não'}</span>
              </div>
              <div>
                <span className="meta-label">Exige HITL</span>
                <span className="meta-value">{pb.requires_hitl ? 'Sim' : 'Não'}</span>
              </div>
              <div>
                <span className="meta-label">Total de Etapas</span>
                <span className="meta-value">{pb.steps.length} passos</span>
              </div>
            </div>

            <div className="playbook-actions">
              <button
                className="filter-btn active"
                onClick={() => handleExecute(pb, 'simulation')}
                disabled={executing}
                style={{ flex: 1 }}
              >
                ⚡ Simular (Sandbox)
              </button>
              <button
                className="filter-btn"
                onClick={() => handleExecute(pb, 'live')}
                disabled={executing}
                style={{ flex: 1, borderColor: '#ef4444', color: '#ef4444' }}
              >
                🔴 Executar (Live)
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Tabela de Execuções Recentes */}
      <div className="card" style={{ marginTop: '28px' }}>
        <div className="card-title">Histórico de Execuções SOAR</div>
        {executions.length === 0 ? (
          <div className="empty-state">Nenhuma execução registrada no histórico até o momento.</div>
        ) : (
          <table className="audit-table">
            <thead>
              <tr>
                <th>ID da Execução</th>
                <th>Playbook</th>
                <th>Modo</th>
                <th>Alvo</th>
                <th>Operador</th>
                <th>Status</th>
                <th>Data / Hora</th>
              </tr>
            </thead>
            <tbody>
              {executions.map(ex => (
                <tr key={ex.execution_id}>
                  <td><code>{ex.execution_id}</code></td>
                  <td><strong>{ex.title}</strong></td>
                  <td>
                    <span className={`status-tag ${ex.mode === 'live' ? 'live-tag' : 'sim-tag'}`}>
                      {ex.mode.toUpperCase()}
                    </span>
                  </td>
                  <td>{ex.target_host}</td>
                  <td>{ex.operator}</td>
                  <td>
                    <span className={`status-tag ${ex.status === 'completed' ? 'success' : 'pending'}`}>
                      {ex.status === 'completed' ? '🟢 Concluído' : '🟡 HITL Pendente'}
                    </span>
                  </td>
                  <td>{new Date(ex.started_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
