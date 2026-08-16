import React, { useEffect, useState, useMemo } from 'react'
import { getApiUrl } from '../config'

export default function ComplianceGovernanceView() {
  const [summary, setSummary] = useState(null)
  const [frameworksData, setFrameworksData] = useState({ frameworks: [], controls: [] })
  const [filterFramework, setFilterFramework] = useState('all')
  const [filterStatus, setFilterStatus] = useState('all')
  const [generatingReport, setGeneratingReport] = useState(false)
  const [lastReport, setLastReport] = useState(null)
  const [authorName, setAuthorName] = useState('DPO / CISO Office')
  const [error, setError] = useState('')

  // Carregar Dados da API de Governança
  useEffect(() => {
    let active = true
    const load = async () => {
      try {
        const [sumRes, fwRes] = await Promise.all([
          fetch(getApiUrl('/api/compliance/summary')),
          fetch(getApiUrl('/api/compliance/frameworks'))
        ])
        if (!sumRes.ok || !fwRes.ok) throw new Error('Não foi possível obter dados de compliance')
        const sumData = await sumRes.json()
        const fwData = await fwRes.json()

        if (active) {
          setSummary(sumData)
          setFrameworksData(fwData)
          setError('')
        }
      } catch (err) {
        if (active) setError(err.message)
      }
    }
    load()
    const timer = setInterval(load, 15000)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [])

  // Controles Filtrados
  const filteredControls = useMemo(() => {
    return (frameworksData.controls || []).filter(ctrl => {
      const matchFw = filterFramework === 'all' || ctrl.framework.toLowerCase().includes(filterFramework.toLowerCase())
      const matchStatus = filterStatus === 'all' || ctrl.status === filterStatus
      return matchFw && matchStatus
    })
  }, [frameworksData.controls, filterFramework, filterStatus])

  // Gerar Relatório Executivo
  const handleGenerateReport = async () => {
    setGeneratingReport(true)
    try {
      const res = await fetch(getApiUrl('/api/compliance/reports/generate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ author: authorName, format: 'markdown' })
      })
      const result = await res.json()
      setLastReport(result)
    } catch (err) {
      alert(`Erro ao gerar relatório: ${err.message}`)
    } finally {
      setGeneratingReport(false)
    }
  }

  return (
    <div className="compliance-view">
      <div className="compliance-header">
        <div>
          <h2>Centro de Governança de IA & Conformidade Regulatória</h2>
          <p style={{ color: '#94a3b8', fontSize: '14px', marginTop: '4px' }}>
            Monitoramento contínuo multi-framework: <strong>LGPD</strong>, <strong>EU AI Act</strong>, <strong>NIST AI RMF 1.0</strong> e <strong>ISO/IEC 42001</strong>.
          </p>
        </div>

        <div className="report-action">
          <button className="filter-btn active" onClick={handleGenerateReport} disabled={generatingReport}>
            {generatingReport ? '⏳ Gerando Relatório...' : '📜 Emitir Relatório CISO / DPO'}
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Relatório Gerado Modal / Preview */}
      {lastReport && (
        <div className="card report-card">
          <div className="console-header">
            <div>
              <span className="status-tag success">RELATÓRIO EMITIDO</span>
              <h3 style={{ margin: '6px 0 2px 0', color: '#f8fafc' }}>Relatório Oficial de Auditoria</h3>
              <div style={{ fontSize: '12px', color: '#94a3b8' }}>
                ID: <code>{lastReport.report_id}</code> | Hash SHA-256: <code>{lastReport.integrity_hash}</code>
              </div>
            </div>
            <button className="filter-btn" onClick={() => setLastReport(null)}>✖ Fechar</button>
          </div>
          <pre className="report-preview-box">{lastReport.report_preview}</pre>
        </div>
      )}

      {/* Visão Geral da Saúde e Score */}
      {summary && (
        <div className="compliance-stats-grid">
          <div className="card score-card">
            <div className="score-label">SCORE GERAL DE CONFORMIDADE</div>
            <div className="score-value">{summary.overall_score}%</div>
            <div className="score-badge">TOTALMENTE CONFORME</div>
          </div>

          <div className="card ai-safety-card">
            <div className="card-title">Métricas de Segurança & Alinhamento de IA</div>
            <div className="ai-safety-grid">
              <div>
                <span className="meta-label">Prompt Injection Defense</span>
                <span className="meta-value" style={{ color: '#10b981' }}>
                  {summary.ai_safety.prompt_injection_resistance}%
                </span>
              </div>
              <div>
                <span className="meta-label">Proteção de PII (LGPD)</span>
                <span className="meta-value" style={{ color: '#10b981' }}>
                  {summary.ai_safety.pii_leak_prevention}%
                </span>
              </div>
              <div>
                <span className="meta-label">Viés Algorítmico (Bias Index)</span>
                <span className="meta-value" style={{ color: '#38bdf8' }}>
                  {summary.ai_safety.algorithmic_bias_score} (Ótimo)
                </span>
              </div>
              <div>
                <span className="meta-label">Integridade Ferramentas MCP</span>
                <span className="meta-value" style={{ color: '#10b981' }}>
                  {summary.ai_safety.mcp_tool_integrity}%
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Cards por Framework Regulatório */}
      <div className="frameworks-grid">
        {(frameworksData.frameworks || []).map(fw => (
          <div key={fw.id} className="framework-card">
            <div className="framework-header">
              <span className="fw-title">{fw.name}</span>
              <span className="fw-score">{fw.score}%</span>
            </div>
            <p className="fw-desc">{fw.description}</p>
            <div className="fw-controls-summary">
              <span className="cnt-pass">🟢 {fw.passed_controls} Aprovados</span>
              <span className="cnt-warn">🟡 {fw.warn_controls} Alerta</span>
              <span className="cnt-fail">🔴 {fw.failed_controls} Falhas</span>
            </div>
          </div>
        ))}
      </div>

      {/* Matriz de Controles de Auditoria */}
      <div className="card" style={{ marginTop: '20px' }}>
        <div className="controls-header">
          <div className="card-title">Matriz de Controles e Evidências Auditadas</div>
          <div className="controls-filters">
            <select
              className="filter-btn"
              value={filterFramework}
              onChange={e => setFilterFramework(e.target.value)}
              style={{ padding: '6px 12px' }}
            >
              <option value="all">Todos os Frameworks</option>
              <option value="lgpd">LGPD</option>
              <option value="eu ai act">EU AI Act</option>
              <option value="nist ai rmf">NIST AI RMF</option>
              <option value="iso 42001">ISO 42001</option>
            </select>

            <select
              className="filter-btn"
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value)}
              style={{ padding: '6px 12px' }}
            >
              <option value="all">Todos os Status</option>
              <option value="PASS">PASS (Aprovado)</option>
              <option value="WARN">WARN (Alerta)</option>
              <option value="FAIL">FAIL (Falha)</option>
            </select>
          </div>
        </div>

        <table className="audit-table" style={{ marginTop: '12px' }}>
          <thead>
            <tr>
              <th>ID Controle</th>
              <th>Framework</th>
              <th>Título do Controle</th>
              <th>Status</th>
              <th>Agente Responsável</th>
              <th>Evidência de Auditoria</th>
            </tr>
          </thead>
          <tbody>
            {filteredControls.map(ctrl => (
              <tr key={ctrl.id}>
                <td><code>{ctrl.id}</code></td>
                <td><strong>{ctrl.framework}</strong></td>
                <td>{ctrl.title}</td>
                <td>
                  <span className={`status-tag ${ctrl.status === 'PASS' ? 'success' : 'pending'}`}>
                    {ctrl.status === 'PASS' ? '🟢 PASS' : '🟡 WARN'}
                  </span>
                </td>
                <td><code>{ctrl.agent}</code></td>
                <td style={{ fontSize: '12px', color: '#cbd5e1' }}>{ctrl.evidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
