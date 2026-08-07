import React from 'react'

export default function Dashboard({ stats, wsConnected }) {
  const healthyPct = stats.agents ? Math.round((stats.healthy / stats.agents) * 100) : 0

  return (
    <div>
      <h2 style={{ marginBottom: '20px', color: '#e2e8f0' }}>Dashboard Principal</h2>

      <div className="card">
        <div className="card-title">Estado do Ecossistema</div>
        <p style={{ color: '#94a3b8' }}>
          Telemetria {wsConnected ? 'conectada em tempo real' : 'temporariamente desconectada'}.
          {' '}{stats.healthy} de {stats.agents} serviços de agente reportam estado saudável.
        </p>
      </div>

      <div className="card">
        <div className="card-title">Métricas Operacionais</div>
        <div className="metric-grid">
          <MetricCard label="Agentes Saudáveis" value={`${stats.healthy}/${stats.agents}`} detail={`${healthyPct}% do ecossistema`} />
          <MetricCard label="Alertas Registrados" value={stats.alerts} detail="stream MCP" warning={stats.alerts > 0} />
          <MetricCard label="Incidentes Ativos" value={stats.incidents} detail="correlacionados" critical={stats.incidents > 0} />
          <MetricCard label="Aprovações HITL" value={stats.hitl || 0} detail="aguardando decisão" warning={(stats.hitl || 0) > 0} />
          <MetricCard label="Ativos Descobertos" value={stats.assets || 0} detail="inventário central" />
          <MetricCard label="Vulnerabilidades" value={stats.vulnerabilities || 0} detail={`${stats.critical_vulnerabilities || 0} críticas`} critical={(stats.critical_vulnerabilities || 0) > 0} />
          <MetricCard label="Remediações" value={stats.remediation_open || 0} detail="fila SOAR" warning={(stats.remediation_open || 0) > 0} />
        </div>
      </div>

      <div className="card">
        <div className="card-title">Cobertura de Saúde</div>
        <p style={{ color: '#94a3b8' }}>Heartbeats recebidos: {healthyPct}% dos agentes conhecidos.</p>
        <div className="progress-track">
          <div className="progress-value" style={{ width: `${healthyPct}%` }} />
        </div>
      </div>
    </div>
  )
}

function MetricCard({ label, value, detail, critical, warning }) {
  return (
    <div className={`metric-card ${critical ? 'metric-critical' : warning ? 'metric-warning' : ''}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  )
}
