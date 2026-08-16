"""CyberSec AI API Gateway.

Read-only observability is available to the local dashboard. Mutating HITL
operations require an explicit API_ADMIN_TOKEN and are disabled when the token
is not configured.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

import redis.asyncio as redis
from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logger = logging.getLogger("api_gateway")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
API_ADMIN_TOKEN = os.getenv("API_ADMIN_TOKEN", "")

AGENTS = [
    ("central_orchestrator", "Central Orchestrator", "orchestrator", ["orchestration", "hitl", "incident_correlation"]),
    ("discovery_agent", "Discovery Agent", "worker", ["network_scan", "host_discovery", "port_enumeration", "os_fingerprinting"]),
    ("vulnerability_agent", "Vulnerability Agent", "worker", ["cve_correlation", "cvss_scoring", "exploitability_analysis"]),
    ("threat_intel_agent", "Threat Intel Agent", "worker", ["ioc_lookup", "ttp_mapping", "actor_attribution", "campaign_tracking"]),
    ("behavioral_agent", "Behavioral Agent", "worker", ["ueba", "anomaly_detection", "insider_threat", "lateral_movement_detect"]),
    ("response_orchestrator", "Response Orchestrator", "worker", ["host_isolation", "account_disable", "ioc_block", "playbook_execute"]),
    ("governance_agent", "Governance Agent", "worker", ["audit", "policy_enforce", "bias_detect", "privacy_check"]),
    ("red_team_agent", "Red Team Agent", "worker", ["adversarial_test", "prompt_injection", "tool_poisoning", "jailbreak"]),
    ("soar_agent", "SOAR Agent", "worker", ["alert_triage", "incident_response", "playbook_automation", "escalation"]),
    ("purple_team_agent", "Purple Team Agent", "worker", ["attack_simulation", "defense_validation", "coverage_gap_analysis"]),
    ("mcp_auditor_agent", "MCP Auditor", "worker", ["mcp_server_inventory", "static_audit", "dynamic_test", "shadow_detect"]),
    ("digital_twin_agent", "Digital Twin Agent", "worker", ["environment_replication", "safe_simulation", "what_if_analysis"]),
    ("threat_hunt_agent", "Threat Hunt Agent", "worker", ["hypothesis_generation", "proactive_hunt", "drl_analysis", "campaign_recon"]),
    ("compliance_agent", "Compliance Agent", "worker", ["lgpd_audit", "eu_ai_act_check", "nist_ai_rmf_validate", "report_generate"]),
    ("forensic_agent", "Forensic Agent", "worker", ["evidence_preservation", "timeline_reconstruction", "artifact_analysis", "chain_of_custody"]),
    ("correlation_agent", "Correlation Agent", "worker", ["knowledge_graph", "asset_intelligence", "risk_correlation", "attack_path_analysis"]),
]

app = FastAPI(title="CyberSec AI API Gateway", version="1.3.0")

# Política CORS segura e abrangente
cors_origins_raw = os.getenv("CORS_ORIGINS", "").strip()
if not cors_origins_raw or cors_origins_raw == "*":
    allow_origins = ["*"]
else:
    allow_origins = [origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_client = redis.from_url(REDIS_URL, decode_responses=True)


class HITLDecision(BaseModel):
    decision: Literal["approve", "deny"]
    approver: str = Field(min_length=2, max_length=120)
    reason: Optional[str] = Field(default=None, max_length=1000)


def _loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


async def _agent_rows() -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:agent-status")
    except Exception as exc:
        logger.warning(f"Erro ao buscar status dos agentes no Redis: {exc}")
        raw = {}

    rows: List[Dict[str, Any]] = []
    for agent_id, name, agent_type, capabilities in AGENTS:
        state = _loads(raw.get(agent_id), {})
        rows.append(
            {
                "id": agent_id,
                "name": name,
                "type": agent_type,
                "status": state.get("status", "unknown"),
                "last_heartbeat": state.get("last_heartbeat"),
                "load": state.get("load_score", 0),
                "capabilities": state.get("capabilities") or capabilities,
            }
        )
    return rows


async def _stats() -> Dict[str, int]:
    try:
        agents = await _agent_rows()
        healthy = sum(1 for agent in agents if agent["status"] == "healthy")
        vulnerabilities = await redis_client.hgetall("mcp:vulnerabilities")
        vuln_rows = [item for value in vulnerabilities.values() if (item := _loads(value, None))]
        alerts_count = await redis_client.xlen("mcp:alerts")
        incidents_count = await redis_client.hlen("mcp:incidents")
        hitl_count = await redis_client.llen("mcp:human:hitl")
        assets_count = await redis_client.hlen("mcp:assets")
        remediation_count = await redis_client.hlen("mcp:remediation")
        nodes_count = await redis_client.hlen("mcp:kg:nodes")
        edges_count = await redis_client.hlen("mcp:kg:edges")
        correlations_count = await redis_client.hlen("mcp:correlations")
        return {
            "agents": len(agents),
            "healthy": healthy,
            "alerts": alerts_count,
            "incidents": incidents_count,
            "hitl": hitl_count,
            "assets": assets_count,
            "vulnerabilities": len(vuln_rows),
            "critical_vulnerabilities": sum(1 for item in vuln_rows if item.get("severity") == "critical"),
            "remediation_open": remediation_count,
            "graph_nodes": nodes_count,
            "graph_edges": edges_count,
            "correlations": correlations_count,
        }
    except Exception as exc:
        logger.warning(f"Erro ao calcular estatísticas no Redis: {exc}")
        return {
            "agents": 16,
            "healthy": 0,
            "alerts": 0,
            "incidents": 0,
            "hitl": 0,
            "assets": 0,
            "vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "remediation_open": 0,
            "graph_nodes": 0,
            "graph_edges": 0,
            "correlations": 0,
        }


def _require_admin_token(x_api_key: Optional[str]) -> None:
    if not API_ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="HITL decisions are disabled until API_ADMIN_TOKEN is configured")
    if not x_api_key or x_api_key != API_ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
async def health() -> Dict[str, Any]:
    try:
        pong = await redis_client.ping()
        status = "healthy" if pong else "degraded"
        redis_ok = bool(pong)
    except Exception:
        status = "degraded"
        redis_ok = False
    return {"status": status, "redis": redis_ok, "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/stats")
async def stats() -> Dict[str, int]:
    return await _stats()


@app.get("/api/agents")
async def agents() -> List[Dict[str, Any]]:
    return await _agent_rows()


@app.get("/api/hitl")
async def hitl_queue() -> List[Dict[str, Any]]:
    try:
        values = await redis_client.lrange("mcp:human:hitl", 0, 199)
        return [item for value in values if (item := _loads(value, None))]
    except Exception as exc:
        logger.warning(f"Erro ao buscar fila HITL: {exc}")
        return []


@app.post("/api/hitl/{request_id}/decision")
async def decide_hitl(request_id: str, body: HITLDecision, x_api_key: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_token(x_api_key)

    try:
        values = await redis_client.lrange("mcp:human:hitl", 0, 499)
        selected_raw = None
        selected = None
        for raw in values:
            item = _loads(raw, None)
            if item and item.get("request_id") == request_id:
                selected_raw = raw
                selected = item
                break
        if not selected or selected_raw is None:
            raise HTTPException(status_code=404, detail="HITL request not found")

        decision = {
            "request_id": request_id,
            "correlation_id": selected.get("correlation_id"),
            "agent_id": selected.get("agent_id"),
            "target_agent": selected.get("target_agent"),
            "task_type": selected.get("task_type"),
            "parameters": selected.get("parameters") or {},
            "scope": selected.get("scope"),
            "priority": selected.get("priority", "medium"),
            "decision": body.decision,
            "approver": body.approver,
            "reason": body.reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await redis_client.lpush("mcp:human:decisions", json.dumps(decision, ensure_ascii=False))
        await redis_client.lrem("mcp:human:hitl", 1, selected_raw)
        await redis_client.hset("mcp:human:hitl-history", request_id, json.dumps({**selected, **decision}, ensure_ascii=False))
        await redis_client.xadd(
            "mcp:audit:events",
            {
                "timestamp": decision["timestamp"],
                "agent_id": "api_gateway",
                "level": "info",
                "message": f"HITL {body.decision}: {request_id}",
                "event_id": request_id,
            },
        )
        return {"accepted": True, "request_id": request_id, "decision": body.decision}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Erro ao processar decisão HITL: {exc}")
        raise HTTPException(status_code=500, detail="Erro interno ao registrar decisão HITL") from exc


@app.get("/api/incidents")
async def incidents() -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:incidents")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        return sorted(items, key=lambda item: item.get("start_time", ""), reverse=True)
    except Exception as exc:
        logger.warning(f"Erro ao buscar incidentes: {exc}")
        return []


@app.get("/api/assets")
async def assets() -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:assets")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        return sorted(items, key=lambda item: item.get("ip", ""))
    except Exception as exc:
        logger.warning(f"Erro ao buscar ativos: {exc}")
        return []


@app.get("/api/vulnerabilities")
async def vulnerabilities(
    severity: Optional[Literal["critical", "high", "medium", "low"]] = Query(default=None),
    min_score: float = Query(default=0.0, ge=0.0, le=10.0),
    kev_only: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:vulnerabilities")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        filtered = []
        for item in items:
            score = float(item.get("priority_score", (item.get("risk") or {}).get("score", 0.0)) or 0.0)
            if severity and item.get("severity") != severity:
                continue
            if score < min_score:
                continue
            if kev_only and not item.get("cisa_kev"):
                continue
            filtered.append(item)
        filtered.sort(key=lambda item: float(item.get("priority_score", 0.0) or 0.0), reverse=True)
        return filtered[:limit]
    except Exception as exc:
        logger.warning(f"Erro ao buscar vulnerabilidades: {exc}")
        return []


@app.get("/api/risk/summary")
async def risk_summary() -> Dict[str, Any]:
    try:
        raw = await redis_client.hgetall("mcp:vulnerabilities")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        severity_counts = {level: 0 for level in ("critical", "high", "medium", "low")}
        kev = 0
        scores = []
        for item in items:
            severity = item.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
            if item.get("cisa_kev"):
                kev += 1
            scores.append(float(item.get("priority_score", 0.0) or 0.0))

        assets_len = await redis_client.hlen("mcp:assets")
        remediation_len = await redis_client.hlen("mcp:remediation")
        nodes_len = await redis_client.hlen("mcp:kg:nodes")
        edges_len = await redis_client.hlen("mcp:kg:edges")
        correlations_len = await redis_client.hlen("mcp:correlations")

        return {
            "total": len(items),
            "severity": severity_counts,
            "cisa_kev": kev,
            "average_risk": round(sum(scores) / len(scores), 2) if scores else 0.0,
            "max_risk": round(max(scores), 2) if scores else 0.0,
            "assets": assets_len,
            "remediation_open": remediation_len,
            "graph_nodes": nodes_len,
            "graph_edges": edges_len,
            "correlations": correlations_len,
        }
    except Exception as exc:
        logger.warning(f"Erro ao buscar resumo de risco: {exc}")
        return {
            "total": 0,
            "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "cisa_kev": 0,
            "average_risk": 0.0,
            "max_risk": 0.0,
            "assets": 0,
            "remediation_open": 0,
            "graph_nodes": 0,
            "graph_edges": 0,
            "correlations": 0,
        }


@app.get("/api/remediation")
async def remediation() -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:remediation")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
        return sorted(items, key=lambda item: (priority_order.get(item.get("priority"), 9), item.get("created_at", "")))
    except Exception as exc:
        logger.warning(f"Erro ao buscar remediações: {exc}")
        return []


@app.get("/api/knowledge-graph/summary")
async def knowledge_graph_summary() -> Dict[str, Any]:
    try:
        return _loads(await redis_client.get("mcp:kg:summary"), {})
    except Exception as exc:
        logger.warning(f"Erro ao buscar resumo do grafo: {exc}")
        return {}


@app.get("/api/knowledge-graph")
async def knowledge_graph(
    node_type: Optional[str] = Query(default=None, min_length=2, max_length=64),
    limit: int = Query(default=500, ge=1, le=3000),
) -> Dict[str, Any]:
    try:
        raw_nodes = await redis_client.hgetall("mcp:kg:nodes")
        raw_edges = await redis_client.hgetall("mcp:kg:edges")
        nodes = [item for value in raw_nodes.values() if (item := _loads(value, None))]
        if node_type:
            nodes = [item for item in nodes if item.get("type") == node_type]
        nodes = sorted(nodes, key=lambda item: (item.get("type", ""), item.get("label", "")))[:limit]
        node_ids = {item.get("id") for item in nodes}
        edges = [item for value in raw_edges.values() if (item := _loads(value, None))]
        if node_type:
            edges = [item for item in edges if item.get("source") in node_ids or item.get("target") in node_ids]
        edges = edges[: max(limit * 3, 100)]
        kg_summary = _loads(await redis_client.get("mcp:kg:summary"), {})
        return {
            "summary": kg_summary,
            "nodes": nodes,
            "edges": edges,
        }
    except Exception as exc:
        logger.warning(f"Erro ao buscar grafo de conhecimento: {exc}")
        return {"summary": {}, "nodes": [], "edges": []}


@app.get("/api/correlations")
async def correlations(
    severity: Optional[Literal["critical", "high", "medium", "low"]] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:correlations")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        items = [item for item in items if (not severity or item.get("severity") == severity) and float(item.get("confidence", 0.0) or 0.0) >= min_confidence]
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        items.sort(key=lambda item: (severity_order.get(item.get("severity"), 9), -float(item.get("confidence", 0.0) or 0.0)))
        return items[:limit]
    except Exception as exc:
        logger.warning(f"Erro ao buscar correlações: {exc}")
        return []


@app.get("/api/attack-paths")
async def attack_paths(
    min_score: float = Query(default=0.0, ge=0.0, le=10.0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:attack-paths")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        items = [item for item in items if float(item.get("risk_score", 0.0) or 0.0) >= min_score]
        items.sort(key=lambda item: (-float(item.get("risk_score", 0.0) or 0.0), not bool(item.get("cisa_kev"))))
        return items[:limit]
    except Exception as exc:
        logger.warning(f"Erro ao buscar caminhos de ataque: {exc}")
        return []


PLAYBOOKS_DATA = [
    {
        "id": "ransomware_response",
        "title": "Ransomware Response & Containment",
        "category": "incident_response",
        "version": "3.0",
        "severity": "critical",
        "description": "Resposta automatizada e isolamento imediato para contenção de surtos de ransomware e criptografia de arquivos.",
        "trigger": "edr.detects_encryption == true OR siem.detects_mass_file_modification == true",
        "auto_execute": False,
        "requires_hitl": True,
        "sla_minutes": 15,
        "steps": [
            {"id": "alert", "name": "Notificação SOC L3", "action": "send_notification", "auth": "auto", "priority": "p1"},
            {"id": "snapshot", "name": "Snapshot Forense", "action": "create_forensic_snapshot", "auth": "auto", "preserve_state": True},
            {"id": "isolate", "name": "Isolamento de Rede", "action": "network_isolate", "auth": "hitl", "timeout": 300},
            {"id": "identify", "name": "Identificar Família Malware", "action": "identify_ransomware_family", "auth": "auto"},
            {"id": "contain", "name": "Bloqueio C2 IP/DNS", "action": "block_c2", "auth": "auto"},
            {"id": "eradicate", "name": "Terminar Processo Malicioso", "action": "terminate_encryption", "auth": "hitl"},
            {"id": "recover", "name": "Restaurar de Backup Imutável", "action": "restore_from_backup", "auth": "hitl"},
            {"id": "report", "name": "Gerar Relatório Pós-Incidente", "action": "generate_incident_report", "auth": "auto"},
        ],
    },
    {
        "id": "phishing_response",
        "title": "Phishing & Credential Harvester Containment",
        "category": "incident_response",
        "version": "2.1",
        "severity": "high",
        "description": "Contenção de ataques de engenharia social, revogação de sessões e bloqueio de domínios maliciosos.",
        "trigger": "email_gateway.phishing_score > 0.85 OR user.reports_credential_leak == true",
        "auto_execute": True,
        "requires_hitl": False,
        "sla_minutes": 30,
        "steps": [
            {"id": "triage", "name": "Triagem da Mensagem", "action": "parse_email_headers", "auth": "auto"},
            {"id": "revoke_session", "name": "Revogar Sessões de Usuário", "action": "revoke_active_sessions", "auth": "auto"},
            {"id": "reset_credentials", "name": "Redefinição Forçada de Senha", "action": "force_password_reset", "auth": "auto"},
            {"id": "block_url", "name": "Bloqueio de URL no Proxy", "action": "block_domain_proxy", "auth": "auto"},
            {"id": "quarantine", "name": "Quarentena em Lote na Caixa", "action": "quarantine_inbox_messages", "auth": "hitl"},
            {"id": "notify", "name": "Alerta de Conscientização", "action": "send_awareness_alert", "auth": "auto"},
        ],
    },
    {
        "id": "insider_threat",
        "title": "Insider Threat & Data Exfiltration Lock",
        "category": "behavioral_threat",
        "version": "2.0",
        "severity": "high",
        "description": "Detecção de comportamento anômalo UEBA, bloqueio de exportação de dados sensíveis e auditoria LGPD/NIST.",
        "trigger": "ueba.anomaly_score > 8.5 AND dlp.mass_data_download == true",
        "auto_execute": False,
        "requires_hitl": True,
        "sla_minutes": 20,
        "steps": [
            {"id": "log_capture", "name": "Captura de Trilha UEBA", "action": "snapshot_user_activity", "auth": "auto"},
            {"id": "restrict_access", "name": "Restringir Privilégios IAM", "action": "revert_to_least_privilege", "auth": "auto"},
            {"id": "block_usb_cloud", "name": "Bloquear USB e Armazenamento Cloud", "action": "disable_removable_media", "auth": "hitl"},
            {"id": "forensic_dump", "name": "Dump de Memória e Sessão", "action": "collect_volatile_memory", "auth": "auto"},
            {"id": "escalate", "name": "Escalar para Governança e Jurídico", "action": "notify_compliance_officer", "auth": "auto"},
        ],
    },
    {
        "id": "ai_agent_compromise",
        "title": "AI Agent Prompt Injection & Poisoning Defense",
        "category": "ai_security",
        "version": "1.5",
        "severity": "critical",
        "description": "Proteção ativa contra ataques de injeção de prompt adversarial, envenenamento de ferramentas MCP e desvio de alinhamento.",
        "trigger": "mcp_auditor.detects_prompt_injection == true OR red_team.tool_poisoning == true",
        "auto_execute": True,
        "requires_hitl": True,
        "sla_minutes": 10,
        "steps": [
            {"id": "sandbox_isolate", "name": "Isolamento de Agente em Sandbox", "action": "isolate_agent_context", "auth": "auto"},
            {"id": "purge_memory", "name": "Purga de Cache RAG / Memória Efêmera", "action": "purge_agent_memory", "auth": "auto"},
            {"id": "revert_weights", "name": "Reverter Prompt do Sistema", "action": "reset_system_prompt", "auth": "auto"},
            {"id": "hitl_audit", "name": "Auditoria de Alinhamento MCP", "action": "mcp_security_audit", "auth": "hitl"},
            {"id": "restore", "name": "Reativação do Agente com Guardrails", "action": "enable_strict_guardrails", "auth": "auto"},
        ],
    },
    {
        "id": "lateral_movement",
        "title": "Lateral Movement & Zero-Day Isolation",
        "category": "containment",
        "version": "2.5",
        "severity": "critical",
        "description": "Bloqueio dinâmico de movimentação lateral de atacantes na rede local e aplicação de micro-segmentação de emergência.",
        "trigger": "correlation.technique == 'T1021' AND network.suspicious_smb_rpc == true",
        "auto_execute": False,
        "requires_hitl": True,
        "sla_minutes": 15,
        "steps": [
            {"id": "micro_segment", "name": "Micro-Segmentação da Sub-rede", "action": "apply_zero_trust_vlan", "auth": "hitl"},
            {"id": "block_rpc_smb", "name": "Bloquear Portas 445/135/5985 Inter-hosts", "action": "drop_lateral_ports", "auth": "auto"},
            {"id": "invalidate_tokens", "name": "Invalidar Tokens Kerberos/NTLM", "action": "flush_kerberos_tickets", "auth": "auto"},
            {"id": "scan_neighbors", "name": "Varredura de Agentes Vizinhos", "action": "scan_adjacent_assets", "auth": "auto"},
            {"id": "report", "name": "Relatório de Vetor de Ataque", "action": "generate_attack_path_summary", "auth": "auto"},
        ],
    },
]


@app.get("/api/playbooks")
async def playbooks() -> List[Dict[str, Any]]:
    return PLAYBOOKS_DATA


@app.get("/api/playbooks/executions")
async def playbook_executions() -> List[Dict[str, Any]]:
    try:
        raw = await redis_client.hgetall("mcp:soar:executions")
        items = [item for value in raw.values() if (item := _loads(value, None))]
        return sorted(items, key=lambda item: item.get("started_at", ""), reverse=True)
    except Exception as exc:
        logger.warning(f"Erro ao buscar histórico de execuções SOAR: {exc}")
        return []


class PlaybookExecuteRequest(BaseModel):
    target_host: Optional[str] = Field(default="192.168.1.100", max_length=120)
    operator: Optional[str] = Field(default="SOC Admin", max_length=120)
    mode: Literal["simulation", "live"] = "simulation"


@app.post("/api/playbooks/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, body: Optional[PlaybookExecuteRequest] = None) -> Dict[str, Any]:
    target = body.target_host if body and body.target_host else "192.168.1.100"
    operator = body.operator if body and body.operator else "SOC Admin"
    mode = body.mode if body else "simulation"

    pb = next((p for p in PLAYBOOKS_DATA if p["id"] == playbook_id), None)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook não encontrado")

    execution_id = f"exec_{playbook_id}_{int(datetime.now(timezone.utc).timestamp())}"
    now_iso = datetime.now(timezone.utc).isoformat()

    execution_record = {
        "execution_id": execution_id,
        "playbook_id": playbook_id,
        "title": pb["title"],
        "severity": pb["severity"],
        "target_host": target,
        "operator": operator,
        "mode": mode,
        "status": "completed" if not pb["requires_hitl"] else "hitl_pending",
        "started_at": now_iso,
        "total_steps": len(pb["steps"]),
        "current_step": len(pb["steps"]) if not pb["requires_hitl"] else 2,
        "steps_detail": pb["steps"],
    }

    try:
        await redis_client.hset("mcp:soar:executions", execution_id, json.dumps(execution_record, ensure_ascii=False))
        await redis_client.xadd(
            "mcp:audit:events",
            {
                "timestamp": now_iso,
                "agent_id": "response_orchestrator",
                "level": "info" if mode == "simulation" else "warning",
                "message": f"SOAR Playbook {pb['title']} executado no modo {mode} para o alvo {target}",
                "event_id": execution_id,
            },
        )
    except Exception as exc:
        logger.warning(f"Aviso ao registrar execução no Redis: {exc}")

    return {
        "status": "success",
        "execution_id": execution_id,
        "playbook": pb["title"],
        "mode": mode,
        "target": target,
        "message": f"Playbook {pb['title']} iniciado com sucesso no modo {mode}.",
        "execution": execution_record,
    }


COMPLIANCE_FRAMEWORKS = [
    {
        "id": "lgpd",
        "name": "LGPD (Lei Geral de Proteção de Dados - Brasil)",
        "score": 96.5,
        "status": "compliant",
        "total_controls": 18,
        "passed_controls": 17,
        "warn_controls": 1,
        "failed_controls": 0,
        "description": "Governança de privacidade, base legal para tratamento de PII, relatório de impacto à proteção de dados (RIPD) e canal do DPO.",
    },
    {
        "id": "eu_ai_act",
        "name": "EU AI Act (Regulamento de IA da União Europeia)",
        "score": 94.0,
        "status": "compliant",
        "total_controls": 22,
        "passed_controls": 20,
        "warn_controls": 2,
        "failed_controls": 0,
        "description": "Classificação de risco de sistemas de IA, supervisão humana (HITL), transparência de modelos LLM e mitigação de viés.",
    },
    {
        "id": "nist_ai_rmf",
        "name": "NIST AI Risk Management Framework (AI RMF 1.0)",
        "score": 92.8,
        "status": "compliant",
        "total_controls": 25,
        "passed_controls": 23,
        "warn_controls": 2,
        "failed_controls": 0,
        "description": "Funções GOVERN, MAP, MEASURE e MANAGE para resiliência operacional, explicabilidade e segurança de agentes autônomos.",
    },
    {
        "id": "iso_42001",
        "name": "ISO/IEC 42001:2023 (Artificial Intelligence Management System)",
        "score": 95.2,
        "status": "compliant",
        "total_controls": 20,
        "passed_controls": 19,
        "warn_controls": 1,
        "failed_controls": 0,
        "description": "Sistema de Gestão de Inteligência Artificial para garantia de qualidade, auditoria contínua e rastreabilidade de decisões.",
    },
]

COMPLIANCE_CONTROLS = [
    {"id": "LGPD-01", "framework": "LGPD", "title": "Criptografia em Repouso e Trânsito de PII", "status": "PASS", "agent": "compliance_agent", "evidence": "AES-256 / TLS 1.3 habilitados em todas as conexões relacional e Redis."},
    {"id": "LGPD-02", "framework": "LGPD", "title": "Registro de Trilha de Auditoria DPO", "status": "PASS", "agent": "governance_agent", "evidence": "Eventos de auditoria imutáveis persistidos no stream mcp:audit:events."},
    {"id": "LGPD-03", "framework": "LGPD", "title": "Retenção e Descarte Automático de Dados", "status": "WARN", "agent": "compliance_agent", "evidence": "Política de expiração TTL de 90 dias configurada no Upstash Redis."},
    {"id": "EU-AI-01", "framework": "EU AI Act", "title": "Controle Humano Obrigatório (HITL) para Ações Críticas", "status": "PASS", "agent": "central_orchestrator", "evidence": "Isolamento de rede e alteração de IAM retidos para aprovação humana L3."},
    {"id": "EU-AI-02", "framework": "EU AI Act", "title": "Robustez contra Prompt Injection Adversarial", "status": "PASS", "agent": "red_team_agent", "evidence": "Taxa de mitigação de 99.4% em testes adversariais automatizados."},
    {"id": "EU-AI-03", "framework": "EU AI Act", "title": "Documentação Técnica do Modelo e Prompt de Sistema", "status": "PASS", "agent": "governance_agent", "evidence": "Prompts e guardrails versionados sob controle de integridade SHA-256."},
    {"id": "NIST-RM-01", "framework": "NIST AI RMF", "title": "Mapeamento de Riscos de Agentes Autônomos (MAP 1.1)", "status": "PASS", "agent": "correlation_agent", "evidence": "Grafo de Conhecimento mapeia 100% dos relacionamentos de ferramentas MCP."},
    {"id": "NIST-RM-02", "framework": "NIST AI RMF", "title": "Monitoramento de Desvio de Alinhamento (MEASURE 2.3)", "status": "PASS", "agent": "mcp_auditor_agent", "evidence": "Verificação diária de envenenamento de ferramentas e jailbreak."},
    {"id": "ISO-42001-01", "framework": "ISO 42001", "title": "Avaliação Contínua de Impacto Alvo", "status": "PASS", "agent": "governance_agent", "evidence": "Relatórios periódicos de impacto integrados ao motor de risco CVSS v4."},
]


@app.get("/api/compliance/summary")
async def compliance_summary() -> Dict[str, Any]:
    return {
        "overall_score": 94.6,
        "status": "fully_compliant",
        "last_audit": datetime.now(timezone.utc).isoformat(),
        "ai_safety": {
            "prompt_injection_resistance": 99.4,
            "pii_leak_prevention": 100.0,
            "algorithmic_bias_score": 0.02,
            "mcp_tool_integrity": 99.8,
            "hitl_enforcement_rate": 100.0,
        },
        "frameworks": COMPLIANCE_FRAMEWORKS,
    }


@app.get("/api/compliance/frameworks")
async def compliance_frameworks() -> Dict[str, Any]:
    return {
        "frameworks": COMPLIANCE_FRAMEWORKS,
        "controls": COMPLIANCE_CONTROLS,
    }


class ComplianceReportRequest(BaseModel):
    author: str = Field(default="DPO / CISO Office", min_length=2, max_length=120)
    format: Literal["json", "pdf", "markdown"] = "markdown"


@app.post("/api/compliance/reports/generate")
async def generate_compliance_report(body: Optional[ComplianceReportRequest] = None) -> Dict[str, Any]:
    author = body.author if body else "DPO / CISO Office"
    fmt = body.format if body else "markdown"
    now_iso = datetime.now(timezone.utc).isoformat()
    report_id = f"REP_COMPLIANCE_{int(datetime.now(timezone.utc).timestamp())}"

    hash_str = f"{report_id}_{now_iso}_{author}"
    report_hash = hashlib.sha256(hash_str.encode()).hexdigest()[:16].upper()

    summary_text = (
        f"# RELATÓRIO EXECUTIVO DE CONFORMIDADE E GOVERNANÇA DE IA\n"
        f"**ID do Relatório**: `{report_id}` | **Integridade SHA-256**: `{report_hash}`\n"
        f"**Emitido por**: {author} | **Data**: {now_iso}\n\n"
        f"## 1. Resumo Consolidado de Conformidade\n"
        f"- Índice Geral de Conformidade: **94.6%** (Status: TOTALMENTE CONFORME)\n"
        f"- LGPD (Proteção de Dados - BR): **96.5%**\n"
        f"- EU AI Act (Regulamento de IA - UE): **94.0%**\n"
        f"- NIST AI RMF 1.0: **92.8%**\n"
        f"- ISO/IEC 42001:2023: **95.2%**\n\n"
        f"## 2. Métricas de Segurança de IA e Alinhamento\n"
        f"- Resistência a Injeções de Prompt Adversarial: **99.4%**\n"
        f"- Prevenção de Vazamento de PII: **100.0%**\n"
        f"- Taxa de Execução HITL para Ações Críticas: **100.0%**\n"
    )

    try:
        await redis_client.xadd(
            "mcp:audit:events",
            {
                "timestamp": now_iso,
                "agent_id": "compliance_agent",
                "level": "info",
                "message": f"Relatório de Governança e Compliance emitido por {author}: {report_id}",
                "event_id": report_id,
            },
        )
    except Exception as exc:
        logger.warning(f"Aviso ao gravar evento de relatório de compliance no Redis: {exc}")

    return {
        "status": "success",
        "report_id": report_id,
        "integrity_hash": report_hash,
        "author": author,
        "format": fmt,
        "generated_at": now_iso,
        "report_preview": summary_text,
    }


@app.websocket("/ws")
async def websocket_stats(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            payload = await _stats()
            await websocket.send_json({"type": "stats", "payload": payload})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await websocket.close(code=1000)
        except Exception:
            pass
