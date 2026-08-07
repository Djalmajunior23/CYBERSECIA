"""CyberSec AI API Gateway.

Read-only observability is available to the local dashboard. Mutating HITL
operations require an explicit API_ADMIN_TOKEN and are disabled when the token
is not configured.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

import redis.asyncio as redis
from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3001").split(",") if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
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
    raw = await redis_client.hgetall("mcp:agent-status")
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
    agents = await _agent_rows()
    healthy = sum(1 for agent in agents if agent["status"] == "healthy")
    vulnerabilities = await redis_client.hgetall("mcp:vulnerabilities")
    vuln_rows = [item for value in vulnerabilities.values() if (item := _loads(value, None))]
    return {
        "agents": len(agents),
        "healthy": healthy,
        "alerts": await redis_client.xlen("mcp:alerts"),
        "incidents": await redis_client.hlen("mcp:incidents"),
        "hitl": await redis_client.llen("mcp:human:hitl"),
        "assets": await redis_client.hlen("mcp:assets"),
        "vulnerabilities": len(vuln_rows),
        "critical_vulnerabilities": sum(1 for item in vuln_rows if item.get("severity") == "critical"),
        "remediation_open": await redis_client.hlen("mcp:remediation"),
        "graph_nodes": await redis_client.hlen("mcp:kg:nodes"),
        "graph_edges": await redis_client.hlen("mcp:kg:edges"),
        "correlations": await redis_client.hlen("mcp:correlations"),
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
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {type(exc).__name__}") from exc
    return {"status": "healthy" if pong else "degraded", "redis": bool(pong), "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/api/stats")
async def stats() -> Dict[str, int]:
    return await _stats()


@app.get("/api/agents")
async def agents() -> List[Dict[str, Any]]:
    return await _agent_rows()


@app.get("/api/hitl")
async def hitl_queue() -> List[Dict[str, Any]]:
    values = await redis_client.lrange("mcp:human:hitl", 0, 199)
    return [item for value in values if (item := _loads(value, None))]


@app.post("/api/hitl/{request_id}/decision")
async def decide_hitl(request_id: str, body: HITLDecision, x_api_key: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    _require_admin_token(x_api_key)

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


@app.get("/api/incidents")
async def incidents() -> List[Dict[str, Any]]:
    raw = await redis_client.hgetall("mcp:incidents")
    items = [item for value in raw.values() if (item := _loads(value, None))]
    return sorted(items, key=lambda item: item.get("start_time", ""), reverse=True)


@app.get("/api/assets")
async def assets() -> List[Dict[str, Any]]:
    raw = await redis_client.hgetall("mcp:assets")
    items = [item for value in raw.values() if (item := _loads(value, None))]
    return sorted(items, key=lambda item: item.get("ip", ""))


@app.get("/api/vulnerabilities")
async def vulnerabilities(
    severity: Optional[Literal["critical", "high", "medium", "low"]] = Query(default=None),
    min_score: float = Query(default=0.0, ge=0.0, le=10.0),
    kev_only: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
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


@app.get("/api/risk/summary")
async def risk_summary() -> Dict[str, Any]:
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

    return {
        "total": len(items),
        "severity": severity_counts,
        "cisa_kev": kev,
        "average_risk": round(sum(scores) / len(scores), 2) if scores else 0.0,
        "max_risk": round(max(scores), 2) if scores else 0.0,
        "assets": await redis_client.hlen("mcp:assets"),
        "remediation_open": await redis_client.hlen("mcp:remediation"),
        "graph_nodes": await redis_client.hlen("mcp:kg:nodes"),
        "graph_edges": await redis_client.hlen("mcp:kg:edges"),
        "correlations": await redis_client.hlen("mcp:correlations"),
    }


@app.get("/api/remediation")
async def remediation() -> List[Dict[str, Any]]:
    raw = await redis_client.hgetall("mcp:remediation")
    items = [item for value in raw.values() if (item := _loads(value, None))]
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    return sorted(items, key=lambda item: (priority_order.get(item.get("priority"), 9), item.get("created_at", "")))


@app.get("/api/knowledge-graph/summary")
async def knowledge_graph_summary() -> Dict[str, Any]:
    return _loads(await redis_client.get("mcp:kg:summary"), {})


@app.get("/api/knowledge-graph")
async def knowledge_graph(
    node_type: Optional[str] = Query(default=None, min_length=2, max_length=64),
    limit: int = Query(default=500, ge=1, le=3000),
) -> Dict[str, Any]:
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
    return {
        "summary": _loads(await redis_client.get("mcp:kg:summary"), {}),
        "nodes": nodes,
        "edges": edges,
    }


@app.get("/api/correlations")
async def correlations(
    severity: Optional[Literal["critical", "high", "medium", "low"]] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    raw = await redis_client.hgetall("mcp:correlations")
    items = [item for value in raw.values() if (item := _loads(value, None))]
    items = [item for item in items if (not severity or item.get("severity") == severity) and float(item.get("confidence", 0.0) or 0.0) >= min_confidence]
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    items.sort(key=lambda item: (severity_order.get(item.get("severity"), 9), -float(item.get("confidence", 0.0) or 0.0)))
    return items[:limit]


@app.get("/api/attack-paths")
async def attack_paths(
    min_score: float = Query(default=0.0, ge=0.0, le=10.0),
    limit: int = Query(default=200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    raw = await redis_client.hgetall("mcp:attack-paths")
    items = [item for value in raw.values() if (item := _loads(value, None))]
    items = [item for item in items if float(item.get("risk_score", 0.0) or 0.0) >= min_score]
    items.sort(key=lambda item: (-float(item.get("risk_score", 0.0) or 0.0), not bool(item.get("cisa_kev"))))
    return items[:limit]


@app.websocket("/ws")
async def websocket_stats(websocket: WebSocket) -> None:
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({"type": "stats", "payload": await _stats()})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return
    except Exception:
        await websocket.close(code=1011)
