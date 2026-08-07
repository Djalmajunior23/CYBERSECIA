#!/usr/bin/env python3
"""
Central Orchestrator — Brain of the CyberSec AI Ecosystem
Coordinates specialized cybersecurity agents via MCP protocol.
"""
import os
import sys
import json
import asyncio
import logging
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("orchestrator")

@dataclass
class AgentRegistry:
    agent_id: str
    agent_type: str
    status: str = "unknown"
    last_heartbeat: Optional[datetime] = None
    capabilities: List[str] = None
    load_score: float = 0.0

class CentralOrchestrator:
    AGENT_CAPABILITIES = {
        "discovery_agent": ["network_scan", "host_discovery", "port_enumeration", "os_fingerprinting"],
        "vulnerability_agent": ["cve_correlation", "cvss_scoring", "exploitability_analysis"],
        "threat_intel_agent": ["ioc_lookup", "ttp_mapping", "actor_attribution", "campaign_tracking"],
        "behavioral_agent": ["ueba", "anomaly_detection", "insider_threat", "lateral_movement_detect"],
        "response_orchestrator": ["host_isolation", "account_disable", "ioc_block", "playbook_execute"],
        "governance_agent": ["audit", "policy_enforce", "bias_detect", "privacy_check"],
        "red_team_agent": ["adversarial_test", "prompt_injection", "tool_poisoning", "jailbreak"],
        "soar_agent": ["alert_triage", "incident_response", "playbook_automation", "escalation"],
        "purple_team_agent": ["attack_simulation", "defense_validation", "coverage_gap_analysis"],
        "mcp_auditor_agent": ["mcp_server_inventory", "static_audit", "dynamic_test", "shadow_detect"],
        "digital_twin_agent": ["environment_replication", "safe_simulation", "what_if_analysis"],
        "threat_hunt_agent": ["hypothesis_generation", "proactive_hunt", "drl_analysis", "campaign_recon"],
        "compliance_agent": ["lgpd_audit", "eu_ai_act_check", "nist_ai_rmf_validate", "report_generate"],
        "forensic_agent": ["evidence_preservation", "timeline_reconstruction", "artifact_analysis", "chain_of_custody"],
        "correlation_agent": ["knowledge_graph", "asset_intelligence", "risk_correlation", "attack_path_analysis"]
    }

    HITL_REQUIRED_TASKS = [
        "contain_critical_infrastructure",
        "exploit_verification",
        "redteam_production",
        "forensic_evidence_acquisition",
        "mcp_server_quarantine"
    ]

    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="central_orchestrator",
            agent_type=AgentType.ORCHESTRATOR,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/0"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.registry: Dict[str, AgentRegistry] = {}
        self.active_incidents: Dict[str, Dict] = {}
        self.hitl_queue: List[Dict] = []
        self._init_registry()
        self._register_handlers()

    def _init_registry(self):
        for agent_id, capabilities in self.AGENT_CAPABILITIES.items():
            self.registry[agent_id] = AgentRegistry(
                agent_id=agent_id,
                agent_type="worker",
                capabilities=capabilities
            )
        logger.info(f"Agent registry initialized with {len(self.registry)} agents")

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_RESULT, self._handle_task_result)
        self.client.register_handler(MessageType.HEARTBEAT, self._handle_heartbeat)
        self.client.register_handler(MessageType.ALERT, self._handle_alert)
        self.client.register_handler(MessageType.QUERY_REQUEST, self._handle_query)
        self.client.register_handler(MessageType.AUTHORIZATION_REQUEST, self._handle_auth_request)

    def _handle_task_result(self, msg: MCPMessage):
        agent_id = msg.envelope.from_addr.agent_id
        result = msg.payload.result
        if result is None:
            logger.warning("TASK_RESULT without result payload from %s", agent_id)
            return

        task_ref = msg.correlation_id
        if result.status in {"success", "partial"}:
            logger.info("Task result %s completed by %s with status=%s", task_ref, agent_id, result.status)
            self._correlate_findings(msg)
        elif result.status == "failure":
            logger.error("Task result %s failed by %s: %s", task_ref, agent_id, result.errors)
            self._handle_task_failure(msg)
        elif result.status == "blocked":
            logger.warning("Task result %s blocked by %s", task_ref, agent_id)
            self._escalate_to_governance(msg)

    def _handle_heartbeat(self, msg: MCPMessage):
        agent_id = msg.envelope.from_addr.agent_id
        heartbeat = msg.payload.heartbeat
        if heartbeat is None:
            return

        reg = self.registry.get(agent_id)
        if reg:
            reg.status = heartbeat.status
            reg.last_heartbeat = msg.timestamp
            if heartbeat.metrics:
                reg.load_score = heartbeat.metrics.get("queue_depth", 0)

        status_record = {
            "status": heartbeat.status,
            "last_heartbeat": msg.timestamp.isoformat(),
            "load_score": reg.load_score if reg else (heartbeat.metrics or {}).get("queue_depth", 0),
            "capabilities": reg.capabilities if reg else (heartbeat.capabilities or ["orchestration"]),
        }
        self.client._redis.hset("mcp:agent-status", agent_id, json.dumps(status_record))

    def _handle_alert(self, msg: MCPMessage):
        alert = msg.payload.alert
        if alert is None:
            logger.warning("ALERT message without alert payload from %s", msg.envelope.from_addr.agent_id)
            return

        severity = alert.severity
        logger.critical(f"ALERT [{severity.upper()}] from {msg.envelope.from_addr.agent_id}: {alert.title}")
        self.client._redis.xadd(
            "mcp:alerts",
            {
                "message_id": msg.message_id,
                "correlation_id": msg.correlation_id,
                "source_agent": msg.envelope.from_addr.agent_id,
                "severity": severity,
                "title": alert.title,
                "timestamp": msg.timestamp.isoformat(),
                "payload": json.dumps(alert.model_dump()),
            },
        )
        if severity == "critical":
            self._trigger_critical_response(msg)
        elif severity == "high":
            self._trigger_high_response(msg)
        else:
            self._route_to_soar(msg)

    def _handle_query(self, msg: MCPMessage):
        query = msg.payload.query
        response_data = {}
        if query.query_type == "agent_status":
            target = query.parameters.get("agent_id")
            if target in self.registry:
                reg = self.registry[target]
                response_data = {
                    "agent_id": reg.agent_id,
                    "status": reg.status,
                    "last_heartbeat": reg.last_heartbeat.isoformat() if reg.last_heartbeat else None,
                    "capabilities": reg.capabilities,
                    "load_score": reg.load_score
                }
        elif query.query_type == "capability_match":
            required = query.parameters.get("capabilities", [])
            matches = []
            for agent_id, reg in self.registry.items():
                if any(cap in reg.capabilities for cap in required):
                    matches.append({
                        "agent_id": agent_id,
                        "capabilities": [c for c in required if c in reg.capabilities],
                        "load_score": reg.load_score,
                        "status": reg.status
                    })
            matches.sort(key=lambda x: (x["load_score"], x["status"] != "healthy"))
            response_data = {"matches": matches}

        response = MCPMessage.Payload(
            message_type=MessageType.QUERY_RESPONSE,
            result=MCPMessage.Payload.Result(status="success", data=response_data)
        )
        self.client.send_message(msg.envelope.from_addr.agent_id, response, correlation_id=msg.correlation_id)

    def _handle_auth_request(self, msg: MCPMessage):
        auth = msg.payload.authorization
        task = msg.payload.task
        if task.task_type in self.HITL_REQUIRED_TASKS:
            hitl_item = {
                "request_id": str(msg.message_id),
                "correlation_id": msg.correlation_id,
                "agent_id": msg.envelope.from_addr.agent_id,
                "task_type": task.task_type,
                "scope": task.scope,
                "parameters": task.parameters,
                "timestamp": msg.timestamp.isoformat(),
                "status": "pending"
            }
            self.hitl_queue.append(hitl_item)
            self.client._redis.lpush("mcp:human:hitl", json.dumps(hitl_item))
            logger.info(f"HITL request queued: {msg.message_id} for {task.task_type}")
        else:
            auth_response = MCPMessage.Payload(
                message_type=MessageType.AUTHORIZATION_RESPONSE,
                authorization=MCPMessage.Payload.Authorization(
                    required=True,
                    auth_type="auto",
                    status="granted",
                    approver="central_orchestrator",
                    approval_time=datetime.now(timezone.utc)
                )
            )
            self.client.send_message(msg.envelope.from_addr.agent_id, auth_response, correlation_id=msg.correlation_id)

    def dispatch_task(self, target_agent: str, task_type: str, parameters: Dict[str, Any],
                      priority: Priority = Priority.MEDIUM, scope: Optional[Dict[str, Any]] = None,
                      correlation_id: Optional[str] = None, hitl_approved: bool = False) -> Optional[str]:
        if target_agent not in self.registry:
            logger.error(f"Unknown agent: {target_agent}")
            return None

        correlation_id = correlation_id or str(uuid.uuid4())
        if task_type in self.HITL_REQUIRED_TASKS and not hitl_approved:
            request_id = f"HITL-{uuid.uuid4()}"
            hitl_item = {
                "request_id": request_id,
                "correlation_id": correlation_id,
                "agent_id": "central_orchestrator",
                "target_agent": target_agent,
                "task_type": task_type,
                "parameters": parameters,
                "scope": scope,
                "priority": priority.name.lower(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "pending",
            }
            self.hitl_queue.append(hitl_item)
            self.client._redis.lpush("mcp:human:hitl", json.dumps(hitl_item))
            logger.warning("Task %s held for HITL approval: %s", task_type, request_id)
            return request_id

        return self.client.send_task(target_agent, task_type, parameters, priority, scope, correlation_id)

    def dispatch_intelligent(self, required_capabilities: List[str], task_type: str, parameters: Dict[str, Any],
                             priority: Priority = Priority.MEDIUM, scope: Optional[Dict[str, Any]] = None) -> Optional[str]:
        matches = []
        for agent_id, reg in self.registry.items():
            if any(cap in reg.capabilities for cap in required_capabilities):
                if reg.status == "healthy":
                    matches.append((agent_id, reg.load_score))
        if not matches:
            logger.error(f"No healthy agent found for capabilities: {required_capabilities}")
            return None
        matches.sort(key=lambda x: x[1])
        selected = matches[0][0]
        logger.info(f"Intelligent dispatch: {task_type} -> {selected} (load: {matches[0][1]})")
        return self.dispatch_task(selected, task_type, parameters, priority, scope)

    def _correlate_findings(self, msg: MCPMessage):
        result = msg.payload.result
        if result is None:
            return
        record = {
            "message_id": msg.message_id,
            "correlation_id": msg.correlation_id,
            "agent_id": msg.envelope.from_addr.agent_id,
            "status": result.status,
            "timestamp": (result.completion_time or datetime.now(timezone.utc)).isoformat(),
            "data": json.dumps(result.data or {}),
            "findings": json.dumps(result.findings or []),
            "errors": json.dumps(result.errors or []),
        }
        self.client._redis.xadd("mcp:task-results", record)
        self._project_operational_state(msg.envelope.from_addr.agent_id, result.data or {}, record["timestamp"])

        # Attach correlated results to any active incident timeline.
        for incident_id, incident in self.active_incidents.items():
            if incident.get("correlation_id") == msg.correlation_id:
                incident.setdefault("timeline", []).append({
                    "timestamp": record["timestamp"],
                    "agent_id": record["agent_id"],
                    "status": result.status,
                    "message_id": msg.message_id,
                })
                self.client._redis.hset("mcp:incidents", incident_id, json.dumps(incident))

    def _project_operational_state(self, agent_id: str, data: Dict[str, Any], timestamp: str) -> None:
        """Project agent-local results into the orchestrator Redis DB for API/BI use."""
        if agent_id == "discovery_agent":
            for host in data.get("hosts", []):
                asset_id = host.get("ip")
                if not asset_id:
                    continue
                asset = dict(host)
                asset["last_observed_at"] = timestamp
                self.client._redis.hset("mcp:assets", asset_id, json.dumps(asset, ensure_ascii=False))

        elif agent_id == "vulnerability_agent":
            for finding in data.get("findings", []):
                finding_id = finding.get("finding_id")
                if not finding_id:
                    identity = f"{finding.get('host')}:{finding.get('port')}:{finding.get('cve_id')}"
                    finding_id = hashlib.sha256(identity.encode()).hexdigest()[:24]
                    finding = {**finding, "finding_id": finding_id}
                projected = {**finding, "last_observed_at": timestamp}
                self.client._redis.hset("mcp:vulnerabilities", finding_id, json.dumps(projected, ensure_ascii=False))

            summary = data.get("summary")
            if summary:
                self.client._redis.set("mcp:risk:last-summary", json.dumps({**summary, "timestamp": timestamp}, ensure_ascii=False))

        elif agent_id == "soar_agent":
            for ticket in data.get("remediation_tickets", []):
                ticket_id = ticket.get("ticket_id")
                if ticket_id:
                    self.client._redis.hset("mcp:remediation", ticket_id, json.dumps(ticket, ensure_ascii=False))

        elif agent_id == "threat_intel_agent":
            for enriched in data.get("enriched_iocs", []):
                ioc = enriched.get("ioc") or {}
                value = ioc.get("value")
                if value:
                    ioc_type = ioc.get("type", "unknown")
                    key = hashlib.sha256(f"{ioc_type}:{value}".encode()).hexdigest()[:24]
                    self.client._redis.hset("mcp:intel:iocs", key, json.dumps(enriched, ensure_ascii=False))

            for mapping in data.get("ttp_mapping", []):
                technique_id = mapping.get("technique_id")
                if technique_id:
                    self.client._redis.hset("mcp:intel:techniques", technique_id, json.dumps(mapping, ensure_ascii=False))

            campaign_name = data.get("campaign")
            if campaign_name:
                self.client._redis.hset("mcp:intel:campaigns", campaign_name, json.dumps(data, ensure_ascii=False))

        elif agent_id == "correlation_agent":
            summary = data.get("knowledge_graph")
            if summary:
                self.client._redis.set("mcp:kg:last-agent-summary", json.dumps(summary, ensure_ascii=False))

    def _handle_task_failure(self, msg: MCPMessage):
        result = msg.payload.result
        if result is None:
            return
        self.client._redis.xadd(
            "mcp:task-failures",
            {
                "message_id": msg.message_id,
                "correlation_id": msg.correlation_id,
                "agent_id": msg.envelope.from_addr.agent_id,
                "errors": json.dumps(result.errors or []),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def _escalate_to_governance(self, msg: MCPMessage):
        self.dispatch_task("governance_agent", "policy_violation_review",
                           {"original_message": msg.model_dump_json(by_alias=True), "violation_type": "task_blocked"}, Priority.HIGH)

    def _trigger_critical_response(self, msg: MCPMessage):
        date_key = datetime.now(timezone.utc).strftime("%Y%m%d")
        try:
            seq_key = f"mcp:incident-seq:{date_key}"
            sequence = int(self.client._redis.incr(seq_key))
            self.client._redis.expire(seq_key, 172800)
        except Exception:
            sequence = len(self.active_incidents) + 1

        incident_id = f"INC-{date_key}-{sequence:04d}"
        incident = {
            "incident_id": incident_id,
            "alert": msg.payload.alert.model_dump(),
            "severity": msg.payload.alert.severity,
            "title": msg.payload.alert.title,
            "source": msg.payload.alert.source,
            "status": "active",
            "start_time": datetime.now(timezone.utc).isoformat(),
            "correlation_id": msg.correlation_id,
            "timeline": [],
        }
        self.active_incidents[incident_id] = incident
        self.client._redis.hset("mcp:incidents", incident_id, json.dumps(incident))

        self.dispatch_task("soar_agent", "incident_triage",
                           {"incident_id": incident_id, "alert": msg.payload.alert.model_dump()}, Priority.CRITICAL)
        self.dispatch_task("threat_intel_agent", "ioc_enrichment",
                           {"incident_id": incident_id, "iocs": msg.payload.alert.iocs}, Priority.CRITICAL)
        self.dispatch_task("threat_hunt_agent", "proactive_hunt",
                           {"incident_id": incident_id, "hypothesis": f"lateral_movement_from_{msg.payload.alert.source}"}, Priority.HIGH)

    def _trigger_high_response(self, msg: MCPMessage):
        self.dispatch_task("soar_agent", "alert_triage", {"alert": msg.payload.alert.model_dump()}, Priority.HIGH)

    def _route_to_soar(self, msg: MCPMessage):
        self.dispatch_task("soar_agent", "alert_ingest", {"alert": msg.payload.alert.model_dump()}, Priority.MEDIUM)

    async def _process_hitl_decisions(self):
        """Apply dashboard HITL decisions and release approved critical tasks."""
        priority_map = {
            "critical": Priority.CRITICAL,
            "high": Priority.HIGH,
            "medium": Priority.MEDIUM,
            "low": Priority.LOW,
            "info": Priority.INFO,
        }
        while True:
            try:
                raw = self.client._redis.rpop("mcp:human:decisions")
                if not raw:
                    await asyncio.sleep(0.5)
                    continue

                decision = json.loads(raw)
                approved = decision.get("decision") == "approve"
                target_agent = decision.get("target_agent")
                correlation_id = decision.get("correlation_id")

                if target_agent:
                    if approved:
                        priority = priority_map.get(decision.get("priority", "medium"), Priority.MEDIUM)
                        message_id = self.dispatch_task(
                            target_agent=target_agent,
                            task_type=decision.get("task_type", ""),
                            parameters=decision.get("parameters") or {},
                            priority=priority,
                            scope=decision.get("scope"),
                            correlation_id=correlation_id,
                            hitl_approved=True,
                        )
                        logger.info("HITL-approved task %s released as %s", decision.get("request_id"), message_id)
                    else:
                        logger.warning("HITL-denied task %s will not be dispatched", decision.get("request_id"))
                    continue

                # Backward-compatible flow for an agent-originated authorization request.
                status = "granted" if approved else "denied"
                target_agent = decision.get("agent_id")
                auth_response = MCPMessage.Payload(
                    message_type=MessageType.AUTHORIZATION_RESPONSE,
                    authorization=MCPMessage.Payload.Authorization(
                        required=True,
                        auth_type="hitl",
                        status=status,
                        approver=decision.get("approver") or "human_analyst",
                        approval_time=datetime.now(timezone.utc),
                    ),
                )
                if target_agent and correlation_id:
                    self.client.send_message(target_agent, auth_response, correlation_id=correlation_id, priority=Priority.HIGH)
                    logger.info("HITL decision %s forwarded for %s", status, decision.get("request_id"))
                else:
                    logger.error("Invalid HITL decision payload: %s", decision)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception("HITL decision processing error: %s", exc)
                await asyncio.sleep(1)

    async def run(self):
        logger.info("=" * 60)
        logger.info("CyberSec AI Ecosystem — Central Orchestrator")
        logger.info("=" * 60)
        logger.info(f"Registered agents: {list(self.registry.keys())}")
        logger.info(f"HITL enabled: {os.getenv('HITL_ENABLED', 'true')}")
        logger.info("Starting message consumption...")
        hitl_task = asyncio.create_task(self._process_hitl_decisions())
        try:
            await self.client.run()
        finally:
            hitl_task.cancel()

if __name__ == "__main__":
    orchestrator = CentralOrchestrator()
    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        logger.info("Shutting down orchestrator...")
        orchestrator.client.stop()
