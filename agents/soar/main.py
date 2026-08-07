#!/usr/bin/env python3
"""Autonomous SOAR Agent — 24/7 Incident Response & Playbook Automation"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import yaml

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("soar")

class SOARAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="soar_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/8"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.playbooks_dir = os.getenv("PLAYBOOKS_DIR", "/app/playbooks")
        self.active_incidents: Dict[str, Dict] = {}
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)
        self.client.register_handler(MessageType.ALERT, self._handle_alert)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "incident_triage":
            asyncio.create_task(self._execute_incident_triage(msg))
        elif task.task_type == "alert_triage":
            asyncio.create_task(self._execute_alert_triage(msg))
        elif task.task_type == "alert_ingest":
            asyncio.create_task(self._execute_alert_ingest(msg))
        elif task.task_type == "playbook_run":
            asyncio.create_task(self._execute_playbook_run(msg))
        elif task.task_type == "vulnerability_triage":
            asyncio.create_task(self._execute_vulnerability_triage(msg))

    def _handle_alert(self, msg: MCPMessage):
        asyncio.create_task(self._process_alert(msg))

    async def _execute_incident_triage(self, msg: MCPMessage):
        task = msg.payload.task
        incident_id = task.parameters.get("incident_id", "")
        alert = task.parameters.get("alert", {})

        logger.info(f"Triaging incident {incident_id}")

        # Determine severity-based response
        severity = alert.get("severity", "medium")

        if severity == "critical":
            # Immediate containment preparation
            self.client.send_task("response_orchestrator", "playbook_execute", {
                "playbook_name": "ransomware_response",
                "variables": {"incident_id": incident_id, "affected_host": alert.get("source", "")}
            }, Priority.CRITICAL)

        incident_record = {
            "incident_id": incident_id,
            "status": "triaged",
            "severity": severity,
            "alert": alert,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "assigned_to": "soar_agent"
        }
        self.active_incidents[incident_id] = incident_record
        self.client._redis.hset(f"incident:{incident_id}", mapping={k: json.dumps(v) if isinstance(v, dict) else v for k, v in incident_record.items()})

        self._send_result(msg, "success", data={"incident_id": incident_id, "status": "triaged", "next_action": "containment_prepared"})

    async def _execute_alert_triage(self, msg: MCPMessage):
        alert = msg.payload.task.parameters.get("alert", {})
        severity = alert.get("severity", "medium")

        if severity in ["critical", "high"]:
            # Create incident
            incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            await self._execute_incident_triage(MCPMessage(
                correlation_id=msg.correlation_id,
                envelope=msg.envelope,
                payload=MCPMessage.Payload(
                    message_type=MessageType.TASK_ASSIGNMENT,
                    task=MCPMessage.Payload.Task(
                        task_type="incident_triage",
                        parameters={"incident_id": incident_id, "alert": alert}
                    )
                )
            ))

        self._send_result(msg, "success", data={"alert_severity": severity, "action": "triaged"})

    async def _execute_alert_ingest(self, msg: MCPMessage):
        alert = msg.payload.task.parameters.get("alert", {})
        logger.info(f"Ingested alert: {alert.get('title', 'Unknown')}")
        self._send_result(msg, "success", data={"status": "logged", "alert_id": alert.get("id", "")})

    async def _execute_vulnerability_triage(self, msg: MCPMessage):
        """Create remediation work items without performing intrusive actions."""
        findings = msg.payload.task.parameters.get("findings", [])
        tickets = []
        now = datetime.now(timezone.utc).isoformat()

        for finding in findings:
            finding_id = finding.get("finding_id") or f"{finding.get('host')}:{finding.get('cve_id')}"
            tier = finding.get("remediation_tier", "P3")
            risk = finding.get("risk") or {}
            action = finding.get("cisa_required_action")
            if not action:
                action = "Patch or mitigate the affected component after change-control validation."

            ticket = {
                "ticket_id": f"REM-{finding_id}",
                "finding_id": finding.get("finding_id"),
                "host": finding.get("host"),
                "cve_id": finding.get("cve_id"),
                "priority": tier,
                "risk_score": finding.get("priority_score", risk.get("score", 0.0)),
                "severity": finding.get("severity", risk.get("severity", "medium")),
                "recommended_sla_hours": risk.get("recommended_sla_hours", 168),
                "recommended_action": action,
                "status": "open",
                "created_at": now,
                "source": "vulnerability_agent",
                "automation": "recommendation_only",
            }
            tickets.append(ticket)
            self.client._redis.hset("soar:remediation", ticket["ticket_id"], json.dumps(ticket, ensure_ascii=False))

        self._send_result(
            msg,
            "success",
            data={
                "remediation_tickets": tickets,
                "total": len(tickets),
                "mode": "recommendation_only",
            },
        )

    async def _execute_playbook_run(self, msg: MCPMessage):
        playbook_name = msg.payload.task.parameters.get("playbook_name")
        variables = msg.payload.task.parameters.get("variables", {})

        # Delegate to Response Orchestrator
        self.client.send_task("response_orchestrator", "playbook_execute", {
            "playbook_name": playbook_name,
            "variables": variables
        }, Priority.HIGH, correlation_id=msg.correlation_id)

        self._send_result(msg, "success", data={"playbook": playbook_name, "delegated_to": "response_orchestrator"})

    async def _process_alert(self, msg: MCPMessage):
        alert = msg.payload.alert
        if alert.severity == "critical":
            self.client.send_task("central_orchestrator", "alert_critical", {
                "alert": alert.model_dump()
            }, Priority.CRITICAL)

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("SOAR Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = SOARAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("SOAR Agent shutting down...")
        agent.client.stop()
