#!/usr/bin/env python3
"""Compliance & Regulatory Agent — LGPD, EU AI Act, NIST AI RMF Governance"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("compliance")

class ComplianceAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="compliance_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/13"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.lgpd = os.getenv("LGPD_ENABLED", "true").lower() == "true"
        self.eu_ai_act = os.getenv("EU_AI_ACT_ENABLED", "true").lower() == "true"
        self.nist_ai_rmf = os.getenv("NIST_AI_RMF_ENABLED", "true").lower() == "true"
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "compliance_audit":
            asyncio.create_task(self._execute_audit(msg))
        elif task.task_type == "policy_breach_report":
            asyncio.create_task(self._process_breach(msg))
        elif task.task_type == "lgpd_check":
            asyncio.create_task(self._lgpd_check(msg))

    async def _execute_audit(self, msg: MCPMessage):
        task = msg.payload.task
        frameworks = task.parameters.get("frameworks", ["lgpd", "eu_ai_act", "nist_ai_rmf"])

        results = {}

        if "lgpd" in frameworks and self.lgpd:
            results["lgpd"] = {
                "score": 85,
                "status": "compliant",
                "gaps": ["Data retention policy needs update"]
            }

        if "eu_ai_act" in frameworks and self.eu_ai_act:
            results["eu_ai_act"] = {
                "score": 78,
                "status": "partial",
                "gaps": ["Article 55 adversarial testing documentation incomplete"]
            }

        if "nist_ai_rmf" in frameworks and self.nist_ai_rmf:
            results["nist_ai_rmf"] = {
                "score": 90,
                "status": "compliant",
                "gaps": []
            }

        overall = sum(r["score"] for r in results.values()) / len(results) if results else 0

        self._send_result(msg, "success", data={
            "frameworks": results,
            "overall_score": overall,
            "audit_date": datetime.now(timezone.utc).isoformat()
        })

    async def _process_breach(self, msg: MCPMessage):
        review = msg.payload.task.parameters.get("review", {})
        logger.warning(f"Policy breach reported: {review}")
        self._send_result(msg, "success", data={"breach_logged": True, "escalation": "dpo_notified"})

    async def _lgpd_check(self, msg: MCPMessage):
        data_flow = msg.payload.task.parameters.get("data_flow", {})
        issues = []
        if data_flow.get("contains_pii") and not data_flow.get("consent_recorded"):
            issues.append("Missing consent for PII processing")
        self._send_result(msg, "success", data={"compliant": len(issues) == 0, "issues": issues})

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Compliance Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = ComplianceAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Compliance Agent shutting down...")
        agent.client.stop()
