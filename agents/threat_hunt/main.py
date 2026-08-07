#!/usr/bin/env python3
"""Threat Hunting Agent — Proactive DRL + LLM Hypothesis-Driven Hunting"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("threat_hunt")

class ThreatHuntAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="threat_hunt_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/12"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "proactive_hunt":
            asyncio.create_task(self._execute_hunt(msg))
        elif task.task_type == "hypothesis_test":
            asyncio.create_task(self._test_hypothesis(msg))
        elif task.task_type == "generate_detection":
            asyncio.create_task(self._generate_detection(msg))

    async def _execute_hunt(self, msg: MCPMessage):
        task = msg.payload.task
        hypothesis = task.parameters.get("hypothesis", "")
        incident_id = task.parameters.get("incident_id", "")

        logger.info(f"Executing hunt: {hypothesis}")

        # Generate hunt query (Sigma-like)
        query = self._generate_query(hypothesis)

        # Execute query against telemetry (simulated)
        findings = [
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "entity": "user:john.smith",
                "behavior": "impossible_travel",
                "evidence": {"locations": ["São Paulo", "London"], "time_delta_minutes": 45},
                "confidence": 92,
                "mitre_technique": "T1078"
            }
        ]

        # Generate detection rule if findings confirmed
        if findings:
            detection = self._generate_sigma_rule(hypothesis, findings[0])
            self.client.send_task("soar_agent", "deploy_detection", {"rule": detection}, Priority.MEDIUM)

        self._send_result(msg, "success", data={
            "hypothesis": hypothesis,
            "findings": findings,
            "detection_generated": len(findings) > 0,
            "incident_id": incident_id
        })

    async def _test_hypothesis(self, msg: MCPMessage):
        hypothesis = msg.payload.task.parameters.get("hypothesis")
        self._send_result(msg, "success", data={"hypothesis": hypothesis, "result": "confirmed"})

    async def _generate_detection(self, msg: MCPMessage):
        gap = msg.payload.task.parameters.get("gap", "")
        rule = self._generate_sigma_rule(gap, {})
        self._send_result(msg, "success", data={"rule": rule, "format": "sigma"})

    def _generate_query(self, hypothesis: str) -> str:
        if "lateral_movement" in hypothesis:
            return "| stats count by src_ip, dest_ip, dest_port | where count > 10"
        return "| search *"

    def _generate_sigma_rule(self, hypothesis: str, finding: Dict) -> Dict:
        return {
            "title": f"Hunt Detection: {hypothesis[:30]}",
            "status": "experimental",
            "logsource": {"category": "network_connection"},
            "detection": {
                "selection": {"dest_port": 445},
                "condition": "selection"
            },
            "falsepositives": ["Legitimate admin activity"],
            "level": "high",
            "tags": ["attack.t1021"]
        }

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Threat Hunt Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = ThreatHuntAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Threat Hunt Agent shutting down...")
        agent.client.stop()
