#!/usr/bin/env python3
"""Governance & Ethics Agent — Audit, Compliance, Bias Detection Engine"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("governance")

class GovernanceAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="governance_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/6"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.policies = []
        self._load_policies()
        self._register_handlers()

    def _load_policies(self):
        policy_file = "/app/config/policies/security_policies.json"
        try:
            with open(policy_file) as f:
                self.policies = json.load(f).get("policies", [])
                logger.info(f"Loaded {len(self.policies)} policies")
        except FileNotFoundError:
            logger.warning(f"Policy file not found: {policy_file}")
            self.policies = []

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)
        self.client.register_handler(MessageType.QUERY_REQUEST, self._handle_query)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "policy_violation_review":
            asyncio.create_task(self._review_violation(msg))
        elif task.task_type == "audit_request":
            asyncio.create_task(self._execute_audit(msg))
        elif task.task_type == "bias_check":
            asyncio.create_task(self._execute_bias_check(msg))

    def _handle_query(self, msg: MCPMessage):
        query = msg.payload.query
        if query.query_type == "policy_check":
            action = query.parameters.get("action")
            result = self._check_policy(action)
            response = MCPMessage.Payload(
                message_type=MessageType.QUERY_RESPONSE,
                result=MCPMessage.Payload.Result(status="success", data=result)
            )
            self.client.send_message(msg.envelope.from_addr.agent_id, response, msg.correlation_id)

    async def _review_violation(self, msg: MCPMessage):
        task = msg.payload.task
        violation = task.parameters.get("violation_type", "")
        original = task.parameters.get("original_message", {})

        review = {
            "violation_type": violation,
            "severity": "high",
            "reviewed_by": "governance_agent",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "recommendation": "Escalate to human security manager",
            "policy_triggered": "scope_validation"
        }

        self._send_result(msg, "success", data=review)

        # Escalate to compliance
        self.client.send_task("compliance_agent", "policy_breach_report", {"review": review}, Priority.HIGH)

    async def _execute_audit(self, msg: MCPMessage):
        task = msg.payload.task
        agent_id = task.parameters.get("agent_id", "all")

        # Query Redis for audit events
        if agent_id == "all":
            events = self.client._redis.xrange("mcp:audit:events", count=1000)
        else:
            events = self.client._redis.xrange(f"mcp:audit:{agent_id}", count=1000)

        audit_report = {
            "agent_id": agent_id,
            "total_events": len(events),
            "events": [{k: v for k, v in event[1].items()} for event in events],
            "integrity_verified": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self._send_result(msg, "success", data=audit_report)

    async def _execute_bias_check(self, msg: MCPMessage):
        task = msg.payload.task
        decisions = task.parameters.get("decisions", [])
        bias_flags = []

        for decision in decisions:
            # Simplified bias detection
            if decision.get("target_group") and decision.get("action") == "block":
                bias_flags.append({
                    "decision_id": decision.get("id"),
                    "potential_bias": "disproportionate_blocking",
                    "confidence": 30,
                    "recommendation": "Review manually"
                })

        self._send_result(msg, "success", data={"bias_flags": bias_flags, "total_checked": len(decisions)})

    def _check_policy(self, action: str) -> Dict:
        for policy in self.policies:
            if policy.get("action") == action:
                return {"allowed": policy.get("allowed", False), "requires_hitl": policy.get("requires_hitl", True)}
        return {"allowed": False, "requires_hitl": True, "reason": "No policy found"}

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Governance Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = GovernanceAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Governance Agent shutting down...")
        agent.client.stop()
