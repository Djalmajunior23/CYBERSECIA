#!/usr/bin/env python3
"""Cyber Digital Twin Agent — Safe Attack Simulation Environment"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("digital_twin")

class DigitalTwinAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="digital_twin_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/11"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.isolated = os.getenv("ISOLATED", "true").lower() == "true"
        self.simulations: Dict[str, Dict] = {}
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "create_twin":
            asyncio.create_task(self._create_twin(msg))
        elif task.task_type == "run_simulation":
            asyncio.create_task(self._run_simulation(msg))
        elif task.task_type == "what_if_analysis":
            asyncio.create_task(self._what_if_analysis(msg))

    async def _create_twin(self, msg: MCPMessage):
        task = msg.payload.task
        topology = task.parameters.get("topology", {})
        twin_id = f"twin-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

        twin = {
            "twin_id": twin_id,
            "topology": topology,
            "status": "created",
            "isolated": self.isolated,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        self.simulations[twin_id] = twin
        self.client._redis.hset(f"twin:{twin_id}", mapping={k: json.dumps(v) if isinstance(v, dict) else v for k, v in twin.items()})

        self._send_result(msg, "success", data={"twin_id": twin_id, "status": "ready"})

    async def _run_simulation(self, msg: MCPMessage):
        task = msg.payload.task
        twin_id = task.parameters.get("twin_id")
        scenario = task.parameters.get("scenario", "ransomware_lateral")

        if twin_id not in self.simulations:
            self._send_result(msg, "failure", errors=[f"Twin {twin_id} not found"])
            return

        logger.info(f"Running simulation {scenario} on twin {twin_id}")

        # Simulated execution
        simulation_result = {
            "scenario": scenario,
            "twin_id": twin_id,
            "phases": [
                {"phase": "initial_compromise", "success": True, "detection_time_ms": 5000},
                {"phase": "lateral_movement", "success": True, "detection_time_ms": 15000},
                {"phase": "objective", "success": False, "detection_time_ms": 8000}
            ],
            "defense_performance": {
                "edr_prevention": "blocked",
                "siem_detection": "alerted",
                "network_segmentation": "contained"
            }
        }

        self._send_result(msg, "success", data=simulation_result)

    async def _what_if_analysis(self, msg: MCPMessage):
        task = msg.payload.task
        change = task.parameters.get("change", "")

        result = {
            "change": change,
            "predicted_mttd": 300,
            "predicted_affected_hosts": 5,
            "implementation_cost": "medium"
        }

        self._send_result(msg, "success", data=result)

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Digital Twin Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = DigitalTwinAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Digital Twin Agent shutting down...")
        agent.client.stop()
