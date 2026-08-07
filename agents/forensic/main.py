#!/usr/bin/env python3
"""Forensic Analysis Agent — Evidence Preservation & Timeline Reconstruction"""
import os
import sys
import json
import asyncio
import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("forensic")

class ForensicAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="forensic_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/14"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.evidence_dir = os.getenv("EVIDENCE_STORAGE", "/app/evidence")
        self.chain_of_custody = os.getenv("CHAIN_OF_CUSTODY", "true").lower() == "true"
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "preserve_evidence":
            asyncio.create_task(self._preserve_evidence(msg))
        elif task.task_type == "timeline_reconstruct":
            asyncio.create_task(self._reconstruct_timeline(msg))
        elif task.task_type == "artifact_analysis":
            asyncio.create_task(self._analyze_artifacts(msg))

    async def _preserve_evidence(self, msg: MCPMessage):
        task = msg.payload.task
        targets = task.parameters.get("targets", [])
        incident_id = task.parameters.get("incident_id", "")

        evidence_items = []

        for target in targets:
            evidence_id = f"EVID-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{hash(target) % 10000}"

            # Simulate acquisition
            acquisition = {
                "evidence_id": evidence_id,
                "source": target,
                "type": "disk_image",
                "acquisition_time": datetime.now(timezone.utc).isoformat(),
                "hash_sha256": hashlib.sha256(target.encode()).hexdigest(),
                "examiner": "forensic_agent",
                "method": "dd_imaging"
            }

            if self.chain_of_custody:
                acquisition["chain_of_custody"] = [
                    {"time": acquisition["acquisition_time"], "action": "acquired", "actor": "forensic_agent", "integrity": acquisition["hash_sha256"]}
                ]

            evidence_items.append(acquisition)
            self.client._redis.hset(f"evidence:{evidence_id}", mapping={k: json.dumps(v) if isinstance(v, (list, dict)) else v for k, v in acquisition.items()})

        self._send_result(msg, "success", data={
            "incident_id": incident_id,
            "evidence_items": evidence_items,
            "chain_of_custody_maintained": self.chain_of_custody
        })

    async def _reconstruct_timeline(self, msg: MCPMessage):
        task = msg.payload.task
        evidence_ids = task.parameters.get("evidence_ids", [])

        timeline = []
        for eid in evidence_ids:
            evidence = self.client._redis.hgetall(f"evidence:{eid}")
            if evidence:
                timeline.append({
                    "time": evidence.get("acquisition_time"),
                    "event": "evidence_acquired",
                    "source": evidence.get("source"),
                    "evidence_id": eid
                })

        timeline.sort(key=lambda x: x["time"])

        self._send_result(msg, "success", data={"timeline": timeline, "events": len(timeline)})

    async def _analyze_artifacts(self, msg: MCPMessage):
        evidence_id = msg.payload.task.parameters.get("evidence_id")
        artifacts = [
            {"type": "registry", "path": "HKCU\\Run", "finding": "suspicious_persistence"},
            {"type": "file", "path": "C:\\Temp\\update.exe", "finding": "malware_signature_match"}
        ]
        self._send_result(msg, "success", data={"evidence_id": evidence_id, "artifacts": artifacts})

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Forensic Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = ForensicAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Forensic Agent shutting down...")
        agent.client.stop()
