#!/usr/bin/env python3
"""Threat Intel Agent — Intelligence Ingestion & TTP Mapping Engine"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import httpx

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("threat_intel")

class ThreatIntelAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="threat_intel_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/3"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.misp_url = os.getenv("MISP_URL", "")
        self.misp_key = os.getenv("MISP_API_KEY", "")
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._register_handlers()
        self._init_intel_cache()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)
        self.client.register_handler(MessageType.QUERY_REQUEST, self._handle_query)

    def _init_intel_cache(self):
        logger.info("Threat intel cache initialized")

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "ioc_enrichment":
            asyncio.create_task(self._execute_ioc_enrichment(msg))
        elif task.task_type == "ttp_mapping":
            asyncio.create_task(self._execute_ttp_mapping(msg))
        elif task.task_type == "campaign_tracking":
            asyncio.create_task(self._execute_campaign_tracking(msg))

    def _handle_query(self, msg: MCPMessage):
        query = msg.payload.query
        if query.query_type == "ioc_lookup":
            ioc_value = query.parameters.get("value")
            ioc_type = query.parameters.get("type", "ip")
            result = self._lookup_ioc(ioc_type, ioc_value)
            response = MCPMessage.Payload(
                message_type=MessageType.QUERY_RESPONSE,
                result=MCPMessage.Payload.Result(status="success", data=result)
            )
            self.client.send_message(msg.envelope.from_addr.agent_id, response, msg.correlation_id)

    async def _execute_ioc_enrichment(self, msg: MCPMessage):
        task = msg.payload.task
        iocs = task.parameters.get("iocs", [])
        incident_id = task.parameters.get("incident_id", "")
        enriched = []

        for ioc in iocs:
            ioc_type = ioc.get("type", "ip")
            ioc_value = ioc.get("value", "")
            intel = self._lookup_ioc(ioc_type, ioc_value)
            enriched.append({"ioc": ioc, "intel": intel})

        self._send_result(msg, "success", data={"incident_id": incident_id, "enriched_iocs": enriched})

    async def _execute_ttp_mapping(self, msg: MCPMessage):
        techniques = msg.payload.task.parameters.get("techniques", [])
        mapping = []
        for tid in techniques:
            mitre_data = self._get_mitre_data(tid)
            mapping.append({"technique_id": tid, "data": mitre_data})
        self._send_result(msg, "success", data={"ttp_mapping": mapping})

    async def _execute_campaign_tracking(self, msg: MCPMessage):
        campaign_name = msg.payload.task.parameters.get("campaign_name", "")
        # Query MISP or other sources
        self._send_result(msg, "success", data={"campaign": campaign_name, "status": "active"})

    def _lookup_ioc(self, ioc_type: str, ioc_value: str) -> Dict:
        cache_key = f"intel:{ioc_type}:{ioc_value}"
        cached = self.client._redis.get(cache_key)
        if cached:
            return json.loads(cached)

        result = {
            "malicious": False,
            "confidence": 0,
            "sources": [],
            "tags": [],
            "associated_actors": [],
            "mitre_mapping": {"tactics": [], "techniques": []},
            "first_seen": None,
            "last_seen": None
        }

        # VirusTotal lookup
        if self.vt_key and ioc_type in ["ip", "domain", "hash"]:
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                # Simplified — in production use async VT client
                result["sources"].append("virustotal")
                result["confidence"] = 50
            except Exception as e:
                logger.error(f"VT lookup error: {e}")

        # MISP lookup
        if self.misp_url and self.misp_key:
            result["sources"].append("misp")

        self.client._redis.setex(cache_key, 3600, json.dumps(result))
        return result

    def _get_mitre_data(self, technique_id: str) -> Dict:
        cache_key = f"mitre:{technique_id}"
        cached = self.client._redis.get(cache_key)
        if cached:
            return json.loads(cached)

        # In production, query MITRE ATT&CK API or local STIX dataset
        data = {
            "name": f"Technique {technique_id}",
            "description": "MITRE ATT&CK technique description",
            "tactics": ["Initial Access"],
            "platforms": ["Windows", "Linux"],
            "data_sources": ["Process monitoring", "File monitoring"]
        }
        self.client._redis.setex(cache_key, 86400, json.dumps(data))
        return data

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Threat Intel Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = ThreatIntelAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Threat Intel Agent shutting down...")
        agent.client.stop()
