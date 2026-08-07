#!/usr/bin/env python3
"""Correlation Agent — Asset Intelligence, Knowledge Graph & Risk Hypotheses."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import redis

from agents.correlation.engine import KnowledgeGraphEngine
from mcp.core import AgentType, MCPClient, MCPClientConfig, MCPMessage, MessageType

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("correlation")


class CorrelationAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="correlation_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/15"),
            heartbeat_interval=30,
        )
        self.client = MCPClient(self.config)
        self.state_redis = redis.from_url(
            os.getenv("STATE_REDIS_URL", "redis://redis:6379/0"),
            decode_responses=True,
        )
        self.engine = KnowledgeGraphEngine(os.getenv("DEFENSIVE_CONTROLS_FILE"))
        self.rebuild_interval = max(30, int(os.getenv("GRAPH_REBUILD_INTERVAL", "120")))
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)
        self.client.register_handler(MessageType.QUERY_REQUEST, self._handle_query)

    def _handle_task(self, msg: MCPMessage):
        if msg.payload.task.task_type in {"graph_rebuild", "correlate_risk", "asset_intelligence_refresh"}:
            asyncio.create_task(self._execute_rebuild(msg))

    def _handle_query(self, msg: MCPMessage):
        query = msg.payload.query
        if query.query_type not in {"graph_summary", "risk_correlations", "attack_paths"}:
            return
        key_map = {
            "graph_summary": "mcp:kg:summary",
            "risk_correlations": "mcp:correlations:last",
            "attack_paths": "mcp:attack-paths:last",
        }
        raw = self.state_redis.get(key_map[query.query_type])
        data = json.loads(raw) if raw else {}
        payload = MCPMessage.Payload(
            message_type=MessageType.QUERY_RESPONSE,
            result=MCPMessage.Payload.Result(status="success", data=data),
        )
        self.client.send_message(msg.envelope.from_addr.agent_id, payload, correlation_id=msg.correlation_id)

    @staticmethod
    def _decode_hash(raw: Dict[str, str]) -> List[Dict[str, Any]]:
        rows = []
        for value in raw.values():
            try:
                rows.append(json.loads(value))
            except (TypeError, json.JSONDecodeError):
                continue
        return rows

    def _load_state(self) -> Dict[str, Any]:
        return {
            "assets": self._decode_hash(self.state_redis.hgetall("mcp:assets")),
            "vulnerabilities": self._decode_hash(self.state_redis.hgetall("mcp:vulnerabilities")),
            "remediations": self._decode_hash(self.state_redis.hgetall("mcp:remediation")),
            "incidents": self._decode_hash(self.state_redis.hgetall("mcp:incidents")),
            "iocs": self._decode_hash(self.state_redis.hgetall("mcp:intel:iocs")),
            "techniques": self._decode_hash(self.state_redis.hgetall("mcp:intel:techniques")),
            "campaigns": self._decode_hash(self.state_redis.hgetall("mcp:intel:campaigns")),
        }

    def rebuild(self) -> Dict[str, Any]:
        graph = self.engine.build(self._load_state())
        pipe = self.state_redis.pipeline(transaction=False)
        pipe.delete("mcp:kg:nodes", "mcp:kg:edges", "mcp:correlations", "mcp:attack-paths")
        for node in graph["nodes"]:
            pipe.hset("mcp:kg:nodes", node["id"], json.dumps(node, ensure_ascii=False))
        for edge in graph["edges"]:
            pipe.hset("mcp:kg:edges", edge["id"], json.dumps(edge, ensure_ascii=False))
        for item in graph["correlations"]:
            pipe.hset("mcp:correlations", item["correlation_id"], json.dumps(item, ensure_ascii=False))
        for item in graph["attack_paths"]:
            pipe.hset("mcp:attack-paths", item["path_id"], json.dumps(item, ensure_ascii=False))
        pipe.set("mcp:kg:summary", json.dumps(graph["summary"], ensure_ascii=False))
        pipe.set("mcp:correlations:last", json.dumps({"items": graph["correlations"], "generated_at": graph["summary"]["generated_at"]}, ensure_ascii=False))
        pipe.set("mcp:attack-paths:last", json.dumps({"items": graph["attack_paths"], "generated_at": graph["summary"]["generated_at"]}, ensure_ascii=False))
        pipe.xadd("mcp:kg:rebuilds", {"timestamp": graph["summary"]["generated_at"], "summary": json.dumps(graph["summary"], ensure_ascii=False)})
        pipe.execute()
        return graph

    async def _execute_rebuild(self, msg: MCPMessage):
        graph = await asyncio.to_thread(self.rebuild)
        self._send_result(
            msg,
            "success",
            data={
                "knowledge_graph": graph["summary"],
                "correlations": graph["correlations"][:50],
                "attack_paths": graph["attack_paths"][:50],
            },
        )

    async def _periodic_rebuild(self):
        while True:
            try:
                graph = await asyncio.to_thread(self.rebuild)
                logger.info(
                    "Knowledge graph rebuilt: %s nodes, %s edges, %s correlations",
                    graph["summary"]["nodes"],
                    graph["summary"]["edges"],
                    graph["summary"]["correlations"],
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception("Knowledge graph rebuild failed: %s", exc)
            await asyncio.sleep(self.rebuild_interval)

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(
                status=status,
                completion_time=datetime.now(timezone.utc),
                data=data or {},
                errors=errors or [],
            ),
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Correlation Agent started")
        rebuild_task = asyncio.create_task(self._periodic_rebuild())
        try:
            await self.client.run()
        finally:
            rebuild_task.cancel()


if __name__ == "__main__":
    agent = CorrelationAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Correlation Agent shutting down...")
        agent.client.stop()
