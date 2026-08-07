#!/usr/bin/env python3
"""MCP Security Auditor — MCP Connection Auditing & Shadow Server Detection"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("mcp_auditor")

class MCPAuditorAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="mcp_auditor_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/10"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.registry_path = os.getenv("MCP_CONFIG_PATH", "/app/config/mcp_servers.json")
        self.registry = self._load_registry()
        self._register_handlers()


    def _load_registry(self) -> Dict[str, Any]:
        candidates = [
            self.registry_path,
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "config", "mcp_servers.json")),
        ]
        for path in candidates:
            try:
                with open(path, encoding="utf-8") as handle:
                    data = json.load(handle)
                logger.info("Loaded MCP registry from %s", path)
                return data
            except FileNotFoundError:
                continue
            except (OSError, json.JSONDecodeError) as exc:
                logger.error("Failed to load MCP registry %s: %s", path, exc)
                break
        logger.warning("No MCP registry available; audits require explicit server input")
        return {"authorized_servers": [], "prohibited_servers": []}

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "mcp_audit":
            asyncio.create_task(self._execute_audit(msg))
        elif task.task_type == "shadow_server_discovery":
            asyncio.create_task(self._discover_shadow_servers(msg))

    async def _execute_audit(self, msg: MCPMessage):
        task = msg.payload.task
        mcp_servers = task.parameters.get("mcp_servers") or self.registry.get("authorized_servers", [])
        findings = []

        for server in mcp_servers:
            # Check for known vulnerabilities
            if server.get("transport") == "stdio" and server.get("command"):
                findings.append({
                    "server": server.get("name"),
                    "finding": "RCE via STDIO",
                    "severity": "critical",
                    "mcp_id": "MCP01",
                    "remediation": "Validate command path, use sandbox"
                })

            if server.get("oauth_scopes") == ["*"]:
                findings.append({
                    "server": server.get("name"),
                    "finding": "Overly broad OAuth scopes",
                    "severity": "high",
                    "mcp_id": "MCP02",
                    "remediation": "Apply least-privilege scopes"
                })

        self._send_result(msg, "success", data={
            "servers_audited": len(mcp_servers),
            "findings": findings,
            "shadow_servers": 0
        })

    async def _discover_shadow_servers(self, msg: MCPMessage):
        observed = msg.payload.task.parameters.get("observed_servers", [])
        authorized = self.registry.get("authorized_servers", [])
        authorized_names = {server.get("name") for server in authorized}
        authorized_urls = {server.get("url") for server in authorized}

        shadow_servers = [
            server for server in observed
            if server.get("name") not in authorized_names and server.get("url") not in authorized_urls
        ]
        self._send_result(msg, "success", data={
            "shadow_servers": shadow_servers,
            "observed": len(observed),
            "authorized_registry_size": len(authorized),
            "scan_coverage": "provided_inventory" if observed else "registry_only",
        })

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("MCP Auditor Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = MCPAuditorAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("MCP Auditor Agent shutting down...")
        agent.client.stop()
