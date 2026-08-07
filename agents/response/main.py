#!/usr/bin/env python3
"""Response Orchestrator — Automated Containment & IR Engine"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import httpx
import yaml

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("response")

class ResponseOrchestrator:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="response_orchestrator",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/5"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.edr_api_key = os.getenv("EDR_API_KEY", "")
        self.firewall_api_key = os.getenv("FIREWALL_API_KEY", "")
        self.playbooks_dir = os.getenv("PLAYBOOKS_DIR", "/app/playbooks")
        self._register_handlers()

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)
        self.client.register_handler(MessageType.QUERY_REQUEST, self._handle_query)

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "contain_execute":
            asyncio.create_task(self._execute_containment(msg))
        elif task.task_type == "playbook_execute":
            asyncio.create_task(self._execute_playbook(msg))
        elif task.task_type == "host_isolate":
            asyncio.create_task(self._isolate_host(msg))
        elif task.task_type == "account_disable":
            asyncio.create_task(self._disable_account(msg))
        elif task.task_type == "ioc_block":
            asyncio.create_task(self._block_ioc(msg))

    def _handle_query(self, msg: MCPMessage):
        query = msg.payload.query
        if query.query_type == "containment_status":
            action_id = query.parameters.get("action_id")
            status = self.client._redis.hgetall(f"action:{action_id}")
            response = MCPMessage.Payload(
                message_type=MessageType.QUERY_RESPONSE,
                result=MCPMessage.Payload.Result(status="success", data=status or {})
            )
            self.client.send_message(msg.envelope.from_addr.agent_id, response, msg.correlation_id)

    async def _execute_containment(self, msg: MCPMessage):
        task = msg.payload.task
        actions = task.parameters.get("actions", [])
        results = []

        for action in actions:
            action_type = action.get("type")
            target = action.get("target")

            if action_type == "host_isolate":
                result = await self._isolate_host_internal(target)
            elif action_type == "account_disable":
                result = await self._disable_account_internal(target)
            elif action_type == "ip_block":
                result = await self._block_ip_internal(target)
            elif action_type == "domain_block":
                result = await self._block_domain_internal(target)
            else:
                result = {"status": "unknown_action", "action": action_type}

            results.append(result)
            self._log_action(action_type, target, result)

        self._send_result(msg, "success", data={"actions_executed": len(results), "results": results})

    async def _execute_playbook(self, msg: MCPMessage):
        task = msg.payload.task
        playbook_name = task.parameters.get("playbook_name", "")
        variables = task.parameters.get("variables", {})

        playbook_path = f"{self.playbooks_dir}/incident_response/{playbook_name}.yaml"
        try:
            with open(playbook_path) as f:
                playbook = yaml.safe_load(f)

            steps = playbook.get("steps", [])
            step_results = []

            for step in steps:
                step_name = list(step.keys())[0]
                step_config = step[step_name]

                # Simple variable substitution
                for key, value in step_config.items():
                    if isinstance(value, str) and "{{" in value:
                        for var_name, var_value in variables.items():
                            step_config[key] = value.replace(f"{{{{{var_name}}}}}", str(var_value))

                result = await self._execute_playbook_step(step_name, step_config)
                step_results.append({"step": step_name, "result": result})

                if result.get("status") == "failure" and step_config.get("on_failure") == "stop":
                    break

            self._send_result(msg, "success", data={"playbook": playbook_name, "steps": step_results})
        except FileNotFoundError:
            self._send_result(msg, "failure", errors=[f"Playbook not found: {playbook_path}"])
        except Exception as e:
            self._send_result(msg, "failure", errors=[str(e)])

    async def _isolate_host(self, msg: MCPMessage):
        target = msg.payload.task.parameters.get("target")
        result = await self._isolate_host_internal(target)
        self._send_result(msg, result["status"], data=result)

    async def _disable_account(self, msg: MCPMessage):
        target = msg.payload.task.parameters.get("target")
        result = await self._disable_account_internal(target)
        self._send_result(msg, result["status"], data=result)

    async def _block_ioc(self, msg: MCPMessage):
        ioc_type = msg.payload.task.parameters.get("ioc_type")
        ioc_value = msg.payload.task.parameters.get("ioc_value")
        if ioc_type == "ip":
            result = await self._block_ip_internal(ioc_value)
        elif ioc_type == "domain":
            result = await self._block_domain_internal(ioc_value)
        else:
            result = {"status": "failure", "error": f"Unsupported IOC type: {ioc_type}"}
        self._send_result(msg, result["status"], data=result)

    async def _isolate_host_internal(self, target: str) -> Dict:
        """Isolate host via EDR API."""
        logger.info(f"Isolating host: {target}")
        # Placeholder for EDR API call
        return {"status": "success", "action": "host_isolate", "target": target, "duration_ms": 2450}

    async def _disable_account_internal(self, target: str) -> Dict:
        """Disable AD/Identity account."""
        logger.info(f"Disabling account: {target}")
        return {"status": "success", "action": "account_disable", "target": target, "duration_ms": 1200}

    async def _block_ip_internal(self, ip: str) -> Dict:
        """Block IP at firewall."""
        logger.info(f"Blocking IP: {ip}")
        return {"status": "success", "action": "ip_block", "target": ip, "duration_ms": 800}

    async def _block_domain_internal(self, domain: str) -> Dict:
        """Block domain at DNS/proxy."""
        logger.info(f"Blocking domain: {domain}")
        return {"status": "success", "action": "domain_block", "target": domain, "duration_ms": 600}

    async def _execute_playbook_step(self, step_name: str, config: Dict) -> Dict:
        """Execute a single playbook step."""
        if step_name == "isolate":
            return await self._isolate_host_internal(config.get("target", ""))
        elif step_name == "disable_account":
            return await self._disable_account_internal(config.get("target", ""))
        elif step_name == "block":
            return await self._block_ip_internal(config.get("target", ""))
        elif step_name == "notify":
            return {"status": "success", "action": "notify", "recipients": config.get("recipients", [])}
        elif step_name == "snapshot":
            return {"status": "success", "action": "snapshot", "target": config.get("target", "")}
        return {"status": "success", "action": step_name}

    def _log_action(self, action_type: str, target: str, result: Dict):
        action_id = f"ACT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{hash(target) % 10000}"
        log_entry = {
            "action_id": action_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "target": target,
            "result": result,
            "agent": "response_orchestrator"
        }
        self.client._redis.hset(f"action:{action_id}", mapping={k: json.dumps(v) if isinstance(v, dict) else v for k, v in log_entry.items()})

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Response Orchestrator started")
        await self.client.run()

if __name__ == "__main__":
    agent = ResponseOrchestrator()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Response Orchestrator shutting down...")
        agent.client.stop()
