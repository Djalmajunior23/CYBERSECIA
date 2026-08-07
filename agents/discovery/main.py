#!/usr/bin/env python3
"""Discovery Agent — Network Reconnaissance & Asset Inventory Engine"""
import os
import sys
import json
import asyncio
import logging
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from mcp.core import MCPClient, MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("discovery")

class DiscoveryAgent:
    def __init__(self):
        self.config = MCPClientConfig(
            agent_id="discovery_agent",
            agent_type=AgentType.WORKER,
            kafka_broker=os.getenv("KAFKA_BROKER", "kafka:29092"),
            redis_url=os.getenv("REDIS_URL", "redis://redis:6379/1"),
            heartbeat_interval=30
        )
        self.client = MCPClient(self.config)
        self.rate_limit = int(os.getenv("RATE_LIMIT", "1000"))
        self.nmap_privileged = os.getenv("NMAP_PRIVILEGED", "true").lower() == "true"
        self.authorized_scopes: List[str] = []
        self.excluded_targets: List[str] = []
        self.asset_risk_default: Dict[str, Any] = {}
        self.asset_risk_profiles: List[Dict[str, Any]] = []
        self._load_scopes()
        self._load_asset_risk_profiles()
        self._register_handlers()

    def _load_scopes(self):
        """Load explicitly authorized scan networks and deny-list exclusions.

        Production containers use /app/config by default. Local development/tests
        fall back to the repository config without silently authorizing anything
        when both files are absent.
        """
        configured_path = os.getenv(
            "AUTHORIZED_SCOPES_FILE",
            "/app/config/scopes/authorized_networks.json",
        )
        candidates = [configured_path]
        local_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "config", "scopes", "authorized_networks.json")
        )
        if local_path not in candidates:
            candidates.append(local_path)

        for scope_file in candidates:
            try:
                with open(scope_file, encoding="utf-8") as f:
                    data = json.load(f)
                self.authorized_scopes = data.get("networks", [])
                self.excluded_targets = data.get("exclusions", [])
                logger.info(
                    "Loaded %d authorized scopes and %d exclusions from %s",
                    len(self.authorized_scopes),
                    len(self.excluded_targets),
                    scope_file,
                )
                return
            except FileNotFoundError:
                continue
            except (OSError, json.JSONDecodeError) as exc:
                logger.error("Failed to load scope file %s: %s", scope_file, exc)
                break

        logger.warning("No valid authorized scope file found; all scan targets will be denied")
        self.authorized_scopes = []
        self.excluded_targets = []


    def _load_asset_risk_profiles(self):
        configured_path = os.getenv(
            "ASSET_RISK_PROFILES_FILE",
            "/app/config/assets/risk_profiles.json",
        )
        candidates = [configured_path]
        local_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "config", "assets", "risk_profiles.json")
        )
        if local_path not in candidates:
            candidates.append(local_path)

        for profile_file in candidates:
            try:
                with open(profile_file, encoding="utf-8") as handle:
                    data = json.load(handle)
                self.asset_risk_default = data.get("default", {})
                self.asset_risk_profiles = data.get("profiles", [])
                logger.info("Loaded %d asset risk profiles from %s", len(self.asset_risk_profiles), profile_file)
                return
            except FileNotFoundError:
                continue
            except (OSError, json.JSONDecodeError) as exc:
                logger.error("Failed to load asset risk profiles %s: %s", profile_file, exc)
                break

        self.asset_risk_default = {"criticality": 5.0, "internet_exposed": False}
        self.asset_risk_profiles = []

    def _risk_context_for_ip(self, ip: str) -> Dict[str, Any]:
        context = dict(self.asset_risk_default)
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return context

        matches = []
        for profile in self.asset_risk_profiles:
            network_value = profile.get("network")
            if not network_value:
                continue
            try:
                network = ipaddress.ip_network(network_value, strict=False)
            except ValueError:
                logger.warning("Ignoring invalid asset risk profile network: %s", network_value)
                continue
            if address in network:
                matches.append((network.prefixlen, profile))

        if matches:
            _, selected = max(matches, key=lambda item: item[0])
            context.update({k: v for k, v in selected.items() if k != "network"})
        return context

    def _register_handlers(self):
        self.client.register_handler(MessageType.TASK_ASSIGNMENT, self._handle_task)
        self.client.register_handler(MessageType.QUERY_REQUEST, self._handle_query)

    def _is_authorized(self, target: str) -> bool:
        """Return True only when the complete target is inside an allowed scope.

        A requested network must be a subnet of an authorized network; supernets
        are never accepted. Explicit exclusions always win, including when an
        excluded host falls inside a requested CIDR range. Hostnames are denied
        here because they cannot be scope-validated without controlled resolution.
        """
        try:
            target_net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False

        try:
            scope_networks = [ipaddress.ip_network(scope, strict=False) for scope in self.authorized_scopes]
            exclusions = [ipaddress.ip_network(item, strict=False) for item in self.excluded_targets]
        except ValueError as exc:
            logger.error("Invalid network in scope configuration: %s", exc)
            return False

        if not any(target_net.subnet_of(scope_net) for scope_net in scope_networks):
            return False

        # If the requested host/network contains any excluded address/network, deny
        # the whole target instead of allowing a scan to cross a deny-list boundary.
        for excluded in exclusions:
            if excluded.subnet_of(target_net) or target_net.subnet_of(excluded):
                return False

        return True

    def _handle_task(self, msg: MCPMessage):
        task = msg.payload.task
        if task.task_type == "network_scan":
            asyncio.create_task(self._execute_network_scan(msg))
        elif task.task_type == "host_discovery":
            asyncio.create_task(self._execute_host_discovery(msg))
        elif task.task_type == "service_fingerprint":
            asyncio.create_task(self._execute_service_fingerprint(msg))

    def _handle_query(self, msg: MCPMessage):
        query = msg.payload.query
        if query.query_type == "asset_lookup":
            asset_id = query.parameters.get("asset_id")
            result = self.client._redis.hgetall(f"cmdb:asset:{asset_id}")
            response = MCPMessage.Payload(
                message_type=MessageType.QUERY_RESPONSE,
                result=MCPMessage.Payload.Result(status="success", data=result or {})
            )
            self.client.send_message(msg.envelope.from_addr.agent_id, response, msg.correlation_id)

    async def _execute_network_scan(self, msg: MCPMessage):
        task = msg.payload.task
        targets = task.scope.get("targets", []) if task.scope else []
        scan_type = task.parameters.get("scan_type", "comprehensive")
        unauthorized = [t for t in targets if not self._is_authorized(t)]
        if unauthorized:
            logger.error(f"Unauthorized targets: {unauthorized}")
            self._send_result(msg, "blocked", errors=[f"Unauthorized targets: {unauthorized}"])
            return
        logger.info(f"Starting {scan_type} scan of {targets}")
        cmd = ["nmap"]
        if self.nmap_privileged:
            cmd.append("-sS")
        else:
            cmd.append("-sT")
        if scan_type == "comprehensive":
            cmd.extend(["-sV", "-sC", "-O", "--top-ports", "1000", "-T4"])
        elif scan_type == "quick":
            cmd.extend(["-F", "-T4"])
        elif scan_type == "udp":
            cmd.extend(["-sU", "--top-ports", "100", "-T4"])
        cmd.extend(["--max-rate", str(self.rate_limit), "-oX", "-"])
        cmd.extend(targets)
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)
            if proc.returncode != 0:
                self._send_result(msg, "failure", errors=[stderr.decode()])
                return
            hosts = self._parse_nmap_xml(stdout.decode())
            for host in hosts:
                self._update_cmdb(host)
            self._send_result(msg, "success", data={"hosts": hosts, "total": len(hosts)})
            self.client.send_task("vulnerability_agent", "vuln_assess", {"hosts": hosts}, Priority.MEDIUM, correlation_id=msg.correlation_id)
        except asyncio.TimeoutError:
            self._send_result(msg, "failure", errors=["Scan timeout"])
        except Exception as e:
            self._send_result(msg, "failure", errors=[str(e)])

    async def _execute_host_discovery(self, msg: MCPMessage):
        task = msg.payload.task
        targets = task.scope.get("targets", []) if task.scope else []
        cmd = ["nmap", "-sn", "-PE", "-PP", "-PM"]
        cmd.extend(targets)
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            hosts = []
            for line in stdout.decode().split("\n"):
                if "Nmap scan report for" in line:
                    ip = line.split("for")[-1].strip()
                    hosts.append({"ip": ip, "status": "up"})
            self._send_result(msg, "success", data={"hosts_discovered": hosts})
        except Exception as e:
            self._send_result(msg, "failure", errors=[str(e)])

    async def _execute_service_fingerprint(self, msg: MCPMessage):
        task = msg.payload.task
        targets = task.parameters.get("targets", [])
        cmd = ["nmap", "-sV", "--version-intensity", "9", "-p", "1-65535"]
        cmd.extend(targets)
        try:
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            services = self._parse_nmap_services(stdout.decode())
            self._send_result(msg, "success", data={"services": services})
        except Exception as e:
            self._send_result(msg, "failure", errors=[str(e)])

    def _parse_nmap_xml(self, xml_data: str) -> List[Dict[str, Any]]:
        import xml.etree.ElementTree as ET
        hosts = []
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall("host"):
                h = {"ip": "", "status": "unknown", "ports": [], "os": {}}
                addr = host.find("address")
                if addr is not None:
                    h["ip"] = addr.get("addr", "")
                status = host.find("status")
                if status is not None:
                    h["status"] = status.get("state", "unknown")
                for port in host.findall("ports/port"):
                    service_elem = port.find("service")
                    state_elem = port.find("state")
                    cpes = []
                    if service_elem is not None:
                        cpes = [node.text for node in service_elem.findall("cpe") if node.text]
                    p = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", ""),
                        "state": state_elem.get("state") if state_elem is not None else "unknown",
                        "service": service_elem.get("name", "") if service_elem is not None else "",
                        "product": service_elem.get("product", "") if service_elem is not None else "",
                        "version": service_elem.get("version", "") if service_elem is not None else "",
                        "banner": service_elem.get("extrainfo", "") if service_elem is not None else "",
                        "cpes": cpes,
                    }
                    h["ports"].append(p)
                os_elem = host.find("os/osmatch")
                if os_elem is not None:
                    h["os"] = {"name": os_elem.get("name"), "accuracy": int(os_elem.get("accuracy", 0))}
                h["risk_context"] = self._risk_context_for_ip(h["ip"])
                hosts.append(h)
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
        return hosts

    def _parse_nmap_services(self, output: str) -> List[Dict[str, Any]]:
        return []

    def _update_cmdb(self, host: Dict[str, Any]):
        asset_key = f"cmdb:asset:{host['ip']}"
        host["last_seen"] = datetime.now(timezone.utc).isoformat()
        self.client._redis.hset(asset_key, mapping={k: json.dumps(v) if isinstance(v, (list, dict)) else v for k, v in host.items()})
        self.client._redis.sadd("cmdb:assets", host["ip"])

    def _send_result(self, original_msg: MCPMessage, status: str, data: Optional[Dict] = None, errors: Optional[List[str]] = None):
        result_payload = MCPMessage.Payload(
            message_type=MessageType.TASK_RESULT,
            result=MCPMessage.Payload.Result(status=status, completion_time=datetime.now(timezone.utc), data=data or {}, errors=errors or [])
        )
        self.client.send_message("central_orchestrator", result_payload, correlation_id=original_msg.correlation_id)

    async def run(self):
        logger.info("Discovery Agent started")
        await self.client.run()

if __name__ == "__main__":
    agent = DiscoveryAgent()
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Discovery Agent shutting down...")
        agent.client.stop()
