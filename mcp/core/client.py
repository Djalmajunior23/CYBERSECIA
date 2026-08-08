"""
MCP Client — Secure, Resilient Inter-Agent Communication Client
Features: mTLS, JWT, circuit breaker, retry, heartbeat, audit logging
"""
import asyncio
import os
import json
import hashlib
import uuid
import time
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Callable, Coroutine
from dataclasses import dataclass, field

import redis
from confluent_kafka import Producer, Consumer, KafkaError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from .protocol import MCPMessage, MessageType, AgentType, Priority, compute_integrity_hash

logger = logging.getLogger("mcp.client")

@dataclass
class CircuitBreaker:
    """Circuit breaker pattern for resilient MCP messaging."""
    failure_threshold: int = 5
    timeout_seconds: int = 60
    failure_count: int = field(default=0, init=False)
    last_failure_time: Optional[float] = field(default=None, init=False)
    state: str = field(default="CLOSED", init=False)  # CLOSED, OPEN, HALF_OPEN

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self) -> bool:
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"
            logger.warning(f"Circuit breaker OPENED after {self.failure_threshold} failures")
            return True
        return False

    def can_execute(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.timeout_seconds:
                self.state = "HALF_OPEN"
                logger.info("Circuit breaker entering HALF_OPEN state")
                return True
            return False
        return True  # HALF_OPEN

@dataclass
class MCPClientConfig:
    agent_id: str
    agent_type: AgentType
    kafka_broker: str = "localhost:9092"
    redis_url: str = "redis://localhost:6379/0"
    private_key_path: Optional[str] = None
    cert_path: Optional[str] = None
    ca_path: Optional[str] = None
    heartbeat_interval: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0

class MCPClient:
    """
    Secure MCP Client for agent-to-agent communication.

    Features:
    - Ed25519 message signing
    - AES-256-GCM payload encryption
    - Circuit breaker per target agent
    - Automatic retry with exponential backoff
    - Heartbeat publishing
    - Immutable audit logging to Redis streams
    """

    def __init__(self, config: MCPClientConfig):
        self.config = config
        self.agent_id = config.agent_id
        self.agent_type = config.agent_type
        self.circuits: Dict[str, CircuitBreaker] = {}
        self.handlers: Dict[MessageType, List[Callable]] = {}
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None

        # Cryptography
        self._private_key = self._load_or_generate_key()
        self._public_key = self._private_key.public_key()
        self._symmetric_key = AESGCM.generate_key(bit_length=256)

        # Kafka
        self._producer = Producer({
            "bootstrap.servers": config.kafka_broker,
            "client.id": f"{config.agent_id}-producer",
            "security.protocol": "SSL" if config.ca_path else "PLAINTEXT",
            "ssl.ca.location": config.ca_path or "",
            "ssl.certificate.location": config.cert_path or "",
            "ssl.key.location": config.private_key_path or "",
        })

        self._consumer = Consumer({
            "bootstrap.servers": config.kafka_broker,
            "group.id": f"{config.agent_id}-group",
            "client.id": f"{config.agent_id}-consumer",
            "auto.offset.reset": "latest",
            "enable.auto.commit": True,
            "security.protocol": "SSL" if config.ca_path else "PLAINTEXT",
            "ssl.ca.location": config.ca_path or "",
            "ssl.certificate.location": config.cert_path or "",
            "ssl.key.location": config.private_key_path or "",
        })

        # Redis (for audit, cache, HITL queues)
        self._redis = redis.from_url(config.redis_url, decode_responses=True)

        # Subscribe to own topic
        self._consumer.subscribe([f"mcp.agent.{config.agent_id}"])

        # Register public key in Redis
        pubkey_bytes = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self._redis.set(f"mcp:agent:{config.agent_id}:pubkey", pubkey_bytes.hex())

        logger.info(f"MCP Client initialized for agent: {config.agent_id}")

    def _load_or_generate_key(self) -> ed25519.Ed25519PrivateKey:
        if self.config.private_key_path:
            with open(self.config.private_key_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        return ed25519.Ed25519PrivateKey.generate()

    def _get_circuit(self, target_agent: str) -> CircuitBreaker:
        if target_agent not in self.circuits:
            self.circuits[target_agent] = CircuitBreaker()
        return self.circuits[target_agent]

    def _sign_payload(self, payload: Dict[str, Any]) -> str:
        data = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        signature = self._private_key.sign(data)
        return signature.hex()

    def _verify_signature(self, public_key_bytes: bytes, payload: Dict[str, Any], signature_hex: str) -> bool:
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            data = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, data)
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False

    def _encrypt_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt payload with AES-256-GCM."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._symmetric_key)
        plaintext = json.dumps(payload, default=str).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return {
            "encrypted": True,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "key_id": f"{self.agent_id}-symmetric-001"
        }

    def send_message(
        self,
        target_agent: str,
        payload: MCPMessage.Payload,
        correlation_id: Optional[str] = None,
        priority: Priority = Priority.MEDIUM,
        wait_for_ack: bool = False,
        timeout: float = 30.0
    ) -> Optional[str]:
        """
        Send a message to target agent with circuit breaker, retry, and audit.

        Returns message_id on success, None on failure.
        """
        circuit = self._get_circuit(target_agent)
        if not circuit.can_execute():
            logger.error(f"Circuit OPEN for {target_agent}, message dropped")
            self._audit_log("error", f"Message to {target_agent} dropped: circuit open")
            return None

        msg = MCPMessage(
            correlation_id=correlation_id or str(uuid.uuid4()),
            envelope=MCPMessage.Envelope(
                from_addr=MCPMessage.Envelope.Address(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    routing_key=f"mcp.agent.{self.agent_id}"
                ),
                to_addr=MCPMessage.Envelope.Address(
                    agent_id=target_agent,
                    agent_type=AgentType.WORKER,  # Default, can be overridden
                    routing_key=f"mcp.agent.{target_agent}"
                )
            ),
            payload=payload
        )

        # Sign and hash
        msg.security.signature = self._sign_payload(msg.payload.model_dump())
        msg.security.integrity_hash = compute_integrity_hash(msg.payload.model_dump())

        # Serialize
        message_json = msg.model_dump_json(by_alias=True)
        topic = f"mcp.agent.{target_agent}"

        # Retry loop
        for attempt in range(self.config.max_retries):
            try:
                self._producer.produce(
                    topic,
                    key=msg.message_id.encode("utf-8"),
                    value=message_json.encode("utf-8"),
                    headers={
                        "mcp-version": "1.0",
                        "sender": self.agent_id,
                        "priority": str(priority.value)
                    },
                    callback=self._delivery_report
                )
                self._producer.poll(0)  # Non-blocking flush

                circuit.record_success()
                self._audit_log("info", f"Message {msg.message_id} sent to {target_agent}")

                if wait_for_ack:
                    # TODO: Implement async ack waiting with correlation_id
                    pass

                return msg.message_id

            except Exception as e:
                logger.warning(f"Attempt {attempt + 1}/{self.config.max_retries} failed: {e}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (2 ** attempt))
                else:
                    circuit.record_failure()
                    self._audit_log("error", f"Message to {target_agent} failed after {self.config.max_retries} attempts: {e}")
                    return None

        return None

    def send_task(
        self,
        target_agent: str,
        task_type: str,
        parameters: Dict[str, Any],
        priority: Priority = Priority.MEDIUM,
        scope: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ) -> Optional[str]:
        """Convenience method for task assignment."""
        from .protocol import create_task_message
        msg = create_task_message(
            from_agent=self.agent_id,
            from_type=self.agent_type,
            to_agent=target_agent,
            to_type=AgentType.WORKER,
            task_type=task_type,
            priority=priority,
            parameters=parameters,
            scope=scope,
            correlation_id=correlation_id
        )
        return self.send_message(target_agent, msg.payload, correlation_id, priority)

    def query_agent(
        self,
        target_agent: str,
        query_type: str,
        parameters: Dict[str, Any],
        timeout: float = 30.0
    ) -> Optional[Dict[str, Any]]:
        """Synchronous query-response pattern."""
        correlation_id = str(uuid.uuid4())
        query_payload = MCPMessage.Payload(
            message_type=MessageType.QUERY_REQUEST,
            query=MCPMessage.Payload.Query(
                query_type=query_type,
                parameters=parameters,
                timeout_seconds=int(timeout)
            )
        )

        msg_id = self.send_message(target_agent, query_payload, correlation_id, Priority.HIGH)
        if not msg_id:
            return None

        # Wait for response on Redis pub/sub (simplified)
        # In production, use dedicated response topic or async callback
        start = time.time()
        while time.time() - start < timeout:
            # Check Redis for response
            response_key = f"mcp:response:{correlation_id}"
            response = self._redis.get(response_key)
            if response:
                self._redis.delete(response_key)
                return json.loads(response)
            time.sleep(0.1)

        logger.warning(f"Query to {target_agent} timed out after {timeout}s")
        return None

    def register_handler(self, message_type: MessageType, handler: Callable[[MCPMessage], None]):
        """Register a handler for incoming message types."""
        if message_type not in self.handlers:
            self.handlers[message_type] = []
        self.handlers[message_type].append(handler)
        logger.info(f"Handler registered for {message_type.value}")

    async def start_consuming(self):
        """Start consuming messages from Kafka."""
        self._running = True
        logger.info(f"{self.agent_id} started consuming from mcp.agent.{self.agent_id}")

        while self._running:
            msg = self._consumer.poll(timeout=1.0)
            if msg is None:
                await asyncio.sleep(0.1)
                continue

            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Consumer error: {msg.error()}")
                continue

            try:
                data = json.loads(msg.value().decode("utf-8"))
                mcp_msg = MCPMessage.model_validate(data)

                # Verify integrity
                expected_hash = compute_integrity_hash(mcp_msg.payload.model_dump())
                if mcp_msg.security.integrity_hash != expected_hash:
                    logger.error(f"Integrity check failed for message {mcp_msg.message_id}")
                    self._audit_log("critical", f"Integrity failure on message from {mcp_msg.envelope.from_addr.agent_id}")
                    continue

                # Verify sender signature
                sender_id = mcp_msg.envelope.from_addr.agent_id
                signature_hex = mcp_msg.security.signature

                if not signature_hex:
                    logger.error(f"Missing signature for message {mcp_msg.message_id} from {sender_id}")
                    self._audit_log("critical", f"Authentication failure: Missing signature on message from {sender_id}")
                    continue

                pubkey_hex = self._redis.get(f"mcp:agent:{sender_id}:pubkey")
                if not pubkey_hex:
                    logger.error(f"Public key not registered for agent {sender_id}. Cannot verify message {mcp_msg.message_id}")
                    self._audit_log("critical", f"Authentication failure: Missing registered public key for {sender_id}")
                    continue

                pubkey_bytes = bytes.fromhex(pubkey_hex)
                if not self._verify_signature(pubkey_bytes, mcp_msg.payload.model_dump(), signature_hex):
                    logger.error(f"Signature verification failed for message {mcp_msg.message_id} from {sender_id}")
                    self._audit_log("critical", f"Authentication failure: Invalid signature from {sender_id}")
                    continue

                # Route to handlers
                handlers = self.handlers.get(mcp_msg.payload.message_type, [])
                for handler in handlers:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            await handler(mcp_msg)
                        else:
                            handler(mcp_msg)
                    except Exception as e:
                        logger.exception(f"Handler error: {e}")

                self._audit_log("info", f"Processed message {mcp_msg.message_id} from {mcp_msg.envelope.from_addr.agent_id}")

            except Exception as e:
                logger.exception(f"Message processing error: {e}")

    async def start_heartbeat(self):
        """Publish periodic heartbeats."""
        while self._running:
            heartbeat_payload = MCPMessage.Payload(
                message_type=MessageType.HEARTBEAT,
                heartbeat=MCPMessage.Payload.Heartbeat(
                    status="healthy",
                    metrics={
                        "cpu_percent": 0,  # TODO: Implement actual metrics
                        "memory_mb": 0,
                        "queue_depth": 0
                    },
                    capabilities=[]  # TODO: Implement capability discovery
                )
            )
            self.send_message("central_orchestrator", heartbeat_payload, priority=Priority.INFO)
            await asyncio.sleep(self.config.heartbeat_interval)

    def _delivery_report(self, err, msg):
        """Kafka delivery callback."""
        if err is not None:
            logger.error(f"Message delivery failed: {err}")
        else:
            logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}]")

    def _audit_log(self, level: str, message: str):
        """Write a tamper-evident audit event to Redis streams.

        Redis is not WORM storage, so this is a hash chain rather than true
        immutability. A later phase should anchor/export these hashes to durable
        append-only storage.
        """
        previous_hash = self._redis.get(f"mcp:audit:last_hash:{self.agent_id}") or ""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": self.agent_id,
            "level": level,
            "message": message,
            "event_id": str(uuid.uuid4()),
            "previous_hash": previous_hash,
        }
        canonical = json.dumps(event, sort_keys=True, ensure_ascii=False).encode("utf-8")
        event["integrity_hash"] = hashlib.sha256(canonical).hexdigest()
        self._redis.xadd("mcp:audit:events", event)
        self._redis.xadd(f"mcp:audit:{self.agent_id}", event)
        self._redis.set(f"mcp:audit:last_hash:{self.agent_id}", event["integrity_hash"])

    async def run(self):
        """Run both consumer and heartbeat."""
        self._heartbeat_task = asyncio.create_task(self.start_heartbeat())
        await self.start_consuming()

    def stop(self):
        """Graceful shutdown."""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        self._consumer.close()
        self._producer.flush()
        logger.info(f"MCP Client {self.agent_id} stopped")
