"""
MCP Protocol Core — Message Schema, Validation, and Serialization
Implements the Model Context Protocol v1.0 for inter-agent communication.
"""
import json
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Literal
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field

class MessageType(str, Enum):
    TASK_ASSIGNMENT = "task_assignment"
    TASK_RESULT = "task_result"
    EVENT_NOTIFICATION = "event_notification"
    QUERY_REQUEST = "query_request"
    QUERY_RESPONSE = "query_response"
    ALERT = "alert"
    HEARTBEAT = "heartbeat"
    AUTHORIZATION_REQUEST = "authorization_request"
    AUTHORIZATION_RESPONSE = "authorization_response"

class AgentType(str, Enum):
    ORCHESTRATOR = "orchestrator"
    WORKER = "worker"
    GOVERNANCE = "governance"

class Priority(int, Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

class MCPMessage(BaseModel):
    mcp_version: Literal["1.0"] = "1.0"
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: int = Field(default=300, ge=30, le=3600)

    envelope: "Envelope" = Field(...)
    payload: "Payload" = Field(...)
    security: "Security" = Field(default_factory=lambda: MCPMessage.Security())
    audit: "Audit" = Field(default_factory=lambda: MCPMessage.Audit())

    class Envelope(BaseModel):
        model_config = ConfigDict(populate_by_name=True)

        from_addr: "Address" = Field(..., alias="from")
        to_addr: "Address" = Field(..., alias="to")
        cc: List["Address"] = Field(default_factory=list)

        class Address(BaseModel):
            agent_id: str
            agent_type: AgentType
            instance: Optional[str] = None
            routing_key: Optional[str] = None

    class Payload(BaseModel):
        message_type: MessageType
        task: Optional["Task"] = None
        result: Optional["Result"] = None
        query: Optional["Query"] = None
        alert: Optional["Alert"] = None
        heartbeat: Optional["Heartbeat"] = None
        authorization: Optional["Authorization"] = None

        class Task(BaseModel):
            task_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
            task_type: str
            priority: Priority = Priority.MEDIUM
            scope: Optional[Dict[str, Any]] = None
            parameters: Optional[Dict[str, Any]] = None
            context: Optional[Dict[str, Any]] = None

        class Result(BaseModel):
            status: str = Field(..., pattern="^(success|partial|failure|blocked)$")
            completion_time: Optional[datetime] = None
            data: Optional[Dict[str, Any]] = None
            findings: List[Dict[str, Any]] = Field(default_factory=list)
            errors: List[str] = Field(default_factory=list)

        class Query(BaseModel):
            query_type: str
            parameters: Dict[str, Any]
            timeout_seconds: int = 30

        class Alert(BaseModel):
            severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
            title: str
            description: str
            source: str
            iocs: List[Dict[str, Any]] = Field(default_factory=list)
            mitre_techniques: List[str] = Field(default_factory=list)

        class Heartbeat(BaseModel):
            status: str = Field(..., pattern="^(healthy|degraded|unhealthy)$")
            metrics: Optional[Dict[str, Any]] = None
            capabilities: List[str] = Field(default_factory=list)

        class Authorization(BaseModel):
            required: bool = True
            auth_type: str = Field(default="auto", pattern="^(none|auto|hitl|dual)$")
            status: Optional[str] = Field(None, pattern="^(granted|pending|denied)$")
            approver: Optional[str] = None
            approval_time: Optional[datetime] = None

    class Security(BaseModel):
        classification: str = Field(default="internal", pattern="^(public|internal|confidential|restricted)$")
        encryption: str = Field(default="aes-256-gcm")
        signature: Optional[str] = None
        integrity_hash: Optional[str] = None

    class Audit(BaseModel):
        event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
        log_level: str = Field(default="info", pattern="^(debug|info|warning|error|critical)$")
        retention_years: int = Field(default=7, ge=1, le=25)

def compute_integrity_hash(payload: Dict[str, Any]) -> str:
    """Compute SHA-256 integrity hash of payload."""
    canonical = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def create_task_message(
    from_agent: str,
    from_type: AgentType,
    to_agent: str,
    to_type: AgentType,
    task_type: str,
    priority: Priority,
    parameters: Dict[str, Any],
    scope: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None
) -> MCPMessage:
    """Factory for task assignment messages."""
    msg = MCPMessage(
        correlation_id=correlation_id or str(uuid.uuid4()),
        envelope=MCPMessage.Envelope(
            from_addr=MCPMessage.Envelope.Address(
                agent_id=from_agent,
                agent_type=from_type,
                routing_key=f"mcp.agent.{from_agent}"
            ),
            to_addr=MCPMessage.Envelope.Address(
                agent_id=to_agent,
                agent_type=to_type,
                routing_key=f"mcp.agent.{to_agent}"
            )
        ),
        payload=MCPMessage.Payload(
            message_type=MessageType.TASK_ASSIGNMENT,
            task=MCPMessage.Payload.Task(
                task_type=task_type,
                priority=priority,
                parameters=parameters,
                scope=scope
            )
        )
    )
    msg.payload.authorization = MCPMessage.Payload.Authorization(
        required=priority in [Priority.CRITICAL, Priority.HIGH],
        auth_type="hitl" if priority == Priority.CRITICAL else "auto"
    )
    msg.security.integrity_hash = compute_integrity_hash(msg.payload.model_dump())
    return msg
