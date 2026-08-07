"""Tests for MCP Protocol core."""
import pytest
from mcp.core import MCPMessage, MessageType, AgentType, Priority, compute_integrity_hash

class TestMCPMessage:
    def test_message_creation(self, sample_mcp_message):
        assert sample_mcp_message.mcp_version == "1.0"
        assert sample_mcp_message.envelope.from_addr.agent_id == "test_agent"
        assert sample_mcp_message.payload.message_type == MessageType.TASK_ASSIGNMENT

    def test_task_assignment(self, sample_mcp_message):
        task = sample_mcp_message.payload.task
        assert task.task_type == "network_scan"
        assert task.priority == Priority.MEDIUM
        assert task.parameters["scan_type"] == "quick"

    def test_integrity_hash(self, sample_mcp_message):
        hash1 = compute_integrity_hash(sample_mcp_message.payload.model_dump())
        hash2 = compute_integrity_hash(sample_mcp_message.payload.model_dump())
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex length

    def test_message_serialization(self, sample_mcp_message):
        json_str = sample_mcp_message.model_dump_json(by_alias=True)
        assert "mcp_version" in json_str
        assert "message_id" in json_str
        parsed = MCPMessage.model_validate_json(json_str)
        assert parsed.message_id == sample_mcp_message.message_id

    def test_priority_ordering(self):
        assert Priority.CRITICAL < Priority.HIGH
        assert Priority.HIGH < Priority.MEDIUM
        assert Priority.MEDIUM < Priority.LOW
        assert Priority.LOW < Priority.INFO

class TestMessageTypes:
    def test_all_message_types_exist(self):
        types = [t.value for t in MessageType]
        expected = [
            "task_assignment", "task_result", "event_notification",
            "query_request", "query_response", "alert", "heartbeat",
            "authorization_request", "authorization_response"
        ]
        for exp in expected:
            assert exp in types

class TestAgentTypes:
    def test_agent_types(self):
        assert AgentType.ORCHESTRATOR.value == "orchestrator"
        assert AgentType.WORKER.value == "worker"
        assert AgentType.GOVERNANCE.value == "governance"
