"""Pytest configuration and shared fixtures."""
import pytest
import asyncio
from unittest.mock import Mock, MagicMock
from mcp.core import MCPClientConfig, MCPMessage, MessageType, AgentType, Priority

@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test case."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def mock_kafka_producer():
    """Mock Kafka producer for testing."""
    producer = Mock()
    producer.produce = Mock(return_value=None)
    producer.poll = Mock(return_value=None)
    producer.flush = Mock(return_value=None)
    return producer

@pytest.fixture
def mock_kafka_consumer():
    """Mock Kafka consumer for testing."""
    consumer = Mock()
    consumer.subscribe = Mock(return_value=None)
    consumer.poll = Mock(return_value=None)
    consumer.close = Mock(return_value=None)
    return consumer

@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    redis = Mock()
    redis.get = Mock(return_value=None)
    redis.set = Mock(return_value=True)
    redis.setex = Mock(return_value=True)
    redis.hset = Mock(return_value=True)
    redis.hgetall = Mock(return_value={})
    redis.zadd = Mock(return_value=True)
    redis.hlen = Mock(return_value=0)
    redis.xlen = Mock(return_value=0)
    redis.llen = Mock(return_value=0)
    redis.lpush = Mock(return_value=True)
    redis.xadd = Mock(return_value=True)
    redis.xrange = Mock(return_value=[])
    redis.sadd = Mock(return_value=True)
    redis.delete = Mock(return_value=True)
    return redis

@pytest.fixture
def sample_mcp_message():
    """Sample MCP message for testing."""
    return MCPMessage(
        envelope=MCPMessage.Envelope(
            from_addr=MCPMessage.Envelope.Address(
                agent_id="test_agent",
                agent_type=AgentType.WORKER,
                routing_key="mcp.agent.test_agent"
            ),
            to_addr=MCPMessage.Envelope.Address(
                agent_id="central_orchestrator",
                agent_type=AgentType.ORCHESTRATOR,
                routing_key="mcp.agent.central_orchestrator"
            )
        ),
        payload=MCPMessage.Payload(
            message_type=MessageType.TASK_ASSIGNMENT,
            task=MCPMessage.Payload.Task(
                task_type="network_scan",
                priority=Priority.MEDIUM,
                parameters={"scan_type": "quick"},
                scope={"targets": ["192.168.1.0/24"]}
            )
        )
    )

@pytest.fixture
def sample_task_result():
    """Sample task result for testing."""
    return MCPMessage.Payload.Result(
        status="success",
        data={"hosts": [{"ip": "192.168.1.1", "status": "up"}]},
        errors=[]
    )
