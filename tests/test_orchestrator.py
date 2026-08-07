"""Tests for Central Orchestrator."""
import pytest
from unittest.mock import Mock, patch
from mcp.core import Priority

class TestCentralOrchestrator:
    @pytest.fixture
    def orchestrator(self, mock_redis):
        with patch('mcp.core.client.Producer'), patch('mcp.core.client.Consumer'):
            from agents.central_orchestrator.main import CentralOrchestrator
            orch = CentralOrchestrator()
            orch.client._redis = mock_redis
            return orch

    def test_registry_initialized(self, orchestrator):
        assert len(orchestrator.registry) == 15
        assert "discovery_agent" in orchestrator.registry
        assert "red_team_agent" in orchestrator.registry
        assert "correlation_agent" in orchestrator.registry

    def test_agent_capabilities(self, orchestrator):
        disc = orchestrator.registry["discovery_agent"]
        assert "network_scan" in disc.capabilities
        assert "host_discovery" in disc.capabilities

    def test_hitl_required_tasks(self, orchestrator):
        assert "contain_critical_infrastructure" in orchestrator.HITL_REQUIRED_TASKS
        assert "forensic_evidence_acquisition" in orchestrator.HITL_REQUIRED_TASKS

    def test_dispatch_unknown_agent(self, orchestrator):
        result = orchestrator.dispatch_task("unknown_agent", "test", {})
        assert result is None

    def test_dispatch_intelligent(self, orchestrator):
        result = orchestrator.dispatch_intelligent(
            ["network_scan"], "scan", {}, Priority.MEDIUM
        )
        # Should return message_id or None depending on mock

    def test_critical_task_is_held_for_hitl(self, orchestrator):
        orchestrator.client.send_task = Mock(return_value="should-not-send")
        result = orchestrator.dispatch_task(
            "response_orchestrator",
            "contain_critical_infrastructure",
            {"target": "asset-01"},
            Priority.CRITICAL,
        )
        assert result.startswith("HITL-")
        orchestrator.client.send_task.assert_not_called()
        orchestrator.client._redis.lpush.assert_called_once()

    def test_hitl_approved_task_can_be_released(self, orchestrator):
        orchestrator.client.send_task = Mock(return_value="message-123")
        result = orchestrator.dispatch_task(
            "response_orchestrator",
            "contain_critical_infrastructure",
            {"target": "asset-01"},
            Priority.CRITICAL,
            hitl_approved=True,
        )
        assert result == "message-123"
        orchestrator.client.send_task.assert_called_once()


def test_projects_vulnerability_findings_to_central_state(mock_redis):
    with patch('mcp.core.client.Producer'), patch('mcp.core.client.Consumer'):
        from agents.central_orchestrator.main import CentralOrchestrator
        orchestrator = CentralOrchestrator()
        orchestrator.client._redis = mock_redis
    finding = {
        "finding_id": "finding-1",
        "host": "10.0.1.50",
        "cve_id": "CVE-2026-0001",
        "priority_score": 9.2,
        "severity": "critical",
    }
    orchestrator._project_operational_state(
        "vulnerability_agent",
        {"findings": [finding], "summary": {"critical": 1, "total": 1}},
        "2026-08-07T12:00:00+00:00",
    )
    calls = orchestrator.client._redis.hset.call_args_list
    assert any(call.args[:2] == ("mcp:vulnerabilities", "finding-1") for call in calls)
    orchestrator.client._redis.set.assert_called()


def test_projects_discovered_assets_to_central_state(mock_redis):
    with patch('mcp.core.client.Producer'), patch('mcp.core.client.Consumer'):
        from agents.central_orchestrator.main import CentralOrchestrator
        orchestrator = CentralOrchestrator()
        orchestrator.client._redis = mock_redis
    orchestrator._project_operational_state(
        "discovery_agent",
        {"hosts": [{"ip": "10.0.1.50", "ports": []}]},
        "2026-08-07T12:00:00+00:00",
    )
    args = orchestrator.client._redis.hset.call_args.args
    assert args[0] == "mcp:assets"
    assert args[1] == "10.0.1.50"
    assert 'last_observed_at' in args[2]


def test_projects_threat_intel_to_central_state(mock_redis):
    with patch('mcp.core.client.Producer'), patch('mcp.core.client.Consumer'):
        from agents.central_orchestrator.main import CentralOrchestrator
        orchestrator = CentralOrchestrator()
        orchestrator.client._redis = mock_redis
    orchestrator._project_operational_state(
        "threat_intel_agent",
        {
            "enriched_iocs": [{"ioc": {"type": "domain", "value": "example.invalid"}, "intel": {"malicious": True}}],
            "ttp_mapping": [{"technique_id": "T1190", "data": {"name": "Exploit Public-Facing Application"}}],
        },
        "2026-08-07T12:00:00+00:00",
    )
    calls = orchestrator.client._redis.hset.call_args_list
    assert any(call.args[0] == "mcp:intel:iocs" for call in calls)
    assert any(call.args[:2] == ("mcp:intel:techniques", "T1190") for call in calls)
