"""Tests for Discovery Agent."""
import pytest
from unittest.mock import Mock, patch, AsyncMock
import asyncio

class TestDiscoveryAgent:
    @pytest.fixture
    def discovery_agent(self, mock_redis):
        with patch('mcp.core.client.Producer'), patch('mcp.core.client.Consumer'):
            from agents.discovery.main import DiscoveryAgent
            agent = DiscoveryAgent()
            agent.client._redis = mock_redis
            return agent

    def test_scope_validation_authorized(self, discovery_agent):
        assert discovery_agent._is_authorized("10.0.1.50") == True
        assert discovery_agent._is_authorized("192.168.1.100") == True

    def test_scope_validation_unauthorized(self, discovery_agent):
        assert discovery_agent._is_authorized("8.8.8.8") == False
        assert discovery_agent._is_authorized("1.1.1.1") == False

    def test_scope_validation_exclusions_win(self, discovery_agent):
        assert discovery_agent._is_authorized("10.0.1.1") is False
        assert discovery_agent._is_authorized("192.168.1.1") is False

    def test_scope_validation_rejects_supernet(self, discovery_agent):
        assert discovery_agent._is_authorized("0.0.0.0/0") is False
        assert discovery_agent._is_authorized("10.0.0.0/7") is False

    def test_scope_validation_rejects_network_containing_exclusion(self, discovery_agent):
        assert discovery_agent._is_authorized("10.0.1.0/24") is False

    def test_parse_nmap_xml(self, discovery_agent):
        xml_data = """<?xml version="1.0"?>
        <nmaprun>
            <host><status state="up"/><address addr="10.0.1.1"/><ports>
                <port portid="80" protocol="tcp"><state state="open"/><service name="http"/></port>
            </ports></host>
        </nmaprun>"""
        hosts = discovery_agent._parse_nmap_xml(xml_data)
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "10.0.1.1"
        assert hosts[0]["ports"][0]["port"] == 80

    @pytest.mark.asyncio
    async def test_execute_network_scan_unauthorized(self, discovery_agent, sample_mcp_message):
        sample_mcp_message.payload.task.scope = {"targets": ["8.8.8.8"]}
        await discovery_agent._execute_network_scan(sample_mcp_message)
        # Should block and not call nmap


def test_parse_nmap_xml_extracts_product_cpe_and_risk(mock_redis):
    with patch('mcp.core.client.Producer'), patch('mcp.core.client.Consumer'):
        from agents.discovery.main import DiscoveryAgent
        discovery_agent = DiscoveryAgent()
        discovery_agent.client._redis = mock_redis
    discovery_agent.asset_risk_default = {"criticality": 4, "internet_exposed": None}
    discovery_agent.asset_risk_profiles = [
        {"network": "10.0.1.0/24", "criticality": 9, "environment": "production"}
    ]
    xml_data = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="10.0.1.50"/>
        <ports>
          <port portid="443" protocol="tcp">
            <state state="open"/>
            <service name="https" product="nginx" version="1.24.0">
              <cpe>cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*</cpe>
            </service>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    hosts = discovery_agent._parse_nmap_xml(xml_data)
    service = hosts[0]["ports"][0]
    assert service["product"] == "nginx"
    assert service["cpes"][0].startswith("cpe:2.3:a:nginx")
    assert hosts[0]["risk_context"]["criticality"] == 9
    assert hosts[0]["risk_context"]["environment"] == "production"
