"""Tests for LLM Client."""
import pytest
from unittest.mock import Mock, patch, AsyncMock
import json
from mcp.llm import LLMClient

class TestLLMClient:
    def test_initialization(self):
        client = LLMClient(provider="google", system_prompt="You are a security analyst.")
        assert client.provider == "google"
        assert client.model == "gemini-1.5-pro"

    def test_unsupported_provider(self):
        with pytest.raises(ValueError):
            LLMClient(provider="invalid")

    @pytest.mark.asyncio
    async def test_fallback_without_api_key(self):
        client = LLMClient(provider="google")
        result = await client.analyze("Test prompt")
        assert result["success"] == True
        assert result["provider"] == "fallback"

    @pytest.mark.asyncio
    async def test_analyze_threat(self):
        client = LLMClient(provider="google")
        result = await client.analyze_threat({"ip": "1.2.3.4", "port": 80})
        assert "structured" in result

    @pytest.mark.asyncio
    async def test_generate_hypothesis(self):
        client = LLMClient(provider="google")
        telemetry = [{"event_type": "auth", "user": "admin"}]
        result = await client.generate_hypothesis(telemetry)
        assert "hypotheses" in result
