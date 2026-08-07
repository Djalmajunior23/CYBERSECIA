"""Tests for Circuit Breaker pattern."""
import pytest
from mcp.core import CircuitBreaker

class TestCircuitBreaker:
    def test_initial_state_closed(self):
        cb = CircuitBreaker()
        assert cb.state == "CLOSED"
        assert cb.can_execute() == True

    def test_record_success(self):
        cb = CircuitBreaker()
        cb.record_success()
        assert cb.failure_count == 0
        assert cb.state == "CLOSED"

    def test_record_failure_opens_circuit(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "CLOSED"  # Not yet
        cb.record_failure()
        assert cb.state == "OPEN"
        assert cb.can_execute() == False

    def test_circuit_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, timeout_seconds=0)
        cb.record_failure()
        assert cb.state == "OPEN"
        import time
        time.sleep(0.1)
        assert cb.can_execute() == True  # Should transition to HALF_OPEN

    def test_success_resets_circuit(self):
        cb = CircuitBreaker(failure_threshold=1)
        cb.record_failure()
        assert cb.state == "OPEN"
        cb.record_success()
        assert cb.state == "CLOSED"
        assert cb.can_execute() == True
