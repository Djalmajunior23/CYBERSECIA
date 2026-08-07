"""Tests for contextual vulnerability prioritization."""
from agents.vulnerability.risk_engine import VulnerabilityRiskEngine


def test_kev_is_prioritized_even_with_moderate_cvss():
    engine = VulnerabilityRiskEngine()
    result = engine.score(
        {
            "cvss_v4": {"base_score": 6.5},
            "epss": {"score": 0.15},
            "cisa_kev": True,
        },
        {"risk_context": {"criticality": 5, "internet_exposed": False}},
    )
    assert result["score"] >= 8.5
    assert result["severity"] == "high"
    assert result["remediation_tier"] == "P2"
    assert "CISA KEV" in " ".join(result["rationale"])


def test_context_changes_operational_priority():
    engine = VulnerabilityRiskEngine()
    cve = {"cvss_v4": {"base_score": 8.0}, "epss": {"score": 0.45}, "cisa_kev": False}
    low_context = engine.score(cve, {"risk_context": {"criticality": 2, "internet_exposed": False}})
    high_context = engine.score(cve, {"risk_context": {"criticality": 10, "internet_exposed": True}})
    assert high_context["score"] > low_context["score"]


def test_critical_risk_has_24_hour_sla():
    engine = VulnerabilityRiskEngine()
    result = engine.score(
        {"cvss_v4": {"base_score": 10.0}, "epss": {"score": 0.99}, "cisa_kev": True},
        {"risk_context": {"criticality": 10, "internet_exposed": True}},
    )
    assert result["severity"] == "critical"
    assert result["recommended_sla_hours"] == 24
    assert 0 <= result["score"] <= 10
