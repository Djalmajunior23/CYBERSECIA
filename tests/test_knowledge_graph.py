from agents.correlation.engine import KnowledgeGraphEngine


def sample_state():
    return {
        "assets": [{
            "ip": "10.0.0.10",
            "status": "up",
            "risk_context": {"criticality": 9.0, "internet_exposed": True, "environment": "dmz"},
            "ports": [{
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "service": "https",
                "product": "Example Web Server",
                "version": "1.0",
                "cpes": ["cpe:2.3:a:example:web_server:1.0:*:*:*:*:*:*:*"]
            }]
        }],
        "vulnerabilities": [{
            "finding_id": "finding-1",
            "host": "10.0.0.10",
            "port": 443,
            "protocol": "tcp",
            "cve_id": "CVE-2026-0001",
            "priority_score": 9.6,
            "severity": "critical",
            "cisa_kev": True,
            "epss": {"score": 0.91},
            "cvss_v4": {"base_score": 9.8},
            "risk": {"confidence": 0.92},
            "mitre_technique": "T1190",
            "cpes": ["cpe:2.3:a:example:web_server:1.0:*:*:*:*:*:*:*"]
        }],
        "remediations": [{
            "ticket_id": "REM-finding-1",
            "finding_id": "finding-1",
            "host": "10.0.0.10",
            "cve_id": "CVE-2026-0001",
            "priority": "P1",
            "risk_score": 9.6,
            "status": "open"
        }],
        "incidents": [], "iocs": [], "techniques": [], "campaigns": []
    }


def test_builds_asset_service_cpe_vulnerability_technique_control_and_remediation():
    graph = KnowledgeGraphEngine().build(sample_state())
    node_types = {node["type"] for node in graph["nodes"]}
    assert {"asset", "service", "cpe", "vulnerability", "technique", "control", "remediation"}.issubset(node_types)
    relations = {edge["relation"] for edge in graph["edges"]}
    assert {"exposes", "identified_as", "vulnerable_to", "affected_by", "maps_to", "mitigated_by", "remediated_by"}.issubset(relations)


def test_correlates_known_exploited_internet_exposure():
    graph = KnowledgeGraphEngine().build(sample_state())
    matches = [item for item in graph["correlations"] if item["type"] == "known_exploited_internet_exposure"]
    assert len(matches) == 1
    assert matches[0]["severity"] == "critical"
    assert matches[0]["confidence"] >= 0.9


def test_attack_path_is_explainable_and_control_aware():
    graph = KnowledgeGraphEngine().build(sample_state())
    path = graph["attack_paths"][0]
    assert path["asset"] == "10.0.0.10"
    assert path["cve_id"] == "CVE-2026-0001"
    assert path["technique_id"] == "T1190"
    assert path["control_coverage"] is True
    assert len(path["node_ids"]) >= 3


def test_technique_convergence_detects_multiple_findings():
    state = sample_state()
    second = dict(state["vulnerabilities"][0])
    second.update({"finding_id": "finding-2", "cve_id": "CVE-2026-0002", "cisa_kev": False, "priority_score": 8.2})
    state["vulnerabilities"].append(second)
    graph = KnowledgeGraphEngine().build(state)
    assert any(item["type"] == "technique_convergence" for item in graph["correlations"])
