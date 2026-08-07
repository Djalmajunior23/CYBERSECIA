"""Explainable cybersecurity knowledge graph and correlation engine.

The engine is intentionally deterministic and read-only. It combines asset,
vulnerability, threat-intelligence, incident and remediation state into a
graph that can be inspected, tested and optionally summarized by an LLM at a
higher layer. No exploit execution or containment action is performed here.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


class KnowledgeGraphEngine:
    """Build an explainable graph and generate evidence-backed hypotheses."""

    def __init__(self, controls_path: Optional[str] = None):
        self.controls = self._load_controls(controls_path)
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _load_controls(controls_path: Optional[str]) -> Dict[str, List[Dict[str, str]]]:
        candidates = []
        if controls_path:
            candidates.append(Path(controls_path))
        candidates.append(
            Path(__file__).resolve().parents[2] / "config" / "knowledge_graph" / "defensive_controls.json"
        )
        for path in candidates:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return data.get("techniques", {})
            except (FileNotFoundError, OSError, json.JSONDecodeError):
                continue
        return {}

    @staticmethod
    def _node_id(node_type: str, key: str) -> str:
        digest = hashlib.sha256(f"{node_type}:{key}".encode()).hexdigest()[:20]
        return f"{node_type}:{digest}"

    @staticmethod
    def _edge_id(source: str, relation: str, target: str) -> str:
        return hashlib.sha256(f"{source}|{relation}|{target}".encode()).hexdigest()[:24]

    def _add_node(
        self,
        node_type: str,
        key: str,
        label: str,
        attributes: Optional[Dict[str, Any]] = None,
        risk_score: float = 0.0,
    ) -> str:
        node_id = self._node_id(node_type, key)
        candidate = {
            "id": node_id,
            "type": node_type,
            "key": key,
            "label": label,
            "attributes": attributes or {},
            "risk_score": round(float(risk_score or 0.0), 2),
        }
        existing = self._nodes.get(node_id)
        if existing:
            merged = {**existing.get("attributes", {}), **candidate["attributes"]}
            existing["attributes"] = merged
            existing["risk_score"] = max(existing.get("risk_score", 0.0), candidate["risk_score"])
            if label and label != key:
                existing["label"] = label
        else:
            self._nodes[node_id] = candidate
        return node_id

    def _add_edge(
        self,
        source: str,
        relation: str,
        target: str,
        confidence: float = 1.0,
        evidence: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> str:
        edge_id = self._edge_id(source, relation, target)
        edge = {
            "id": edge_id,
            "source": source,
            "target": target,
            "relation": relation,
            "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
            "evidence": sorted(set(evidence or [])),
            "attributes": attributes or {},
        }
        existing = self._edges.get(edge_id)
        if existing:
            existing["confidence"] = max(existing.get("confidence", 0.0), edge["confidence"])
            existing["evidence"] = sorted(set(existing.get("evidence", []) + edge["evidence"]))
            existing["attributes"] = {**existing.get("attributes", {}), **edge["attributes"]}
        else:
            self._edges[edge_id] = edge
        return edge_id

    @staticmethod
    def _asset_exposure(asset: Dict[str, Any]) -> str:
        context = asset.get("risk_context") or {}
        if context.get("internet_exposed") is True:
            return "internet"
        environment = str(context.get("environment") or asset.get("environment") or "").lower()
        if environment in {"dmz", "internet", "edge", "external"}:
            return "internet"
        if context.get("internet_exposed") is False:
            return "internal"
        return "unknown"

    @staticmethod
    def _finding_score(finding: Dict[str, Any]) -> float:
        return float(finding.get("priority_score", (finding.get("risk") or {}).get("score", 0.0)) or 0.0)

    def build(self, state: Dict[str, Any]) -> Dict[str, Any]:
        self._nodes = {}
        self._edges = {}

        assets = state.get("assets") or []
        vulnerabilities = state.get("vulnerabilities") or []
        remediations = state.get("remediations") or []
        incidents = state.get("incidents") or []
        iocs = state.get("iocs") or []
        techniques = state.get("techniques") or []
        campaigns = state.get("campaigns") or []

        asset_index: Dict[str, str] = {}
        service_index: Dict[Tuple[str, str, int], str] = {}
        vuln_index: Dict[str, str] = {}
        technique_index: Dict[str, str] = {}
        ioc_index: Dict[Tuple[str, str], str] = {}

        for asset in assets:
            ip = str(asset.get("ip") or asset.get("asset_id") or "").strip()
            if not ip:
                continue
            risk_context = asset.get("risk_context") or {}
            asset_id = self._add_node(
                "asset",
                ip,
                ip,
                {
                    "status": asset.get("status"),
                    "os": asset.get("os") or {},
                    "risk_context": risk_context,
                    "exposure": self._asset_exposure(asset),
                    "last_observed_at": asset.get("last_observed_at") or asset.get("last_seen"),
                },
                risk_score=float(risk_context.get("criticality", 0.0) or 0.0),
            )
            asset_index[ip] = asset_id

            for port in asset.get("ports") or []:
                try:
                    port_number = int(port.get("port") or 0)
                except (TypeError, ValueError):
                    port_number = 0
                protocol = str(port.get("protocol") or "tcp")
                service_key = (ip, protocol, port_number)
                product = str(port.get("product") or port.get("service") or "unknown")
                version = str(port.get("version") or "").strip()
                service_label = f"{product} {version}".strip() + f" ({port_number}/{protocol})"
                service_id = self._add_node(
                    "service",
                    f"{ip}:{protocol}:{port_number}",
                    service_label,
                    {
                        "host": ip,
                        "port": port_number,
                        "protocol": protocol,
                        "service": port.get("service"),
                        "product": port.get("product"),
                        "version": version,
                        "state": port.get("state"),
                    },
                )
                service_index[service_key] = service_id
                self._add_edge(asset_id, "exposes", service_id, evidence=["asset_inventory"])

                for cpe in sorted(set(port.get("cpes") or [])):
                    cpe_id = self._add_node("cpe", cpe, cpe, {"cpe": cpe})
                    self._add_edge(service_id, "identified_as", cpe_id, confidence=0.95, evidence=["service_fingerprint"])

        for item in techniques:
            tid = str(item.get("technique_id") or item.get("id") or "").upper()
            if not tid:
                continue
            data = item.get("data") or item
            technique_index[tid] = self._add_node(
                "technique",
                tid,
                f"{tid} — {data.get('name') or 'MITRE ATT&CK technique'}",
                {
                    "name": data.get("name"),
                    "tactics": data.get("tactics") or [],
                    "platforms": data.get("platforms") or [],
                },
            )

        findings_by_asset: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for finding in vulnerabilities:
            host = str(finding.get("host") or "")
            cve_id = str(finding.get("cve_id") or "").upper()
            if not cve_id:
                continue
            score = self._finding_score(finding)
            vuln_id = vuln_index.get(cve_id) or self._add_node(
                "vulnerability",
                cve_id,
                cve_id,
                {
                    "description": finding.get("description") or "",
                    "cvss": (finding.get("cvss_v4") or {}).get("base_score", 0.0),
                    "epss": (finding.get("epss") or {}).get("score", 0.0),
                    "cisa_kev": bool(finding.get("cisa_kev")),
                    "cisa_due_date": finding.get("cisa_due_date"),
                    "severity": finding.get("severity"),
                },
                risk_score=score,
            )
            vuln_index[cve_id] = vuln_id

            asset_id = asset_index.get(host)
            if asset_id:
                findings_by_asset[host].append(finding)
                confidence = float((finding.get("risk") or {}).get("confidence", 0.7) or 0.7)
                self._add_edge(
                    asset_id,
                    "affected_by",
                    vuln_id,
                    confidence=confidence,
                    evidence=[finding.get("finding_id") or cve_id],
                    attributes={"finding_id": finding.get("finding_id"), "risk_score": score},
                )
                protocol = str(finding.get("protocol") or "tcp")
                try:
                    port_number = int(finding.get("port") or 0)
                except (TypeError, ValueError):
                    port_number = 0
                service_id = service_index.get((host, protocol, port_number))
                if service_id:
                    self._add_edge(
                        service_id,
                        "vulnerable_to",
                        vuln_id,
                        confidence=confidence,
                        evidence=[finding.get("finding_id") or cve_id],
                    )

            for cpe in finding.get("cpes") or []:
                cpe_node = self._add_node("cpe", cpe, cpe, {"cpe": cpe})
                self._add_edge(cpe_node, "affected_by", vuln_id, confidence=0.9, evidence=["vulnerability_correlation"])

            technique_id = str(finding.get("mitre_technique") or "").upper()
            if technique_id:
                technique_node = technique_index.get(technique_id)
                if not technique_node:
                    technique_node = self._add_node(
                        "technique",
                        technique_id,
                        technique_id,
                        {"name": None, "tactics": []},
                    )
                    technique_index[technique_id] = technique_node
                self._add_edge(vuln_id, "maps_to", technique_node, confidence=0.65, evidence=["finding_mapping"])

        for technique_id, technique_node in technique_index.items():
            for control in self.controls.get(technique_id, []):
                control_key = str(control.get("id") or control.get("name") or "control")
                control_node = self._add_node(
                    "control",
                    control_key,
                    control.get("name") or control_key,
                    {"framework": control.get("framework"), "status": control.get("status", "recommended")},
                )
                self._add_edge(technique_node, "mitigated_by", control_node, confidence=0.9, evidence=["defensive_control_catalog"])

        remediation_by_finding: Dict[str, List[str]] = defaultdict(list)
        for ticket in remediations:
            ticket_id = str(ticket.get("ticket_id") or "")
            if not ticket_id:
                continue
            remediation_node = self._add_node(
                "remediation",
                ticket_id,
                ticket_id,
                {
                    "priority": ticket.get("priority"),
                    "status": ticket.get("status"),
                    "recommended_action": ticket.get("recommended_action"),
                    "recommended_sla_hours": ticket.get("recommended_sla_hours"),
                },
                risk_score=float(ticket.get("risk_score", 0.0) or 0.0),
            )
            finding_id = str(ticket.get("finding_id") or "")
            if finding_id:
                remediation_by_finding[finding_id].append(remediation_node)
            cve_id = str(ticket.get("cve_id") or "").upper()
            if cve_id and cve_id in vuln_index:
                self._add_edge(vuln_index[cve_id], "remediated_by", remediation_node, evidence=["soar_remediation"])
            host = str(ticket.get("host") or "")
            if host in asset_index:
                self._add_edge(asset_index[host], "has_remediation", remediation_node, evidence=["soar_remediation"])

        for enriched in iocs:
            ioc = enriched.get("ioc") or enriched
            intel = enriched.get("intel") or {}
            ioc_type = str(ioc.get("type") or "unknown")
            value = str(ioc.get("value") or "").strip()
            if not value:
                continue
            ioc_node = self._add_node(
                "ioc",
                f"{ioc_type}:{value}",
                value,
                {
                    "ioc_type": ioc_type,
                    "malicious": bool(intel.get("malicious")),
                    "confidence": intel.get("confidence", 0),
                    "tags": intel.get("tags") or [],
                    "sources": intel.get("sources") or [],
                },
                risk_score=float(intel.get("confidence", 0) or 0) / 10.0,
            )
            ioc_index[(ioc_type, value)] = ioc_node
            for actor in intel.get("associated_actors") or []:
                actor_name = str(actor).strip()
                if not actor_name:
                    continue
                actor_node = self._add_node("threat_actor", actor_name, actor_name, {})
                self._add_edge(ioc_node, "associated_with", actor_node, confidence=0.6, evidence=["threat_intel"])
            mitre = intel.get("mitre_mapping") or {}
            for tid in mitre.get("techniques") or []:
                tid = str(tid).upper()
                technique_node = technique_index.get(tid) or self._add_node("technique", tid, tid, {})
                technique_index[tid] = technique_node
                self._add_edge(ioc_node, "indicates", technique_node, confidence=0.6, evidence=["threat_intel"])

        for campaign in campaigns:
            name = str(campaign.get("campaign") or campaign.get("name") or "").strip()
            if not name:
                continue
            campaign_node = self._add_node("campaign", name, name, {"status": campaign.get("status")})
            for actor in campaign.get("actors") or []:
                actor_node = self._add_node("threat_actor", str(actor), str(actor), {})
                self._add_edge(campaign_node, "attributed_to", actor_node, confidence=0.55, evidence=["campaign_tracking"])
            for tid in campaign.get("techniques") or []:
                tid = str(tid).upper()
                technique_node = technique_index.get(tid) or self._add_node("technique", tid, tid, {})
                technique_index[tid] = technique_node
                self._add_edge(campaign_node, "uses", technique_node, confidence=0.65, evidence=["campaign_tracking"])

        for incident in incidents:
            incident_id_value = str(incident.get("incident_id") or "")
            if not incident_id_value:
                continue
            incident_node = self._add_node(
                "incident",
                incident_id_value,
                incident_id_value,
                {"severity": incident.get("severity"), "status": incident.get("status"), "title": incident.get("title")},
            )
            source = str((incident.get("alert") or {}).get("source") or incident.get("source") or "")
            if source in asset_index:
                self._add_edge(incident_node, "involves", asset_index[source], confidence=0.9, evidence=[incident_id_value])
            alert = incident.get("alert") or {}
            for ioc in alert.get("iocs") or []:
                ioc_type = str(ioc.get("type") or "unknown")
                value = str(ioc.get("value") or "").strip()
                if not value:
                    continue
                ioc_node = ioc_index.get((ioc_type, value)) or self._add_node("ioc", f"{ioc_type}:{value}", value, {"ioc_type": ioc_type})
                self._add_edge(incident_node, "observed_ioc", ioc_node, confidence=0.95, evidence=[incident_id_value])

        correlations = self._build_correlations(assets, vulnerabilities, findings_by_asset)
        attack_paths = self._build_attack_paths(vulnerabilities, asset_index, service_index, vuln_index, technique_index)

        type_counts = Counter(node["type"] for node in self._nodes.values())
        relation_counts = Counter(edge["relation"] for edge in self._edges.values())
        coverage_gaps = sorted(
            tid for tid in technique_index if not self.controls.get(tid)
        )
        summary = {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "node_types": dict(sorted(type_counts.items())),
            "relations": dict(sorted(relation_counts.items())),
            "correlations": len(correlations),
            "critical_correlations": sum(1 for item in correlations if item.get("severity") == "critical"),
            "attack_paths": len(attack_paths),
            "coverage_gaps": coverage_gaps,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return {
            "summary": summary,
            "nodes": sorted(self._nodes.values(), key=lambda item: (item["type"], item["label"])),
            "edges": sorted(self._edges.values(), key=lambda item: (item["relation"], item["source"], item["target"])),
            "correlations": correlations,
            "attack_paths": attack_paths,
        }

    def _build_correlations(
        self,
        assets: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        findings_by_asset: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        asset_map = {str(asset.get("ip")): asset for asset in assets if asset.get("ip")}
        correlations: List[Dict[str, Any]] = []

        for finding in vulnerabilities:
            host = str(finding.get("host") or "")
            asset = asset_map.get(host, {})
            exposure = self._asset_exposure(asset) if asset else "unknown"
            risk_context = asset.get("risk_context") or {}
            criticality = float(risk_context.get("criticality", 0.0) or 0.0)
            score = self._finding_score(finding)
            epss = float((finding.get("epss") or {}).get("score", 0.0) or 0.0)
            kev = bool(finding.get("cisa_kev"))
            evidence = [finding.get("finding_id") or finding.get("cve_id") or "finding"]

            if kev and exposure == "internet":
                correlations.append(self._correlation(
                    "known_exploited_internet_exposure",
                    "critical",
                    min(0.99, 0.84 + min(epss, 0.15)),
                    host,
                    finding,
                    ["CISA KEV", "internet-exposed asset", f"risk={score:.1f}"],
                    evidence,
                ))
            elif kev and score >= 8.0:
                correlations.append(self._correlation(
                    "known_exploited_high_risk",
                    "high",
                    0.86,
                    host,
                    finding,
                    ["CISA KEV", f"risk={score:.1f}"],
                    evidence,
                ))

            if epss >= 0.7 and criticality >= 7.0:
                correlations.append(self._correlation(
                    "high_exploit_probability_on_critical_asset",
                    "high" if score < 9.0 else "critical",
                    min(0.97, 0.75 + epss * 0.2),
                    host,
                    finding,
                    [f"EPSS={epss:.3f}", f"asset criticality={criticality:.1f}"],
                    evidence,
                ))

        for host, host_findings in findings_by_asset.items():
            technique_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for finding in host_findings:
                tid = str(finding.get("mitre_technique") or "").upper()
                if tid:
                    technique_groups[tid].append(finding)
            for tid, items in technique_groups.items():
                if len(items) < 2:
                    continue
                max_score = max(self._finding_score(item) for item in items)
                correlations.append({
                    "correlation_id": hashlib.sha256(f"technique_convergence:{host}:{tid}".encode()).hexdigest()[:24],
                    "type": "technique_convergence",
                    "severity": "high" if max_score >= 8.0 else "medium",
                    "confidence": round(min(0.95, 0.6 + len(items) * 0.08), 3),
                    "asset": host,
                    "cve_id": None,
                    "technique_id": tid,
                    "title": f"Multiple weaknesses converge on {tid} for {host}",
                    "rationale": [f"{len(items)} findings map to the same ATT&CK technique", f"max risk={max_score:.1f}"],
                    "evidence": sorted(item.get("finding_id") or item.get("cve_id") for item in items),
                    "recommended_next_step": "Validate control coverage and prioritize remediation for the shared attack technique.",
                })

        deduped = {item["correlation_id"]: item for item in correlations}
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(
            deduped.values(),
            key=lambda item: (severity_order.get(item.get("severity"), 9), -float(item.get("confidence", 0.0))),
        )

    @staticmethod
    def _correlation(
        kind: str,
        severity: str,
        confidence: float,
        host: str,
        finding: Dict[str, Any],
        rationale: List[str],
        evidence: List[str],
    ) -> Dict[str, Any]:
        cve_id = finding.get("cve_id")
        key = f"{kind}:{host}:{cve_id}:{finding.get('port')}"
        return {
            "correlation_id": hashlib.sha256(key.encode()).hexdigest()[:24],
            "type": kind,
            "severity": severity,
            "confidence": round(confidence, 3),
            "asset": host,
            "cve_id": cve_id,
            "technique_id": finding.get("mitre_technique"),
            "title": f"{kind.replace('_', ' ').title()}: {host} / {cve_id}",
            "rationale": rationale,
            "evidence": evidence,
            "recommended_next_step": "Prioritize defensive validation and remediation; keep execution gated by existing change-control/HITL policies.",
        }

    def _build_attack_paths(
        self,
        vulnerabilities: List[Dict[str, Any]],
        asset_index: Dict[str, str],
        service_index: Dict[Tuple[str, str, int], str],
        vuln_index: Dict[str, str],
        technique_index: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        paths = []
        for finding in vulnerabilities:
            host = str(finding.get("host") or "")
            cve_id = str(finding.get("cve_id") or "").upper()
            if host not in asset_index or cve_id not in vuln_index:
                continue
            protocol = str(finding.get("protocol") or "tcp")
            try:
                port_number = int(finding.get("port") or 0)
            except (TypeError, ValueError):
                port_number = 0
            nodes = [asset_index[host]]
            service_node = service_index.get((host, protocol, port_number))
            if service_node:
                nodes.append(service_node)
            nodes.append(vuln_index[cve_id])
            technique_id = str(finding.get("mitre_technique") or "").upper()
            if technique_id and technique_id in technique_index:
                nodes.append(technique_index[technique_id])
            score = self._finding_score(finding)
            control_coverage = bool(technique_id and self.controls.get(technique_id))
            path_key = f"{host}:{protocol}:{port_number}:{cve_id}:{technique_id}"
            paths.append({
                "path_id": hashlib.sha256(path_key.encode()).hexdigest()[:24],
                "asset": host,
                "service": f"{port_number}/{protocol}",
                "cve_id": cve_id,
                "technique_id": technique_id or None,
                "risk_score": round(score, 2),
                "severity": finding.get("severity"),
                "cisa_kev": bool(finding.get("cisa_kev")),
                "epss": float((finding.get("epss") or {}).get("score", 0.0) or 0.0),
                "control_coverage": control_coverage,
                "node_ids": nodes,
                "explanation": "Asset → exposed service → vulnerability → ATT&CK technique" if technique_id else "Asset → exposed service → vulnerability",
            })
        return sorted(paths, key=lambda item: (-item["risk_score"], not item["cisa_kev"], -item["epss"]))
