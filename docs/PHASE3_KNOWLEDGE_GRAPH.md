# Phase 3 — Asset Intelligence, Knowledge Graph & AI Correlation

Phase 3 turns the operational state produced by Discovery, Vulnerability, Threat Intel, Incident Response and SOAR into an explainable cybersecurity graph.

## Objectives

- unify asset, service, CPE, CVE, ATT&CK, IOC, actor, campaign, incident, control and remediation context;
- build evidence-backed relationships rather than isolated alerts;
- surface high-confidence risk correlations such as CISA KEV on internet-exposed assets;
- materialize defensive attack paths without executing offensive actions;
- show control-coverage gaps for mapped ATT&CK techniques;
- keep the correlation layer deterministic, auditable and safe by default.

## New Correlation Agent

`correlation_agent` is the 15th worker agent. It reads the orchestrator Redis projection (DB 0), rebuilds the graph periodically and publishes:

- `mcp:kg:nodes`
- `mcp:kg:edges`
- `mcp:correlations`
- `mcp:attack-paths`
- `mcp:kg:summary`

The graph is read-only. It does not exploit assets, isolate hosts, modify firewall rules or run remediation automatically.

## Knowledge model

Node types currently supported:

`asset`, `service`, `cpe`, `vulnerability`, `technique`, `ioc`, `threat_actor`, `campaign`, `incident`, `control`, `remediation`.

Core relations include:

`exposes`, `identified_as`, `affected_by`, `vulnerable_to`, `maps_to`, `mitigated_by`, `remediated_by`, `has_remediation`, `associated_with`, `indicates`, `attributed_to`, `uses`, `involves`, `observed_ioc`.

## Explainable correlation rules

Phase 3 introduces deterministic hypotheses with evidence and confidence scores:

1. known exploited vulnerability + internet exposure;
2. CISA KEV + already-high contextual risk;
3. high EPSS + high asset criticality;
4. multiple findings converging on one ATT&CK technique for the same asset.

These hypotheses are defensive prioritization signals. They do not authorize intrusive action. Existing HITL/change-control safeguards remain authoritative.

## API

New read-only endpoints:

- `GET /api/knowledge-graph`
- `GET /api/correlations`
- `GET /api/attack-paths`
- `GET /api/knowledge-graph/summary`

## Dashboard

A new **Intelligence Graph** view provides:

- graph metrics;
- top risk correlations;
- defensive attack paths;
- entity explorer by node type;
- visibility into ATT&CK control coverage.

## Validation

The unit suite includes graph construction, correlation detection, attack-path explainability and ATT&CK control-coverage regression tests.
