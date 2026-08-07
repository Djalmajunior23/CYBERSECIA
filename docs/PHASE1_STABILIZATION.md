# Phase 1 — Stabilization Baseline

This document records the verified state of the uploaded CyberSec AI Ecosystem after the first stabilization pass.

## What was fixed

- Migrated the MCP schema to Pydantic v2-compatible field definitions and serialization APIs.
- Fixed MCP envelope aliases (`from` / `to`) so messages can be created using the code's `from_addr` / `to_addr` names.
- Fixed MCP `Security` and `Audit` default factories that raised `NameError` at runtime.
- Exported `compute_integrity_hash` from `mcp.core` as expected by the test suite.
- Fixed a missing `os` import in MCP payload encryption support.
- Added hash-chained, tamper-evident Redis audit events.
- Fixed Discovery scope validation so a requested supernet cannot escape the authorized range.
- Enforced configured scan exclusions and added fail-closed local/development scope loading.
- Added regression tests for supernet/exclusion handling.
- Fixed the central orchestrator's TASK_RESULT handler, which previously dereferenced a task object that is absent from result messages.
- Added Redis-backed agent heartbeat, alert, task-result, task-failure and incident state for dashboard/API consumption.
- Added real HITL gating in the orchestrator: selected critical tasks are queued before dispatch and released only after approval.
- Added an API Gateway with health, stats, agents, incidents, HITL queue, HITL decisions and WebSocket telemetry.
- Protected HITL mutation with an explicit `API_ADMIN_TOKEN`; mutation is disabled when no token is configured.
- Replaced dashboard mock data with API/WebSocket-backed views.
- Fixed dashboard container build logic for the archive, which did not contain a `package-lock.json`.
- Added missing Docker build/runtime files and removed mounts/packages that would break or mask container content.
- Reworked `make init`, health checks and operational Make targets around Docker Compose v2.
- Added an orchestrator dispatch CLI so Make targets no longer point to missing scripts.
- Added `.dockerignore` and `.gitignore` rules to reduce accidental secret/private-key leakage.

## Verified locally

- Python source compilation succeeds.
- Docker Compose YAML parses with 22 services and all referenced local Dockerfiles/volume paths exist.
- 34 Python tests pass with warnings treated as errors.
- Redis and Kafka were represented by temporary test stubs because those packages/services are not available in the analysis runtime; production code still targets the real libraries in Docker.

## Functional vs. simulated/partial

### Functional foundation

- MCP message schema and serialization.
- Kafka/Redis client abstraction and circuit breaker.
- Authorized network scope validation.
- Nmap command orchestration in Discovery Agent.
- NVD HTTP integration in Vulnerability Agent.
- Central task routing and capability registry.
- HITL pre-dispatch gating for critical task types.
- Redis-backed operational state for API/dashboard.
- API Gateway read endpoints and WebSocket telemetry.
- Dashboard views for agents, HITL and incidents.
- SOAR playbook loading/routing structure.

### Partial or simulated and not yet production-grade

- Kafka transport is PLAINTEXT in the current Compose file; generated PKI is not yet wired into broker/client TLS.
- MCP messages are signed, but sender public-key identity verification is not yet connected to a trusted registry.
- AES-GCM helper code exists but normal MCP payloads are not encrypted at message level.
- Audit hash chaining is tamper-evident but Redis is not immutable/WORM storage.
- RBAC/ABAC files exist but API authentication/authorization is not yet a full user/role system.
- Threat Hunt currently uses simulated telemetry findings.
- Red Team and Purple Team results are mostly simulated scaffolding.
- Forensic evidence acquisition/artifact analysis is currently simulated metadata, not real acquisition tooling.
- Vulnerability enrichment still has TODOs for CISA KEV and EPSS.
- MCP shadow-server discovery is still a placeholder.
- Heartbeat metrics currently report placeholder CPU/memory/queue values.
- `wait_for_ack` in the MCP client is not implemented.

## Recommended Phase 2

1. **Security plane** — Kafka TLS/mTLS, certificate identity mapping, trusted signing-key registry, API login/JWT, RBAC/ABAC enforcement and secret management.
2. **Scanner pipeline** — Discovery → fingerprint normalization → CVE/CPE matching → EPSS → CISA KEV → asset criticality → risk score → remediation queue.
3. **Evidence and data plane** — persist incidents/assets/vulnerabilities to PostgreSQL and telemetry to ClickHouse instead of relying primarily on Redis state.
4. **Real observability** — Prometheus/OpenTelemetry metrics, health/readiness endpoints for every agent and Grafana dashboards.
5. **AI security gateway** — provider abstraction, model policy, prompt/data redaction, structured outputs, model fallback, budget/rate limits and auditability.
6. **Detection engineering** — real SIEM connectors, Sigma rules, ATT&CK coverage model, validation feedback loop and Purple Team evidence.
7. **OT/ICS safety layer** — dedicated OT scopes, protocol-aware passive discovery, stricter HITL, digital-twin validation and no active scanning by default on critical industrial assets.
