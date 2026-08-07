#!/bin/bash
set -euo pipefail

KAFKA_BROKER="${KAFKA_BROKER:-kafka:29092}"
TOPICS=(
    "mcp.agent.central_orchestrator"
    "mcp.agent.discovery_agent"
    "mcp.agent.vulnerability_agent"
    "mcp.agent.threat_intel_agent"
    "mcp.agent.behavioral_agent"
    "mcp.agent.response_orchestrator"
    "mcp.agent.governance_agent"
    "mcp.agent.red_team_agent"
    "mcp.agent.soar_agent"
    "mcp.agent.purple_team_agent"
    "mcp.agent.mcp_auditor_agent"
    "mcp.agent.digital_twin_agent"
    "mcp.agent.threat_hunt_agent"
    "mcp.agent.compliance_agent"
    "mcp.agent.forensic_agent"
    "mcp.telemetry.raw"
    "mcp.telemetry.enriched"
    "mcp.alerts.critical"
    "mcp.alerts.standard"
    "mcp.human.hitl"
    "mcp.audit.events"
)

if command -v kafka-topics >/dev/null 2>&1; then
    run_topic_cmd() { kafka-topics "$@"; }
elif command -v docker >/dev/null 2>&1 && docker compose ps kafka >/dev/null 2>&1; then
    run_topic_cmd() { docker compose exec -T kafka kafka-topics "$@"; }
else
    echo "[KAFKA] kafka-topics not found and Kafka container is unavailable" >&2
    exit 1
fi

for topic in "${TOPICS[@]}"; do
    echo "[KAFKA] Creating topic: $topic"
    run_topic_cmd --bootstrap-server "$KAFKA_BROKER" --create --if-not-exists --topic "$topic" --partitions 3 --replication-factor 1
done

echo "[KAFKA] All topics created successfully"
