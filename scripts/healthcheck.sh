#!/bin/bash
set -u

echo "[HEALTH] CyberSec AI Ecosystem Health Check"
echo "==========================================="

echo "[HEALTH] Containers:"
docker compose ps || true

check() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "  ✓ $name: OK"
  else
    echo "  ✗ $name: DOWN"
  fi
}

check "Kafka" docker compose exec -T kafka kafka-broker-api-versions --bootstrap-server kafka:29092
check "Redis" docker compose exec -T redis redis-cli ping
check "PostgreSQL" docker compose exec -T postgres pg_isready -U cybersec -d cybersec_ecosystem
check "ClickHouse" curl -fsS http://localhost:8123/ping
check "API Gateway" curl -fsS http://localhost:8080/health
check "Dashboard" curl -fsS http://localhost:3001/

echo "[HEALTH] Check complete"
