.PHONY: all build up down logs ps clean init test redteam-scan health purple-validate threat-hunt compliance-audit mcp-audit backup-evidence

all: init build up

init:
	@echo "[INIT] Generating/reusing PKI certificates..."
	@bash scripts/init-pki.sh
	@echo "[INIT] Starting infrastructure required for initialization..."
	@docker compose up -d kafka redis postgres
	@echo "[INIT] Waiting for Kafka..."
	@until docker compose exec -T kafka kafka-broker-api-versions --bootstrap-server kafka:29092 >/dev/null 2>&1; do sleep 2; done
	@echo "[INIT] Waiting for PostgreSQL..."
	@until docker compose exec -T postgres pg_isready -U cybersec -d cybersec_ecosystem >/dev/null 2>&1; do sleep 2; done
	@echo "[INIT] Creating Kafka topics..."
	@KAFKA_BROKER=kafka:29092 bash scripts/init-kafka-topics.sh
	@echo "[INIT] Ensuring database schema..."
	@docker compose exec -T postgres psql -U cybersec -d cybersec_ecosystem -f /docker-entrypoint-initdb.d/init.sql >/dev/null
	@echo "[INIT] Done."

build:
	@echo "[BUILD] Building all containers..."
	@docker compose build --parallel

up:
	@echo "[UP] Starting CyberSec AI Ecosystem..."
	@docker compose up -d
	@echo "[UP] Services available:"
	@echo "  - Dashboard:     http://localhost:3001"
	@echo "  - API Gateway:   http://localhost:8080"
	@echo "  - Grafana:       http://localhost:3000"
	@echo "  - Kafka:         localhost:9092"
	@echo "  - Redis:         localhost:6379"
	@echo "  - PostgreSQL:    localhost:5432"
	@echo "  - ClickHouse:    localhost:8123"

down:
	@echo "[DOWN] Stopping all services..."
	@docker compose down

logs:
	@docker compose logs -f --tail=100

ps:
	@docker compose ps

health:
	@bash scripts/healthcheck.sh

redteam-scan:
	@echo "[RED TEAM] Dispatching adversarial test in the test environment..."
	@docker compose exec -T central_orchestrator python agents/central_orchestrator/dispatch.py \
		--target-agent red_team_agent \
		--task-type adversarial_test \
		--priority high \
		--parameters '{"target_agent":"all_test_agents","layer":"model"}'

purple-validate:
	@echo "[PURPLE TEAM] Dispatching defense validation..."
	@docker compose exec -T central_orchestrator python agents/central_orchestrator/dispatch.py \
		--target-agent purple_team_agent \
		--task-type defense_validation \
		--priority medium \
		--parameters '{"technique":"T1566.001","target_env":"test"}'

threat-hunt:
	@echo "[THREAT HUNT] Dispatching proactive hunt..."
	@docker compose exec -T central_orchestrator python agents/central_orchestrator/dispatch.py \
		--target-agent threat_hunt_agent \
		--task-type proactive_hunt \
		--priority medium \
		--parameters '{"hypothesis":"apt29_lateral_movement"}'

compliance-audit:
	@echo "[COMPLIANCE] Dispatching regulatory audit..."
	@docker compose exec -T central_orchestrator python agents/central_orchestrator/dispatch.py \
		--target-agent compliance_agent \
		--task-type compliance_audit \
		--priority medium \
		--parameters '{"frameworks":["lgpd","eu_ai_act","nist_ai_rmf"]}'

mcp-audit:
	@echo "[MCP AUDIT] Dispatching MCP registry audit..."
	@docker compose exec -T central_orchestrator python agents/central_orchestrator/dispatch.py \
		--target-agent mcp_auditor_agent \
		--task-type mcp_audit \
		--priority medium \
		--parameters '{}'

clean:
	@echo "[CLEAN] Removing all containers, networks, and volumes..."
	@docker compose down -v
	@docker system prune -f

test:
	@echo "[TEST] Running unit and integration tests..."
	@python -m pytest tests/ -v --tb=short

backup-evidence:
	@mkdir -p backups
	@echo "[BACKUP] Creating forensic evidence backup..."
	@docker run --rm -v cybersec-ai-ecosystem_forensic-evidence:/source -v $(PWD)/backups:/dest alpine \
		tar czf /dest/evidence-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /source .
