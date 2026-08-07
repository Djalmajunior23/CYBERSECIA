# Arquitetura do CyberSec AI Ecosystem

## Visão Geral

O ecossistema é construído sobre uma arquitetura de **microserviços orientada a agentes**, onde cada agente é um container Docker independente que se comunica via **Model Context Protocol (MCP)**.

## Princípios de Design

1. **Separação de Responsabilidades**: Cada agente tem uma função única e bem definida
2. **Resiliência**: Circuit breakers, retries, health checks, e standby instances
3. **Segurança por Design**: validação de escopo, HITL, assinatura de mensagens e hash chains; mTLS está planejado para o hardening de produção
4. **Escalabilidade**: Kafka para message broker, Redis para cache/state
5. **Observabilidade**: OpenTelemetry, Prometheus, Grafana
6. **Governança**: HITL gates, policy enforcement, bias detection

## Protocolo MCP

### Camadas de Segurança — estado atual
- **Transporte**: Kafka está configurado como PLAINTEXT no Compose de desenvolvimento; TLS/mTLS ainda precisa ser ligado.
- **Mensagem**: assinatura e hash de integridade existem; o helper AES-256-GCM ainda não está integrado ao fluxo normal de mensagens.
- **Autenticação**: API HITL usa token administrativo nesta fase; JWT/mTLS/SPIFFE ainda não formam uma identidade unificada.
- **Autorização**: arquivos RBAC/ABAC existem, mas a aplicação completa dessas políticas ainda está em evolução.
- **Auditoria**: eventos Redis possuem hash chain para evidência de adulteração; WORM/append-only externo é recomendado para produção.

### Topologia de Mensagens
- **Topics Kafka**: Um tópico por agente + tópicos compartilhados (alerts, audit, telemetry)
- **Routing**: Baseado em routing keys (mcp.agent.{agent_id})
- **Pub/Sub**: Redis para queries síncronas e HITL queues

## Fluxos de Dados

### 1. Varredura de Vulnerabilidade
```
Orquestrador -> Discovery (scan) -> Vulnerability (CVE) -> Threat Intel (enrich)
     -> Response (assess) -> Governance (approve) -> SOAR (playbook)
```

### 2. Resposta a Incidente Crítico
```
Behavioral (alert) -> Orquestrador -> SOAR (triage) + Threat Intel (enrich)
     + Threat Hunt (proactive) -> Response (contain) -> Forensic (evidence)
```

### 3. Red Team -> Purple Team Loop
```
Red Team (test) -> Purple Team (validate) -> Threat Hunt (detection)
     -> SOAR (playbook update) -> Compliance (report)
```

## Armazenamento

| Dado | Tecnologia | Justificativa |
|------|-----------|---------------|
| Metadados | PostgreSQL | ACID, relacional |
| Telemetria | ClickHouse | OLAP, séries temporais |
| Cache/State | Redis | Baixa latência, pub/sub |
| Audit Logs | Kafka + WORM | Imutabilidade, replay |
| Evidence | Volume Docker + Hash | Chain of custody |

## Rede

- **cybersec-net**: Rede principal (bridge, 172.20.0.0/16)
- **twin-sandbox**: Rede isolada para Digital Twin (internal, 172.30.0.0/16)
- **mTLS**: PKI disponível para hardening; não está ativado no Kafka/Compose atual
