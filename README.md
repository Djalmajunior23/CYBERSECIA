# 🛡️ CyberSec AI Ecosystem

**Plataforma de cibersegurança orientada por IA — 15 agentes especializados + orquestrador central, arquitetura MCP, HITL, Risk Intelligence e Knowledge Graph.**

## Visão Geral

Este ecossistema integra:
- **6 Agentes Base**: Discovery, Vulnerability, Threat Intel, Behavioral, Response, Governance
- **9 Agentes de Expansão**: Red Team, SOAR, Purple Team, MCP Auditor, Digital Twin, Threat Hunt, Compliance, Forensic, Correlation
- **Protocolo MCP interno**: Mensageria entre agentes com assinatura, integridade, circuit breaker e trilha de auditoria; TLS/mTLS do Kafka ainda está em fase de hardening
- **Playbooks SOAR**: Resposta automatizada a incidentes (ransomware, phishing, insider threat, AI compromise)
- **Conformidade**: LGPD, EU AI Act, NIST AI RMF, ISO 27001:2022
- **Vulnerability Intelligence contextual**: CPE -> NVD/CVE -> CVSS -> EPSS -> CISA KEV -> criticidade/exposição -> risco operacional -> SOAR.
- **Estado operacional central**: ativos, findings e remediações projetados pelo orquestrador para API/BI.

## Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                    CENTRAL ORCHESTRATOR                     │
│              (Decomposição, Coordenação, HITL)             │
└──┬────────┬────────┬────────┬────────┬────────┬──────────┘
   │        │        │        │        │        │
┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐
│Disc.│ │Vuln.│ │Thrt.│ │Behav│ │Resp.│ │Gov. │
│Agent│ │Agent│ │Intel│ │ioral│ │Orch.│ │ern. │
└──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘
   │        │        │        │        │        │
┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐ ┌──▼──┐
│Red  │ │SOAR │ │Purpl│ │MCP  │ │Digi-│ │Thrt.│
│Team │ │Agent│ │eTeam│ │Audit│ │Twin │ │Hunt │
│Agent│ │     │ │Agent│ │or   │ │Agent│ │Agent│
└─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘
┌─────────────────────────────────────────────────────────────┐
│ Compliance │ Forensic │ Correlation │ Kafka / Redis       │
└─────────────────────────────────────────────────────────────┘
```

## Fase 2 — Risk Intelligence

A cadeia de descoberta e vulnerabilidades agora funciona como um pipeline de priorização:

```text
Discovery -> Fingerprint/CPE -> CVE -> CVSS -> EPSS -> CISA KEV
          -> Asset Criticality/Exposure -> Contextual Risk -> SOAR Remediation
```

Principais entregas:

- extração de produto, versão e CPE pelo Discovery Agent;
- perfis de criticidade por CIDR em `config/assets/risk_profiles.json`;
- adaptadores para NVD CVE API 2.0, FIRST EPSS e CISA KEV;
- motor de risco 0-10 com `P1-P4`, SLA, confiança e rationale;
- fila SOAR de remediação em modo `recommendation_only`;
- endpoints `/api/assets`, `/api/vulnerabilities`, `/api/risk/summary` e `/api/remediation`;
- nova visão de vulnerabilidades no dashboard.

Detalhes: [`docs/PHASE2_RISK_INTELLIGENCE.md`](docs/PHASE2_RISK_INTELLIGENCE.md).

## Quick Start

### 1. Clone e Configure
```bash
cd cybersec-ai-ecosystem
cp .env.example .env
# Edite .env com suas chaves de API
```

### 2. Inicialize a Infraestrutura
```bash
make init        # Gera certificados PKI, cria tópicos Kafka, inicializa DB
make build       # Builda todos os containers Docker
make up          # Inicia o ecossistema completo
```

### 3. Acesse os Serviços
| Serviço | URL | Credenciais |
|---------|-----|-------------|
| Dashboard | http://localhost:3001 | — |
| API Gateway | http://localhost:8080 | leitura local; decisões HITL usam `X-API-Key` |
| Grafana | http://localhost:3000 | admin / (ver .env) |
| Kafka | localhost:9092 | — |
| PostgreSQL | localhost:5432 | cybersec / (ver .env) |

### 4. Operações Diárias
```bash
make health              # Verifica saúde de todos os serviços
make redteam-scan        # Executa testes adversariais nos agentes
make purple-validate     # Valida cobertura de detecção
make threat-hunt         # Inicia caça proativa a ameaças
make compliance-audit    # Audita conformidade regulatória
make mcp-audit           # Audita conexões MCP
```

## Estrutura do Projeto

```
cybersec-ai-ecosystem/
├── docker-compose.yml          # Orquestração de 20+ serviços
├── Makefile                    # Comandos de operação
├── .env.example                # Template de configuração
├── requirements.txt            # Dependências Python
├── mcp/                        # Protocolo MCP Core
│   ├── core/protocol.py        # Schema de mensagens
│   └── core/client.py          # Cliente MCP (assinatura, circuit breaker, TLS opcional)
├── agents/                     # 15 agentes especializados + orquestrador
│   ├── central_orchestrator/   # Coordenação central
│   ├── discovery/              # Reconhecimento de rede
│   ├── vulnerability/          # CVE + EPSS/KEV + motor de risco contextual
│   ├── threat_intel/           # Inteligência de ameaças
│   ├── behavioral/             # UEBA / Anomalias
│   ├── response/               # Contenção automatizada
│   ├── governance/             # Auditoria e governança
│   ├── red_team/               # Testes adversariais
│   ├── soar/                   # Resposta a incidentes 24/7
│   ├── purple_team/            # Simulação + validação
│   ├── mcp_auditor/            # Auditoria de MCP
│   ├── digital_twin/           # Ambiente de simulação
│   ├── threat_hunt/            # Caça proativa
│   ├── compliance/             # LGPD, EU AI Act
│   ├── forensic/               # Análise forense
│   └── correlation/            # Knowledge Graph + correlação de risco
├── playbooks/                  # Playbooks SOAR
│   ├── incident_response/      # Ransomware, Phishing, Insider
│   └── containment/            # Lateral movement
├── config/                     # Configurações
│   ├── scopes/                 # Redes autorizadas
│   ├── assets/                 # Criticidade e contexto de risco
│   ├── policies/               # Políticas de segurança
│   ├── rbac/                   # Controle de acesso
│   └── mcp_servers.json        # Servidores MCP autorizados
├── scripts/                    # Scripts de inicialização
│   ├── init-pki.sh             # Geração de certificados
│   ├── init-kafka-topics.sh    # Criação de tópicos
│   ├── init-db.sql             # Schema PostgreSQL
│   └── healthcheck.sh          # Verificação de saúde
├── prompts/system/             # Prompts para AI Studio
└── docs/                       # Documentação
```

## Segurança

- **Scope Validation**: varreduras de rede são fail-closed, limitadas a CIDRs autorizados e respeitam exclusões explícitas.
- **HITL Gates**: tarefas críticas selecionadas são retidas pelo orquestrador e só são liberadas após aprovação humana via API protegida.
- **Circuit Breaker**: prevenção de cascata de falhas na mensageria entre agentes.
- **Audit Trail**: Redis Streams com encadeamento SHA-256 para detecção de adulteração; armazenamento WORM ainda é uma etapa futura.
- **PKI**: scripts de geração de certificados existem, porém o `docker-compose.yml` ainda usa Kafka PLAINTEXT por padrão; mTLS precisa ser ligado no hardening de produção.
- **Assinatura de mensagens**: assinatura Ed25519 está implementada no cliente, mas a verificação de identidade por chave pública confiável ainda precisa ser conectada ao registry.
- **Red/Purple Team**: a arquitetura e os agentes existem, porém vários resultados ainda são simulados e não devem ser tratados como evidência real.
- **External vulnerability intelligence**: NVD lookups can be disabled with `VULN_NVD_LOOKUPS_ENABLED=false` when product/CPE fingerprints must remain local.

## Frameworks Integrados

- MITRE ATT&CK Enterprise v16.0+
- MITRE ATLAS v5.4.0+
- OWASP Top 10 for LLM 2025
- OWASP ASI (Agentic AI) 2026
- OWASP MCP Top 10
- NIST Cybersecurity Framework 2.0
- NIST AI Risk Management Framework
- EU AI Act (Regulation 2024/1689)
- LGPD (Lei 13.709/2018)
- ISO/IEC 42001 / 27001:2022

## Licença

MIT License — Uso em ambientes autorizados apenas.


## Phase 3 — Intelligence Graph

The current baseline adds a dedicated **Correlation Agent** that builds an explainable cybersecurity knowledge graph from the operational state. It connects assets, exposed services, CPEs, vulnerabilities, ATT&CK techniques, IOCs, threat actors, campaigns, incidents, defensive controls and remediation tickets.

Key outputs:

- evidence-backed risk correlations (KEV + exposure, EPSS + criticality, ATT&CK convergence);
- defensive attack paths (`asset → service → CVE → ATT&CK`);
- control coverage and gap visibility;
- read-only graph APIs and an **Intelligence Graph** dashboard view;
- periodic graph rebuilds without automatic offensive or containment actions.

See [`docs/PHASE3_KNOWLEDGE_GRAPH.md`](docs/PHASE3_KNOWLEDGE_GRAPH.md).
