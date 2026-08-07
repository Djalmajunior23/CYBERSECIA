# Fase 2 — Vulnerability Intelligence & Contextual Risk

## Objetivo

Transformar o fluxo de descoberta de ativos em uma cadeia operacional de priorização:

`Discovery -> Fingerprint/CPE -> CVE -> CVSS -> EPSS -> CISA KEV -> Asset Context -> Risk -> SOAR Remediation`

A fase não executa exploração automática. O SOAR cria recomendações/tickets de remediação; ações críticas continuam sujeitas aos gates HITL existentes.

## Componentes implementados

### 1. Discovery enriquecido

O `DiscoveryAgent` agora extrai do XML do Nmap:

- serviço;
- produto;
- versão;
- CPEs reportados pelo fingerprint;
- contexto operacional do ativo.

O contexto do ativo é carregado de `config/assets/risk_profiles.json`. O arquivo aceita um perfil padrão e perfis específicos por CIDR. Quando vários perfis correspondem ao IP, o CIDR mais específico vence.

### 2. Vulnerability Intelligence

`agents/vulnerability/intel_sources.py` implementa adaptadores para:

- NVD CVE API 2.0;
- FIRST EPSS API;
- CISA Known Exploited Vulnerabilities (KEV) JSON catalog.

A busca NVD prefere CPE 2.3 quando disponível e usa `keywordSearch` como fallback. EPSS é consultado em lotes. O catálogo KEV é correlacionado por CVE ID.

> Privacidade: consultas NVD por CPE/keyword podem revelar fingerprints de software a um serviço externo. Defina `VULN_NVD_LOOKUPS_ENABLED=false` em ambientes que exijam funcionamento exclusivamente local e alimente o cache por um mirror/feed interno.

### 3. Motor de risco contextual

`agents/vulnerability/risk_engine.py` separa severidade técnica de prioridade operacional. O score final, de 0 a 10, considera:

- CVSS;
- EPSS;
- presença e urgência no CISA KEV;
- criticidade do ativo;
- exposição;
- sinal adicional de threat intelligence.

Além do score, o motor produz:

- severidade `critical/high/medium/low`;
- tier de remediação `P1-P4`;
- SLA recomendado;
- confiança do score;
- componentes do cálculo;
- rationale legível.

### 4. Estado operacional centralizado

Os agentes continuam usando DBs Redis distintos para cache/estado local, mas o `CentralOrchestrator` projeta dados necessários ao BI/API para o Redis central:

- `mcp:assets`;
- `mcp:vulnerabilities`;
- `mcp:risk:last-summary`;
- `mcp:remediation`.

Isso elimina a inconsistência anterior em que o dashboard não conseguia enxergar CMDB/findings salvos nos DBs privados dos agentes.

### 5. SOAR de remediação

Findings `high` ou `critical` geram uma tarefa `vulnerability_triage` para o `SOARAgent`.

O agente cria tickets `REM-*` contendo:

- host/CVE;
- prioridade;
- risk score;
- SLA;
- ação recomendada;
- modo `recommendation_only`.

Nenhuma exploração, patch, isolamento ou contenção é executada por esse fluxo automaticamente.

### 6. API e Dashboard

Novos endpoints:

- `GET /api/assets`
- `GET /api/vulnerabilities`
- `GET /api/risk/summary`
- `GET /api/remediation`

O dashboard ganhou a aba **Vulnerabilidades**, com score contextual, CVSS, EPSS, KEV, confiança e SLA.

## Configuração do contexto de ativos

Exemplo de `config/assets/risk_profiles.json`:

```json
{
  "default": {
    "criticality": 5,
    "internet_exposed": null,
    "environment": "unknown"
  },
  "profiles": [
    {
      "network": "10.10.20.0/24",
      "criticality": 9,
      "internet_exposed": false,
      "environment": "production",
      "business_service": "MES"
    }
  ]
}
```

## Validação da fase

- Python `compileall`: aprovado.
- Testes unitários: 40 aprovados.
- JSX/JS: validação sintática aprovada via parser TypeScript.
- Build npm completo: não executado neste ambiente porque o registry interno não disponibilizou os pacotes React/Vite. Isso é uma limitação do ambiente de validação, não uma falha sintática detectada no frontend.

## Próximos passos recomendados

1. mirror/cache interno de NVD/EPSS/KEV para operação air-gapped;
2. normalização CPE avançada e software inventory/SBOM;
3. asset ownership e business impact via CMDB;
4. threat-intel correlation por CVE/TTP/campanha;
5. risk acceptance/exception workflow com expiração;
6. SLA aging e métricas MTTR/overdue;
7. banco PostgreSQL como source of truth e Redis apenas como cache/stream;
8. mTLS/PKI e trust store para identidades MCP;
9. autenticação JWT/RBAC real no API Gateway;
10. WORM/append-only audit anchoring.
