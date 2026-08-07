# Guia de Deploy

## Requisitos

- Docker 24.0+
- Docker Compose 2.20+
- 16GB RAM mínimo (32GB recomendado)
- 50GB disco SSD
- Acesso à Internet (para downloads de imagens e feeds de inteligência)

## Deploy em Produção

### 1. Preparação
```bash
git clone <repo>
cd cybersec-ai-ecosystem
cp .env.example .env
# Configure todas as variáveis obrigatórias
```

### 2. Segurança Inicial
```bash
make init
# Isso gera:
# - Certificados PKI em config/pki/
# - Tópicos Kafka
# - Schema PostgreSQL
```

### 3. Primeiro Deploy
```bash
make build
make up
```

### 4. Validação
```bash
make health
# Todos os serviços devem reportar OK
```

### 5. Configuração de Scopes
Edite `config/scopes/authorized_networks.json` com seus ranges de rede.

### 6. Ativação de HITL
O HITL (Human-in-the-Loop) é ativado por padrão. Acesse:
- Dashboard: http://localhost:3001
- Fila de aprovações: Menu "HITL Queue"

## Troubleshooting

### Kafka não inicia
```bash
docker-compose logs kafka
# Verifique se a porta 9092 está livre
```

### Agentes não se conectam
```bash
# Verifique certificados
ls -la config/pki/
# Verifique conectividade de rede
docker-compose exec discovery_agent ping kafka
```

### Scope violation
```bash
# Verifique scopes autorizados
cat config/scopes/authorized_networks.json
# Verifique logs do Governance Agent
docker-compose logs governance_agent
```
