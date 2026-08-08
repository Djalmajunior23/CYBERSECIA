# Guia de Deploy Manual no Render — CyberSec IA API Gateway

Este documento orienta o processo de deploy manual e publicação segura do backend/API Gateway do ecossistema CyberSec IA na plataforma **Render** através da interface gráfica (Web Service tradicional).

---

## 1. Stack do Deploy

* **Tecnologia**: Python + FastAPI
* **Servidor**: Uvicorn
* **Banco de Dados (Relacional)**: PostgreSQL Gerenciado na **Neon** (externo)
* **Banco de Cache/Estado**: Redis Serverless na **Upstash** (externo)
* **WebSocket**: Nativo e suportado no endpoint `/ws`
* **Health Check**: Endpoint `/health` integrado ao ping do Redis

---

## 2. Passo a Passo para o Deploy no Painel do Render (Sem Blueprint)

Siga este passo a passo para criar o Web Service de forma totalmente manual:

1. Acesse o [Render Dashboard](https://dashboard.render.com).
2. Clique no botão **New +** no canto superior direito e selecione a opção **Web Service**.
3. Conecte sua conta do GitHub e selecione o repositório **`Djalmajunior23/CYBERSECIA`**.
4. Na tela de configurações do serviço, preencha os seguintes campos de forma exata:
   * **Name**: `cybersecia-api`
   * **Region**: `oregon` (ou de sua preferência)
   * **Branch**: `main`
   * **Root Directory**: `services/api_gateway` *(Crucial para isolar o monorepo!)*
   * **Runtime**: `Python`
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   * **Instance Type**: `Free`
5. Clique na seção **Advanced** (Configurações Avançadas) no final da página e ajuste:
   * **Health Check Path**: `/health`
6. Na mesma seção Advanced, clique em **Add Environment Variable** para preencher as variáveis do backend:

### Variáveis de Ambiente Obrigatórias:

| Chave | Valor Recomendado / Exemplo | Descrição |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `production` | Modo de execução do ecossistema. |
| `REDIS_URL` | `redis://default:senha@upstash.io:6379` | URL de conexão com a sua instância do Redis na Upstash. |
| `DATABASE_URL` | `postgresql://user:password@neon.tech/cybersec` | URL de conexão com o banco PostgreSQL no Neon. |
| `CORS_ORIGINS` | `https://cybersecia.vercel.app` | URLs do frontend separadas por vírgula. |
| `API_ADMIN_TOKEN` | `seu-token-secreto-de-administrador` | Chave de autorização de decisões HITL. |
| `JWT_SECRET` | `gerar-um-segredo-forte-de-32-caracteres` | Chave de criptografia dos tokens JWT. |

7. Clique em **Create Web Service** no final da página para iniciar a build e o deploy.

---

## 3. Monitoramento e Validação

### Visualizar Logs:
* No painel do Render, vá até o seu serviço `cybersecia-api` e clique na aba **Logs** para inspecionar requisições e conexões do WebSocket em tempo real.

### Teste de Saúde:
* Acesse `https://cybersecia-api.onrender.com/health` (ou a URL real fornecida pelo Render).
* Resposta de sucesso esperada:
  ```json
  {
    "status": "healthy",
    "redis": true,
    "timestamp": "2026-08-07T22:39:00Z"
  }
  ```
