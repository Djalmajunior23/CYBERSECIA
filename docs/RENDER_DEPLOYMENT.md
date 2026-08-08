# Guia de Deploy no Render — CyberSec IA API Gateway

Este documento orienta o processo de deploy automatizado e publicação segura do backend/API Gateway do ecossistema CyberSec IA na plataforma **Render** utilizando arquivos de Blueprint (`render.yaml`).

---

## 1. Stack do Deploy

* **Tecnologia**: Python + FastAPI
* **Servidor**: Uvicorn
* **Banco de Cache/Estado**: Redis Gerenciado (Plano Gratuito)
* **WebSocket**: Nativo e suportado no endpoint `/ws`
* **Health Check**: Endpoint `/health` integrado ao ping do Redis

---

## 2. Preparação do Repositório e Blueprint

O Render detecta automaticamente a configuração de infraestrutura através do arquivo [render.yaml](file:///c:/VIBE%20CODING/CYBERSECIA/render.yaml) localizado na raiz do repositório.

### Detalhes do Blueprint:
* **Blueprint Name**: `cybersecia-production` ou `cybersecia-staging`
* **Branch**: `main` (produção) ou `feature/render-deployment` (staging)
* **Blueprint Path**: `render.yaml`

---

## 3. Passo a Passo para o Deploy no Painel do Render

1. Acesse o [Render Dashboard](https://dashboard.render.com).
2. Clique no botão **New +** e selecione a opção **Blueprint**.
3. Conecte sua conta do GitHub e selecione o repositório `Djalmajunior23/CYBERSECIA`.
4. Preencha as seguintes informações na tela de criação de Blueprint:
   * **Blueprint Name**: `cybersecia-production`
   * **Branch**: `main` (ou a branch técnica correspondente)
   * **Blueprint Path**: `render.yaml`
5. O Render lerá o arquivo de Blueprint, detectará o serviço de Web Service Python (`cybersecia-api`) e o banco de dados Redis (`cybersecia-redis`).
6. Preencha as variáveis de ambiente necessárias que estão marcadas para preenchimento manual (**CORS_ORIGINS** e **API_ADMIN_TOKEN**).
7. Clique em **Apply** para iniciar o provisionamento e o deploy.

---

## 4. Variáveis de Ambiente

| Variável | Obrigatória | Padrão / Exemplo | Descrição |
| :--- | :---: | :--- | :--- |
| `ENVIRONMENT` | Sim | `production` | Modo de execução do ecossistema. |
| `REDIS_URL` | Sim | *(Auto-injetada pelo Render)* | URL de conexão segura com o Redis. |
| `CORS_ORIGINS` | Sim | `https://cybersecia.vercel.app` | Domínios do frontend autorizados a fazer chamadas de API (separados por vírgula). |
| `API_ADMIN_TOKEN` | Sim | `change-me-to-a-strong-token` | Chave de autorização utilizada para as decisões críticas HITL (Aprovação Humana). |
| `JWT_SECRET` | Sim | *(Auto-gerada pelo Render)* | Segredo criptográfico para geração de tokens JWT seguros. |

> [!WARNING]
> Nunca versione chaves secretas ou tokens de produção reais no repositório. Use variáveis de ambiente do Render para mantê-las seguras.

---

## 5. Build, Start e Porta no Render

* **Root Directory**: `services/api_gateway` (o Render isola o monorepo e executa a compilação nesta pasta).
* **Build Command**: `pip install -r requirements.txt` (instala apenas as dependências mínimas necessárias do API Gateway).
* **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
* **Health Check**: Rota `/health`.
* **Porta**: O Render injeta dinamicamente a variável de ambiente `$PORT`. O uvicorn lê essa porta de forma transparente.

---

## 6. Monitoramento, Logs e Solução de Problemas (Troubleshooting)

### Visualizar Logs de Execução:
* No painel do Render, navegue até o serviço `cybersecia-api`.
* Clique na aba **Logs** para inspecionar requisições, conexões WebSocket e mensagens de inicialização.

### Verificação de Saúde:
* Faça uma requisição HTTP GET para `https://<seu-app-do-render>.onrender.com/health`.
* Resposta esperada:
  ```json
  {
    "status": "healthy",
    "redis": true,
    "timestamp": "2026-08-07T22:39:00Z"
  }
  ```

### Rollback:
* Se um deploy falhar ou apresentar comportamentos inesperados, você pode clicar em **Rollback** no painel do Render e escolher uma das builds bem-sucedidas anteriores para restaurar o serviço instantaneamente.
