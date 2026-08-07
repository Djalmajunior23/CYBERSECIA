FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/response/ /app/agents/response/
COPY playbooks/ /app/playbooks/
ENV PYTHONPATH=/app
ENV AGENT_ID=response_orchestrator
ENV AGENT_TYPE=worker
CMD ["python", "-u", "agents/response/main.py"]
