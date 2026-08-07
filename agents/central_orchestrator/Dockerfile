FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/central_orchestrator/ /app/agents/central_orchestrator/
COPY config/ /app/config/
COPY prompts/system/ /app/prompts/
ENV PYTHONPATH=/app
ENV AGENT_ID=central_orchestrator
ENV AGENT_TYPE=orchestrator
CMD ["python", "-u", "agents/central_orchestrator/main.py"]
