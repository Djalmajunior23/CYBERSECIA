FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/mcp_auditor/ /app/agents/mcp_auditor/
COPY config/mcp_servers.json /app/config/mcp_servers.json
ENV PYTHONPATH=/app
ENV AGENT_ID=mcp_auditor_agent
ENV AGENT_TYPE=worker
CMD ["python", "-u", "agents/mcp_auditor/main.py"]
