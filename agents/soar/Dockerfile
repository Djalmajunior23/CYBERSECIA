FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/soar/ /app/agents/soar/
COPY playbooks/ /app/playbooks/
ENV PYTHONPATH=/app
ENV AGENT_ID=soar_agent
ENV AGENT_TYPE=worker
ENV PLAYBOOKS_DIR=/app/playbooks
CMD ["python", "-u", "agents/soar/main.py"]
