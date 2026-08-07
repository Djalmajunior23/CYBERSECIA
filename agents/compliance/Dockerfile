FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/compliance/ /app/agents/compliance/
ENV PYTHONPATH=/app
ENV AGENT_ID=compliance_agent
ENV AGENT_TYPE=worker
ENV LGPD_ENABLED=true
ENV EU_AI_ACT_ENABLED=true
ENV NIST_AI_RMF_ENABLED=true
CMD ["python", "-u", "agents/compliance/main.py"]
