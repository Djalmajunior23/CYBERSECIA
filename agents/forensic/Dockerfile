FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev sleuthkit && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/forensic/ /app/agents/forensic/
ENV PYTHONPATH=/app
ENV AGENT_ID=forensic_agent
ENV AGENT_TYPE=worker
ENV EVIDENCE_STORAGE=/app/evidence
ENV CHAIN_OF_CUSTODY=true
CMD ["python", "-u", "agents/forensic/main.py"]
