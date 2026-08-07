FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/threat_hunt/ /app/agents/threat_hunt/
ENV PYTHONPATH=/app
ENV AGENT_ID=threat_hunt_agent
ENV AGENT_TYPE=worker
CMD ["python", "-u", "agents/threat_hunt/main.py"]
