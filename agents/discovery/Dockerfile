FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends nmap masscan libpcap-dev gcc libpq-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/discovery/ /app/agents/discovery/
COPY config/scopes/ /app/config/scopes/
COPY config/assets/ /app/config/assets/
ENV PYTHONPATH=/app
ENV AGENT_ID=discovery_agent
ENV AGENT_TYPE=worker
CMD ["python", "-u", "agents/discovery/main.py"]
