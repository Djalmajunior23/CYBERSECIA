FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev iputils-ping && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/digital_twin/ /app/agents/digital_twin/
ENV PYTHONPATH=/app
ENV AGENT_ID=digital_twin_agent
ENV AGENT_TYPE=worker
ENV ISOLATED=true
CMD ["python", "-u", "agents/digital_twin/main.py"]
