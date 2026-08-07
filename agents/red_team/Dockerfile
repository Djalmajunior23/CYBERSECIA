FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev git && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Install adversarial testing frameworks
RUN pip install --no-cache-dir pyrit garak deepteam
COPY mcp/ /app/mcp/
COPY agents/red_team/ /app/agents/red_team/
ENV PYTHONPATH=/app
ENV AGENT_ID=red_team_agent
ENV AGENT_TYPE=worker
ENV TEST_ENV_ONLY=true
CMD ["python", "-u", "agents/red_team/main.py"]
