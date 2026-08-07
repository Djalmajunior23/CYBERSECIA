FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev git && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Install Atomic Red Team
RUN git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git /app/atomic
COPY mcp/ /app/mcp/
COPY agents/purple_team/ /app/agents/purple_team/
ENV PYTHONPATH=/app
ENV AGENT_ID=purple_team_agent
ENV AGENT_TYPE=worker
ENV ATOMIC_RED_TEAM_PATH=/app/atomic
CMD ["python", "-u", "agents/purple_team/main.py"]
