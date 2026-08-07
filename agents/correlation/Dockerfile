FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp/ /app/mcp/
COPY agents/correlation/ /app/agents/correlation/
COPY config/knowledge_graph/ /app/config/knowledge_graph/
ENV PYTHONPATH=/app
ENV AGENT_ID=correlation_agent
ENV AGENT_TYPE=worker
CMD ["python", "-u", "agents/correlation/main.py"]
