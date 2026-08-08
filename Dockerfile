FROM python:3.11-slim
WORKDIR /app

# Copia o requirements do api_gateway usando a estrutura do repositório
COPY services/api_gateway/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copia o main.py usando a estrutura do repositório
COPY services/api_gateway/main.py ./main.py

EXPOSE 8080

# Comando de inicialização respeitando a porta dinâmica $PORT fornecida pelo Render
CMD sh -c "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"
