FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -e . && pip install --no-cache-dir requests beautifulsoup4

EXPOSE 8000

CMD ["uvicorn", "skoll.web_server:app", "--host", "0.0.0.0", "--port", "8000"]
