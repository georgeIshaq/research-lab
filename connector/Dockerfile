FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY lambda_connector ./lambda_connector

RUN useradd --system --uid 10001 app
USER app

# Cloud Run sets PORT. --proxy-headers lets the app see the https scheme Cloud Run terminates.
CMD exec uvicorn --factory lambda_connector.server:create_app --host 0.0.0.0 --port "$PORT" --proxy-headers --forwarded-allow-ips '*'
