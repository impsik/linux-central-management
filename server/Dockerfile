FROM golang:1.26.6 AS enrollment-agent
WORKDIR /src
COPY agent/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/fleet-agent-amd64 ./cmd/fleet-agent \
    && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /out/fleet-agent-arm64 ./cmd/fleet-agent

FROM python:3.11-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ansible openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY server/app ./app
COPY --from=enrollment-agent /out/ /app/enrollment-agents/

# Alembic migrations
COPY server/alembic.ini ./alembic.ini
COPY server/alembic ./alembic

EXPOSE 8000
CMD ["sh","-c","alembic upgrade head && exec uvicorn app.main:app --host ${SERVER_BIND_HOST:-0.0.0.0} --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
