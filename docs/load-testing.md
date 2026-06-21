# Agent Load Testing

Use `scripts/agent_load_test.py` to simulate large fleets sending data to the
agent API. It exercises the real `/agent/*` endpoints and follows the current
auth flow:

1. Register with `AGENT_SHARED_TOKEN`.
2. Store issued per-agent tokens in a local cache file.
3. Send HMAC-signed heartbeat, package inventory, update inventory, and optional
   job-poll requests as those agents.

Run this against staging or a disposable test install first. The test creates
fake host rows using the selected `--agent-prefix`.

## Install Client Dependency

If you are not using the repo virtualenv:

```bash
python3 -m pip install aiohttp
```

The repo backend requirements already include `aiohttp`.

## Onboarding Storm

This simulates 10,000 agents checking in and sending inventory.

```bash
python3 scripts/agent_load_test.py \
  --base-url http://SERVER_IP:8000 \
  --bootstrap-token "$AGENT_SHARED_TOKEN" \
  --agents 10000 \
  --agent-prefix loadtest-10k \
  --concurrency 250 \
  --ramp-up-seconds 120 \
  --cycles 1 \
  --packages-per-host 25 \
  --updates-per-host 5 \
  --csv loadtest-10k.csv
```

## Steady-State Heartbeat Test

After the first run, reuse the token cache and send repeated heartbeat waves.

```bash
python3 scripts/agent_load_test.py \
  --base-url http://SERVER_IP:8000 \
  --agents 10000 \
  --agent-prefix loadtest-10k \
  --skip-register \
  --token-cache .loadtest-agent-tokens.json \
  --concurrency 250 \
  --cycles 10 \
  --cycle-sleep-seconds 30 \
  --packages-per-host -1 \
  --updates-per-host -1 \
  --csv loadtest-10k-heartbeat.csv
```

## Include Long-Polling

`/agent/next-job` can hold connections for `AGENT_POLL_TIMEOUT_SECONDS`. Test it
separately so it does not hide write-path bottlenecks.

```bash
python3 scripts/agent_load_test.py \
  --base-url http://SERVER_IP:8000 \
  --agents 10000 \
  --agent-prefix loadtest-10k \
  --skip-register \
  --token-cache .loadtest-agent-tokens.json \
  --concurrency 500 \
  --cycles 1 \
  --packages-per-host -1 \
  --updates-per-host -1 \
  --poll-next-job
```

## What To Watch

On the app server:

```bash
docker stats
docker compose -f deploy/docker/docker-compose.yml logs -f server
```

If Postgres is in Docker:

```bash
docker compose -f deploy/docker/docker-compose.yml exec db psql -U fleet -d fleet -c "select count(*) from hosts;"
docker compose -f deploy/docker/docker-compose.yml exec db psql -U fleet -d fleet -c "select count(*) from host_packages;"
docker compose -f deploy/docker/docker-compose.yml exec db psql -U fleet -d fleet -c "select count(*) from host_package_updates;"
```

Good first-pass criteria:

- No server/container restart.
- Error rate under 1%.
- p95 heartbeat latency stays below a few seconds during steady-state waves.
- Package/update inventory latency is stable instead of rising every cycle.
- Dashboard and host inventory remain usable while the test is running.

If the app fails this test, keep the token cache and CSV output. They make it
easy to rerun the same fleet shape after tuning database indexes, worker count,
connection pool size, or expensive write paths.
