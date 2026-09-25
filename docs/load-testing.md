# Agent Load Testing

## Timed 100/250-host capacity test

Use `scripts/fleet_capacity_test.py` for realistic independent agent loops and
authenticated UI API probes. It creates synthetic hosts; **never point it at
your live installation**. The separate Compose file below has its own database,
no installation credentials or host-management mounts, and publishes only
`127.0.0.1:18800`. Stop each fleet-size stack before starting the next one.

The stack limits the server and PostgreSQL to **2 CPUs and 2 GiB each**. These
are container ceilings on the machine running Docker, not reserved hardware
or production sizing recommendations. Keep other heavy tasks off that machine
while measuring. The load generator also needs CPU and network headroom.

Before starting the stack, activate a Python environment with
`server/requirements.txt` installed and prepare `packages.json` from a
representative Ubuntu 24.04 host. For example, run this on that host and copy
the JSON file to the test client's working directory:

```bash
python3 - <<'PY' > packages.json
import json, subprocess, sys
rows = subprocess.check_output([
    'dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\n',
], text=True)
json.dump([dict(zip(('name', 'version', 'arch'), row.split('\t')))
           for row in rows.splitlines()], sys.stdout)
PY
```

Preparing dependencies and data first preserves the intended overlap with CVE
sync, which starts 150 seconds after application startup. From the repository
root, create disposable credentials outside the checkout:

```bash
export CAPACITY_DIR=$(mktemp -d)
python3 - <<'PY'
import json, os, secrets
from pathlib import Path
p = Path(os.environ['CAPACITY_DIR'])
values = {name: secrets.token_urlsafe(32) for name in (
    'CAPACITY_DB_PASSWORD', 'CAPACITY_UI_PASSWORD', 'CAPACITY_AGENT_TOKEN')}
for filename, data in {
    'stack.env': ''.join(f'{k}={v}\n' for k, v in values.items()),
    'agent-token': values['CAPACITY_AGENT_TOKEN'],
    'ui-password': values['CAPACITY_UI_PASSWORD'],
}.items():
    fd = os.open(p / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(data)
PY

docker compose -f deploy/docker/docker-compose.capacity.yml \
  --env-file "$CAPACITY_DIR/stack.env" -p lcm-capacity-100 up -d --build
```

Create a session through the normal login endpoint; the harness reads the resulting
cookie file without printing its contents:

```bash
python3 - <<'PY'
import json, os, time
from pathlib import Path
import httpx
p = Path(os.environ['CAPACITY_DIR'])
for _ in range(120):
    try:
        if httpx.get('http://127.0.0.1:18800/health', timeout=2).status_code == 200:
            break
    except httpx.HTTPError:
        pass
    time.sleep(.5)
else:
    raise SystemExit('Test server did not become healthy; inspect its logs')
response = httpx.post('http://127.0.0.1:18800/auth/login', json={
    'username': 'capacity-admin', 'password': (p / 'ui-password').read_text().strip(),
}, timeout=15)
response.raise_for_status()
cookies = dict(response.cookies)
assert 'fleet_session' in cookies, 'Login did not issue a session'
fd = os.open(p / 'ui-cookies.json', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as output:
    json.dump(cookies, output)
PY

python3 scripts/fleet_capacity_test.py \
  --base-url http://127.0.0.1:18800 --confirm-isolated \
  --agents 100 --agent-prefix capacity-100 \
  --bootstrap-token-file "$CAPACITY_DIR/agent-token" \
  --ui-cookie-file "$CAPACITY_DIR/ui-cookies.json" \
  --package-seed-file packages.json \
  --duration-seconds 420 --packages-per-host 850 --ui-clients 3 \
  --require-metrics-coverage --fail-on-error-rate 0 \
  --ready-file "$CAPACITY_DIR/ready-100.json" \
  --json "$CAPACITY_DIR/result-100.json" --csv "$CAPACITY_DIR/requests-100.csv"
```

This loopback stack is for API measurement; its test client explicitly supplies
the login cookie over loopback HTTP. MFA enforcement is disabled only in this
disposable stack. Normal browser deployments should use HTTPS and their usual
MFA policy. The harness supports `--ca-file` for a test server with a private CA.

For representative CVE matching, add `--package-seed-file packages.json`, a JSON
list of Ubuntu 24.04 package objects with `name`, `version`, and `arch`. It is
padded or truncated to `--packages-per-host`. The built-in seed includes only a
few real package names; the remaining entries are synthetic and will not match
CVE data. Record the seed and any deliberately older versions with the results.

The seven-minute measurement starts **after** every agent has registered and
successfully submitted its first package/update inventory. Defaults are:

- heartbeat every 5 seconds;
- package and update inventory every 300 seconds, with staggered first uploads;
- independent long-poll connections, followed by a 2-second pause;
- nonce-checked simulated results for metrics and user discovery; no received
  commands are executed;
- three staggered UI API streams, each requesting seven endpoints every 15
  seconds using one shared test session. This is not three real browsers.

CVE sync starts 150 seconds after application startup. Check the server logs
to confirm that all three Ubuntu release feeds finished and that their processing
overlapped the measured interval. A test without this overlap is not evidence
of performance during CVE sync. The CSV contains request start/end timestamps
and warmup/steady phases for checking the overlap.

Inspect persisted coverage as well as the client report: accepting a job event
does not by itself prove that the metric snapshot was saved.
`--require-metrics-coverage` requires every agent's acknowledgement before the
measurement deadline; it does not validate persisted snapshots or their age.

```bash
docker compose -f deploy/docker/docker-compose.capacity.yml \
  --env-file "$CAPACITY_DIR/stack.env" -p lcm-capacity-100 exec -T db \
  psql -U fleet -d fleet -c \
  "SELECT count(DISTINCT agent_id) AS hosts_with_metrics FROM host_metrics_snapshots;"

docker compose -f deploy/docker/docker-compose.capacity.yml \
  --env-file "$CAPACITY_DIR/stack.env" -p lcm-capacity-100 logs --timestamps server \
  > "$CAPACITY_DIR/server-100.log"

docker compose -f deploy/docker/docker-compose.capacity.yml \
  --env-file "$CAPACITY_DIR/stack.env" -p lcm-capacity-100 stop
```

Repeat using project name `lcm-capacity-250`, `--agents 250`, a new agent prefix,
and separate result files. Create a new login session for its separate DB.
Stopping the stack preserves its test database for inspection. Remove only the
specific test project's containers/volumes when you no longer need that dataset.

Acceptance checks:

- zero unexpected HTTP errors, restarts, or out-of-memory kills;
- assess every endpoint separately; many fast heartbeats must not hide a slow
  or broken report. Check endpoint request counts and missed UI rounds too:
  a slow earlier route can reduce later routes' request counts;
- target UI API p95 below 500 ms and check p99/max during CVE processing;
- all 100/250 hosts have persisted metrics, with freshness consistent with the
  configured batch size (about 2/5 minutes at 50 hosts per 60-second batch);
- no growing job backlog or missed heartbeat/inventory intervals;
- record CPU, peak memory, DB size, and the hardware/load-generator placement.

Short runs do not establish long-term retention, growth, high availability, or
browser rendering performance. Repeat with retained history and your actual
package/report workload before publishing a production capacity guarantee.

## Batch agent API tests

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
