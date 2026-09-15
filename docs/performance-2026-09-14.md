# Capacity evaluation: 14 September 2026

**The 100-host run met this short test protocol; the 250-host run did not.**
At 250 hosts, UI API p95 exceeded the 500 ms target, heartbeat intervals were
missed, and one warmup request failed. Both runs collected metrics from every
host and completed all three CVE feeds. These results do not establish a
production hardware requirement.

## Changes under evaluation

- **Metrics collection reaches the whole fleet.** The scheduler selects hosts
  with missing or oldest metrics before applying its batch limit. It excludes
  outstanding collection jobs and considers recent attempts so failing hosts
  cannot repeatedly take the first batch. Database work runs in a worker thread;
  jobs are committed before notifying the dispatcher. An interval of zero now
  disables automatic collection.
- **Routine metrics history has a bounded cleanup policy.** By default, cleanup
  runs every 300 seconds and removes at most 5,000 successful automatic metrics
  job runs older than seven days. It preserves manual jobs, failed and active
  runs, and jobs referenced by audit or workflow records. Empty parent jobs are
  removed only when safe. The cleanup uses an indexed selection, PostgreSQL
  transaction timeouts, and an advisory lock. This policy does not delete stored
  metrics snapshots or other administrative history.
- **Authentication releases database connections before network waits.** Agent
  authentication reads its token hash in a short worker-owned session before
  awaiting the signed request body. UI authentication resolves an immutable
  session snapshot and closes its connection before downstream processing.
  Existing token, HMAC, session, MFA, and CSRF checks remain in place.
- **Job polling holds connections only while accessing the queue.** The long
  poll waits outside a database session. PostgreSQL claims lock the individual
  run rather than a batch's shared parent job, and stale-run recovery locks its
  candidates to prevent overlapping polls from recovering the same run twice.
- **CVE reports read less inventory.** Report generation first finds relevant
  releases, package names, and CVEs above the severity threshold. It then loads
  only matching inventory columns and reuses repeated version comparisons in a
  bounded cache local to that request. Existing background CVE parsing and
  reporting run outside the API event loop.

Earlier diagnostic runs identified connection-pool exhaustion and expensive
fleet-wide CVE reporting. Those runs used earlier code and are not the final
results for the changes above. In particular, a diagnostic run without a
completed three-feed sync cannot establish performance through an entire sync.

## Tested build and environment

The candidate reports version `0.1.0-beta.1`, with local changes on top of base
commit `97aa2b2b36a93c70905f3007022bba8b448fac93`. The archived
`tested-build.json` records SHA-256 hashes for the relevant server, harness, and
Compose files. The version or base commit alone does not identify this candidate.

| Item | Configuration |
|---|---|
| Physical host | Intel Xeon E3-1270 at 3.40 GHz; 4 cores / 8 threads |
| Physical memory | Approximately 24 GB; 23,990 MiB reported |
| API server container | Maximum 2 CPUs and 2 GiB RAM |
| Database container | PostgreSQL 16; maximum 2 CPUs and 2 GiB RAM |
| Test client | Same shared Linux machine as both containers |
| Transport | Loopback HTTP; no TLS or external network latency in API probes |
| Isolation | Separate empty PostgreSQL volume for each fleet size; runs sequential |
| Image | `lcm-capacity-test:beta` |
| Image ID | `sha256:b8c09225b6c15a111b0942baabd4dd0ceb5574f9f69c2b3d27ee77ac0b8e9358` |

These CPU and memory limits are **container ceilings**, not dedicated resources
or measured production requirements. The load generator, server, database, and
other work on the machine share physical CPU and memory. The final test image
contained the tested application code; it had no source bind mounts or overlays.
Any recommended production VM size remains a planning estimate and must be
presented separately from this experiment's measured resource use.

## Workload

The procedure and reusable commands are in [Agent Load Testing](load-testing.md).
The harness uses real agent registration, issued per-agent credentials,
HMAC-signed requests, and nonce-checked simulated job results. It does not run
received management commands on real machines.

| Parameter | Value |
|---|---|
| Fleet sizes | 100 and 250 simulated hosts, each starting with an empty test DB |
| Initial population | 20-second registration ramp and 60-second inventory stagger; about 80 seconds planned warmup |
| Measurement interval | 420 seconds after every initial package and update inventory succeeds |
| Heartbeat | Every 5 seconds per host |
| Package and update inventory | Every 300 seconds per host |
| Job polling | Independent connections, expected 25-second server wait, then a 2-second pause |
| Packages per host | 850: 686 real Ubuntu package names, padded with synthetic names |
| Version overrides | 10 real packages deliberately use older baseline versions |
| UI API activity | Three staggered streams using one authenticated test session |
| UI request cadence | Seven endpoints per stream every 15 seconds, sequential within a stream |
| Metrics scheduling | Up to 50 hosts per 60-second batch |
| CVE data | Real Canonical Ubuntu focal, jammy, and noble feeds |
| CVE start | Configured 150 seconds after application startup |

Actual warmup duration depends on request completion and is recorded separately
from the planned ramp. The package seed SHA-256 is
`0836a0356a3652a48f0e8036715cd8871843d3826bd383df9afd3d8a56e7237b`.
Synthetic padding exercises inventory volume but does not match real CVEs;
shared package data also means this is not a heterogeneous 250-host fleet.

The test session is created through normal login. MFA enforcement is disabled
only in the disposable stack, and the client explicitly supplies its session
cookie over loopback HTTP. No installation credentials, SSH keys, or live
management volumes are used.

## Measurement and acceptance

The JSON summary and request CSV distinguish warmup from the measured interval.
The analysis uses CSV request start/end timestamps and server logs to calculate
latency across the full measured interval and for requests overlapping CVE sync.
An overlapping request retains its entire latency. Sync completion and overlap
are established from the logged start, release stages, and completion event.

Each endpoint's count, failures, p50, p95, p99, and maximum are assessed separately.
The target for UI API p95 is below 500 ms, including during CVE processing.
The expected long-poll wait is reported separately; it is not a slow ordinary
API response. Counts and missed UI rounds matter because a slow early endpoint
delays later requests in the same stream.

**These are HTTP API measurements, not browser rendering measurements.** The
three streams do not load HTML, execute application JavaScript, render the host
table, measure interaction latency, or represent three distinct signed-in users.

Persisted metrics and their age are sampled directly in PostgreSQL near the end
of each run. Client acknowledgements alone do not prove snapshots were stored.
With the configured scheduler, a normal complete rotation is approximately two
minutes for 100 hosts and five minutes for 250 hosts. Database observations
include their sample's offset from the measurement deadline.

The analysis also records HTTP errors, overdue heartbeat/inventory intervals,
job backlog, container restarts, out-of-memory kills, sampled CPU/memory peaks,
and database size. Docker CPU percentages use 100% for one CPU core. Docker
memory reporting is not process RSS, and periodic samples can miss shorter
peaks. Each measured interval contains 75 resource snapshots; the database was
sampled 18 times at 100 hosts and 19 times at 250 hosts. Sample timestamps
slightly precede collection completion.

## Final results

The results come from the archived `analysis-100.json` / `analysis-100.md` and
`analysis-250.json` / `analysis-250.md`. The JSON analyses include the build
manifest and saved final database/container state. All times below are UTC on
14 September 2026.

| Check | 100 hosts | 250 hosts |
|---|---|---|
| Measured interval; actual warmup | 18:53:34.156–19:00:34.158; 420.001 s measured, 79.707 s warmup | 19:02:59.978–19:09:59.979; 420.001 s measured, 91.654 s warmup |
| All three CVE feeds complete; overlap duration | Yes; 18:54:32.592–18:56:58.427, 145.835 s | Yes; 19:03:44.766–19:08:44.069, 299.303 s |
| Unexpected HTTP errors during measurement | 0 across 9,888 ordinary requests and 1,650 completed long polls | 0 across 21,477 ordinary requests and 3,673 completed long polls |
| Unexpected HTTP errors during warmup | 0 | 1 failed long poll out of 1,058 warmup polls; 5,756 warmup requests in total |
| Cancelled requests at shutdown | 100 intentionally cancelled idle long polls; no other request types | 243 intentionally cancelled idle long polls; no other request types |
| Persisted metrics coverage and oldest latest snapshot | 100/100; 75.241 s old at 19:00:16.095, 18.062 s before deadline | 250/250; 276.382 s old at 19:09:50.294, 9.685 s before deadline |
| Missed heartbeat / inventory / UI intervals | 0 / 0 / 0 across all phases | 1,978 / 0 / 0 across all phases |
| Job runs in samples near the end | 500 successful; no queued, running, or failed runs | 650 successful; no queued, running, or failed runs |
| Sampled server CPU / memory peak | 159.61% / 217.3 MiB | 154.59% / 314.4 MiB |
| Sampled database CPU / memory peak | 61.93% / 194.1 MiB | 73.32% / 271.4 MiB |
| Final database size | 84,057,111 bytes, approximately 80.2 MiB | 121,412,631 bytes, approximately 115.8 MiB |
| Server and database restarts / OOM kills | 0 / 0 for both containers | 0 / 0 for both containers |
| Protocol outcome | Pass for this short workload | Fail: warmup error, UI latency, and missed heartbeats |

The saved 100-host final database/container snapshot is at 19:00:46.462 UTC, 12.304 seconds
after the deadline: all 100 hosts were online, all had persisted metrics, and
the oldest latest snapshot was 102.863 seconds old. It contained 85,000 installed
packages, 2,500 available-update rows, 8,448 CVE definitions, and 176,504 CVE
package links. Its 22 database connections included no idle transactions.

The 250-host final snapshot is at 19:10:02.416 UTC, 2.437 seconds after the
deadline: all 250 hosts were online and had persisted metrics, with the oldest
latest snapshot 285.758 seconds old. It contained 212,500 installed packages,
6,250 available-update rows, and the same 8,448 CVE definitions and 176,504 CVE
package links. Its 22 database connections also included no idle transactions.

The 250-host warmup failure was a `ServerDisconnectedError` on `next-job` at
19:02:21.594 UTC, after 16.880 ms. Its cause is unresolved. It occurred before
CVE sync started and cannot be attributed to that sync. The next normal poll
started two seconds later and completed with HTTP 200. All 25,150 completed
steady requests returned HTTP 200, but the warmup failure still fails the
harness's strict zero-error check. No container restart or OOM kill was observed.

Pacing counters cover warmup, steady measurement, and draining together; they
cannot isolate missed intervals to the CVE window. At 250 hosts, the measured
heartbeat p95 was 5,411.755 ms, longer than the five-second heartbeat period;
package inventory p95 was 14,266.305 ms. The 1,978 skipped heartbeat intervals
therefore remain a material failure even though every completed steady request
succeeded and hosts remained online. No inventory or UI rounds were skipped.

Idle polls were intentionally cancelled when each measured workload ended.
Cancelled requests remain in the harness summary and are excluded from CSV
latency percentiles. Neither run reported background-task errors. The 100-host
run had no harness validation failures; the 250-host run recorded the warmup
poll failure above.

### 100-host UI API latency

All latencies below are milliseconds. Counts and p50/p95/p99/max refer to the
full measured interval. Each route also had 29 completed requests overlapping
the initial CVE sync, with zero failures; the final column gives that window's
p95. Each route's overall p95 was below the 500 ms target. The urgent-updates
route had an observed maximum above 500 ms, so this is not a maximum-latency
guarantee.

| UI API endpoint | Count | Failures | p50 | p95 | p99 | Max | Sync p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `/dashboard/summary` | 84 | 0 | 29.669 | 198.680 | 469.550 | 469.550 | 208.380 |
| `/dashboard/urgent-updates?limit=10` | 84 | 0 | 196.091 | 411.247 | 508.415 | 508.415 | 45.810 |
| `/hosts` | 84 | 0 | 28.478 | 49.190 | 189.280 | 189.280 | 41.203 |
| `/reports/hosts-updates?only_pending=false&online_only=false&limit=500` | 84 | 0 | 30.445 | 57.454 | 232.266 | 232.266 | 161.243 |
| `/reports/cve-high-severity?min_severity=7&limit=200` | 84 | 0 | 194.465 | 372.166 | 473.335 | 473.335 | 85.687 |
| `/dashboard/attention?limit=500&include_live=false` | 84 | 0 | 31.274 | 60.548 | 188.429 | 188.429 | 60.548 |
| `/auth/me` | 84 | 0 | 10.390 | 22.829 | 75.327 | 75.327 | 25.190 |

**The CVE-overlap window covers the first sync into an empty database.** These
hosts use Ubuntu 24.04, and relevant noble data became available only near the
end of the three-feed sync. CVE-dependent report latencies during that window
are therefore lower than after the data is populated. The 100-host overall
figures include about 3.5 minutes after the complete sync, with fully populated
CVE data. Repeated synchronization against existing CVE data and retained
history was not tested.

### 250-host UI API latency

All latencies are milliseconds. Counts and p50/p95/p99/max cover the full
measured interval. Each route had 60 completed requests overlapping the initial
CVE sync, with zero failures; the final column gives that window's p95. Every
route exceeded the 500 ms p95 target in both windows.

| UI API endpoint | Count | Failures | p50 | p95 | p99 | Max | Sync p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `/dashboard/summary` | 84 | 0 | 47.505 | 1213.244 | 2341.898 | 2341.898 | 1347.903 |
| `/dashboard/urgent-updates?limit=10` | 84 | 0 | 134.845 | 1251.450 | 1442.889 | 1442.889 | 1277.862 |
| `/hosts` | 84 | 0 | 75.375 | 1221.278 | 1824.616 | 1824.616 | 1322.986 |
| `/reports/hosts-updates?only_pending=false&online_only=false&limit=500` | 84 | 0 | 70.235 | 1249.312 | 1815.786 | 1815.786 | 1293.027 |
| `/reports/cve-high-severity?min_severity=7&limit=200` | 84 | 0 | 76.731 | 1146.839 | 2558.328 | 2558.328 | 1146.839 |
| `/dashboard/attention?limit=500&include_live=false` | 84 | 0 | 70.367 | 926.467 | 1542.418 | 1542.418 | 1019.313 |
| `/auth/me` | 84 | 0 | 31.163 | 991.286 | 1491.241 | 1491.241 | 1018.553 |

The three-feed sync took 299.303 seconds, leaving only 75.910 seconds of the
measured interval after the full CVE dataset was available. The same cold-sync
limitation applies: much of this run precedes the matching noble feed's arrival.

A single additional authenticated report GET after measurement confirmed
1,000 host/package findings and returned its first 200 rows, including
`libssl3t64`, `openssh-server`, `openssl`, and `sudo`. This proves the seeded
inventory matched real feed data; these are host/package findings, not 1,000
distinct CVEs. The check is saved in `cve-report-check-250.json` and is excluded
from all measured counts and latency statistics.

The archived evidence includes the build manifest, package seed, harness
JSON/CSV, timestamped server logs, and container/database samples. Disposable
passwords, agent tokens, and session cookies are excluded from this report.

## Conclusions

The implemented fixes are sufficient for the 100-host workload in this short,
isolated run: every host had recent persisted metrics, all three feeds
completed, UI API p95 stayed below 500 ms, and no unexpected errors or missed
scheduled intervals were recorded.

The 250-host run did not pass the same protocol. Metrics coverage and successful
steady responses show continued operation, but they do not cancel out the
warmup error, missed heartbeats, or UI API p95 of 926–1,251 ms. This test is not
evidence that 250 hosts meet the intended responsiveness target.

The README's 250-host starting estimate of 8 vCPU, 16 GB RAM, and a 200 GB SSD
is planning guidance, not a tested remedy. The default server runs one Uvicorn
process; increasing CPU count alone has not been shown to resolve its remaining
processing or concurrency limits. Neither a larger VM nor a different worker
configuration was measured here.

Python 3.11's GIL permits only one thread to execute Python code at once, so
moving work to threads does not guarantee parallel execution of CPU-bound
Python code; this run did not establish the GIL as the bottleneck.
([Python threading documentation](https://docs.python.org/3.11/library/threading.html))
PostgreSQL also relies on the operating system's cache, and its per-operation
memory allowance can multiply across concurrent operations, so the sampled
peaks do not remove the need for memory headroom.
([PostgreSQL 16 resource documentation](https://www.postgresql.org/docs/16/runtime-config-resource.html))

## Regression validation

The final backend suite passed 342 tests, with two PostgreSQL opt-in tests
skipped and 15 warnings, in 183.71 seconds. Those two concurrency tests also
passed separately against PostgreSQL 16. These correctness checks are separate
from the capacity protocol; they do not change the failed 250-host outcome.

## Limits of the conclusion

A seven-minute fresh-database run does not establish long-term history growth,
disk sizing, retention behavior over weeks, browser responsiveness, WAN/TLS
overhead, or availability during failures. The routine-history cleanup needs
its separate retention regressions; a new database does not exercise seven-day
expiry. Production sizing should additionally consider retained data, package
diversity, administrative jobs, concurrent users, and operational headroom.
