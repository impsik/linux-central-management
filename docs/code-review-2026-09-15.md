# Reliability review — 2026-09-15

The review covered the Python API and job lifecycle, Go agent command handlers,
firewall UI flows, installer/agent updater, scheduled work, and CI regression
coverage. It focused on reproducible failures and privileged operations rather
than cosmetic refactoring.

## Fixed

| Area | Failure | Result |
| --- | --- | --- |
| Inactive UFW | A disabled firewall appeared to have no rules, preventing informed removals | Saved user rules remain visible and can be removed by verified exact identity, including routed and quoted-profile rules |
| Firewalld rules | Adding rules could reload away unrelated runtime rules; source-scoped allows lost their source restriction | Changes address runtime and permanent stores directly, verify their result, and retain source restrictions |
| Firewalld inspection | Read errors could produce a misleading partial or empty ruleset | Incomplete reads fail explicitly; saved/runtime scope and default-zone coverage are shown |
| Host firewall view | Removal reconstructed an allow rule from fields instead of removing the displayed deny/source-specific rule | Host and fleet views share durable job handling and exact rule deletion |
| Firewall feedback | Refresh cleared selected hosts and operations concealed unchanged/off-state results | Selections survive refresh, per-host results explain actual changes, and duplicate host-view submissions are blocked |
| Agent job events | A delayed message could reopen or overwrite an already completed attempt | Row locking and terminal-state checks preserve the first terminal result; a new nonce still permits deliberate retry |
| Scheduled jobs | Two workers could dispatch the same scheduled operation from stale ORM state | A locked, refreshed claim checks both status and due time before dispatching |
| Async job waits | Synchronous database polling blocked the API event loop | Each polling query uses a worker thread and private DB session |
| Agent updater | Rollback could restore an already broken on-disk replacement while the old executable was still running | The previous binary is copied from the actual running executable before replacement |
| User management | API error text was inserted into HTML without escaping | Error messages render as text |
| Account commands | Option-like usernames reached privileged commands; a generated password appeared in a shell command argument | Unsafe usernames and root account operations are rejected at the agent boundary; the generated password reaches chpasswd over stdin |

## Verification

- Full Python suite: 419 passed; two PostgreSQL-only tests skipped in this run.
- Separate migrated, disposable PostgreSQL 16 database: all three concurrency
  tests passed, including simultaneous scheduler workers.
- Frontend suite: 149 passed.
- Agent: `go test ./...` and `go vet ./...` passed.
- Shared version consistency and template status-color checks passed.
- Browser exercise of the real fleet firewall HTML/JS with isolated API fixtures:
  saved rules while off, selected removals across two hosts, preserved selections,
  enable/disable state changes, and adding a port while off.

The browser fixture and agent command fakes do not verify packet filtering on a
real node. Direct node SSH verification was unavailable in this environment;
no live node firewall rules were changed. Firewalld's view covers the default
zone's ports, services and rich rules, not a complete effective network policy.
Both firewall managers installed and inactive remain an explicit configuration
error rather than selecting one implicitly. See [Firewall management](firewall-management.md)
for update requirements and operating behavior.
