# Linux Central Management development

[Back to the project overview](../README.md)

The backend lives in `server/`, the Go agent in `agent/`, deployment files in
`deploy/`, and Ansible playbooks in `ansible/`. The web UI uses HTML, CSS, and
JavaScript templates in `server/app/templates/`.
Agents use HTTPS requests and long polling; this repository does not use gRPC
or generated Protocol Buffer sources.

### Release versions

Update the root `VERSION` file, then run `python3 scripts/sync-version.py`.
This generates the server and agent version constants; commit both generated
files with `VERSION`. CI runs `python3 scripts/sync-version.py --check` to reject
missing or inconsistent versions. Ordinary Go and Docker builds include these
constants without additional build flags.

The UI footer shows the server version. Each host reports its own installed
agent version, so existing agents retain their previous number until their
binary is upgraded. Run `sudo /opt/fleet-agent/fleet-agent --version` on an installed
host to inspect its binary without starting the service or connecting to the Master.

To run the tests from a development checkout, use Python 3.12 (the backend CI
version), Node.js 22, and a Go toolchain compatible with `agent/go.mod`:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r server/requirements.txt
python -m pytest server/tests -q

npm ci
npm run test:frontend

(cd agent && go test ./...)
```

Use a separate development checkout for testing. Deployment and host-attachment
scripts are intended for actual administration and require elevated privileges.
