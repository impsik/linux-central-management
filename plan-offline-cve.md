# Implementation Plan: Offline CVE Database

To stop the agent from leaking CVE queries to `ubuntu.com`, we will move the lookup logic to the server, which will download the full CVE database daily.

## 1. Database Schema (Server)

We need a table to store the CVE status for all Ubuntu releases.

**New Table:** `cve_definitions`
- `cve_id` (String, PK) - e.g., "CVE-2024-1234"
- `status_data` (JSON) - A mapping of Ubuntu release codenames to status.
  ```json
  {
    "jammy": { "status": "released", "package": "openssl", "details": "..." },
    "noble": { "status": "needs-triage", "package": "openssl" }
  }
  ```
- `last_updated` (DateTime)

## 2. Background Sync Service (Server)

A new service `server/app/services/cve_sync.py` will:
1.  Download the official Ubuntu CVE Tracker JSON: `https://git.launchpad.net/ubuntu-cve-tracker/plain/scripts/cve-tracker` (or use the OVAL files if easier, but the JSON output from the tracker is often used).
    *   *Correction:* Canonical publishes a JSON feed at `https://ubuntu.com/security/cves.json` or we can use the OVAL files per release.
    *   *Best approach:* Use the OVAL files for supported releases (focal, jammy, noble, etc.) because they are machine-readable and contain exact package versions.
    *   URL: `https://security-metadata.canonical.com/oval/com.ubuntu.<release>.cve.oval.xml.bz2`
2.  Parse the XML/JSON.
3.  Upsert into `cve_definitions`.

## 3. API Endpoint (Server)

**GET /api/v1/cve/{cve_id}?distro_codename=jammy**
- Looks up `cve_id` in `cve_definitions`.
- Returns the status for the requested codename.

## 4. Agent Modification

Modify `agent/internal/cve.go`:
- Remove `checkCVEViaUbuntuCom`.
- Add `checkCVEViaFleetServer`.
- It will call `GET <FLEET_SERVER_URL>/api/v1/cve/<CVE>?distro_codename=<CODENAME>`.

## 5. Security & Privacy Benefit

- **Agent** only talks to **Server**.
- **Server** only downloads **bulk data** (all CVEs), never revealing which specific one you care about.

---

**Approval:**
Does this plan sound good? I can start by creating the database migration and the sync service.
