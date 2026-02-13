from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException

from ..config import settings

BASE_DIR = Path(__file__).resolve().parents[2]

_ansible_setting = getattr(settings, "ansible_dir", "ansible")
ANSIBLE_DIR = (Path(_ansible_setting) if Path(_ansible_setting).is_absolute() else (BASE_DIR / _ansible_setting)).resolve()
_ansible_log_setting = getattr(settings, "ansible_log_dir", "ansible/logs")
ANSIBLE_LOG_DIR = (Path(_ansible_log_setting) if Path(_ansible_log_setting).is_absolute() else (BASE_DIR / _ansible_log_setting)).resolve()


def _parse_playbook_prompts(playbook_path: Path) -> list[dict[str, Any]]:
    prompts: list[dict[str, Any]] = []
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(playbook_path.read_text(encoding="utf-8"))
        plays = data if isinstance(data, list) else [data]
        for play in plays:
            if not isinstance(play, dict):
                continue
            vars_prompt = play.get("vars_prompt") or []
            for item in vars_prompt:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                prompt = str(item.get("prompt") or name).strip()
                private = bool(item.get("private", False))
                prompts.append({"name": name, "prompt": prompt, "private": private})
        return prompts
    except Exception:
        pass

    # Very rough fallback parser
    text = playbook_path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    in_block = False
    block_indent = None
    current: dict[str, Any] | None = None
    for line in lines:
        raw = line.rstrip("\n")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if stripped.startswith("vars_prompt:"):
            in_block = True
            block_indent = indent
            continue
        if not in_block:
            continue
        if block_indent is not None and indent <= block_indent and not stripped.startswith("-"):
            break
        if stripped.startswith("- "):
            if current:
                prompts.append(current)
            current = {}
            key_val = stripped[2:].split(":", 1)
            if len(key_val) == 2:
                key = key_val[0].strip()
                val = key_val[1].strip().strip('"\'')
                if key:
                    current[key] = val
            continue
        if current is None:
            current = {}
        if ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip().strip('"\'')
            if key:
                if key == "private":
                    current[key] = val.lower() in ("true", "yes", "1")
                else:
                    current[key] = val
    if current:
        prompts.append(current)

    cleaned: list[dict[str, Any]] = []
    for item in prompts:
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        prompt = str(item.get("prompt") or name).strip()
        private = bool(item.get("private", False))
        cleaned.append({"name": name, "prompt": prompt, "private": private})
    return cleaned


def list_playbooks() -> list[dict[str, Any]]:
    if not ANSIBLE_DIR.exists():
        return []
    playbooks: list[dict[str, Any]] = []
    for path in sorted(ANSIBLE_DIR.glob("*.yml")) + sorted(ANSIBLE_DIR.glob("*.yaml")):
        if not path.is_file():
            continue
        if path.name in {"inventory.yml", "inventory.yaml"}:
            continue
        playbooks.append({"name": path.name, "prompts": _parse_playbook_prompts(path)})
    return playbooks


def redact_extra_vars(playbook: str, extra_vars: dict[str, Any] | None) -> dict[str, Any]:
    playbooks = {p["name"]: p for p in list_playbooks()}
    if playbook not in playbooks:
        return {}
    private_names = {p.get("name") for p in playbooks[playbook].get("prompts", []) if p.get("private")}
    extra_vars = extra_vars or {}

    redacted: dict[str, Any] = {}
    for k, v in extra_vars.items():
        if k in private_names:
            redacted[k] = "REDACTED"
        else:
            redacted[k] = v
    return redacted


def run_playbook(
    playbook: str,
    agent_ids: list[str],
    extra_vars: dict[str, Any] | None,
    *,
    inventory_hosts: list[str] | None = None,
) -> dict[str, Any]:
    playbooks = {p["name"]: p for p in list_playbooks()}
    if playbook not in playbooks:
        raise HTTPException(404, "Playbook not found")
    if not agent_ids:
        raise HTTPException(400, "agent_ids is required")

    playbook_path = ANSIBLE_DIR / playbook
    if not playbook_path.exists():
        raise HTTPException(404, "Playbook not found")

    extra_vars = extra_vars or {}

    prompt_names = {p.get("name") for p in playbooks[playbook].get("prompts", []) if p.get("name")}
    private_names = {p.get("name") for p in playbooks[playbook].get("prompts", []) if p.get("private")}

    # Auto-fill common target variables based on the selected agents.
    # Legacy playbooks use vars_prompt name "server"; newer ones use "target_hosts".
    # Use resolved targets (inventory hosts) for defaults presented to playbooks.
    inv_hosts = inventory_hosts or agent_ids

    if ("server" in prompt_names) or ("server" in extra_vars):
        extra_vars["server"] = " ".join(inv_hosts)

    # Only set target_hosts if it exists as a prompt and the user didn't provide anything.
    # (If they typed a group like "all" or "web", respect that.)
    if ("target_hosts" in prompt_names) and (not str(extra_vars.get("target_hosts", "")).strip()):
        extra_vars["target_hosts"] = " ".join(inv_hosts)

    # Use resolved connection targets (IP/FQDN) if provided; fall back to agent ids.
    inv_hosts = inventory_hosts or agent_ids
    inventory = ",".join([h for h in inv_hosts if str(h).strip()]) + ","

    def _sanitize_log_value(key: str, value: Any) -> Any:
        if key in private_names:
            return "REDACTED"
        return value

    log_dir = ANSIBLE_LOG_DIR
    log_dir_ok = True
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        log_dir_ok = False

    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", Path(playbook).stem).strip("_") or "playbook"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    import uuid

    run_id = uuid.uuid4().hex[:8]
    log_name = f"{slug}-{timestamp}-{run_id}.log"
    log_path = (log_dir / log_name) if log_dir_ok else None

    ssh_user = (getattr(settings, "ansible_ssh_user", None) or "ubuntu").strip() or "ubuntu"
    key_file = (getattr(settings, "ansible_private_key_file", None) or "").strip() or None

    # Best-effort default key selection inside container
    if not key_file:
        for candidate in ("/root/.ssh/id_ed25519", "/root/.ssh/id_rsa"):
            try:
                if Path(candidate).exists():
                    key_file = candidate
                    break
            except Exception:
                pass

    cmd = ["ansible-playbook", str(playbook_path), "-i", inventory, "-u", ssh_user, "-e", json.dumps(extra_vars)]
    if key_file:
        cmd += ["--private-key", key_file]

    try:
        result = subprocess.run(cmd, cwd=str(ANSIBLE_DIR), capture_output=True, text=True, timeout=600)
        rc = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except FileNotFoundError as e:
        rc = 127
        stdout = ""
        stderr = str(e)
    except subprocess.TimeoutExpired:
        rc = 124
        stdout = ""
        stderr = "ansible-playbook timed out"
    except Exception as e:
        rc = 1
        stdout = ""
        stderr = str(e)

    safe_vars = {k: _sanitize_log_value(k, v) for k, v in extra_vars.items()}
    log_lines = [
        f"Playbook: {playbook}",
        f"Inventory: {inventory}",
        f"Extra vars: {json.dumps(safe_vars, ensure_ascii=True)}",
        f"Started: {timestamp}",
        f"Return code: {rc}",
        "---- stdout ----",
        stdout or "",
        "---- stderr ----",
        stderr or "",
    ]

    log_written = False
    if log_path is not None:
        try:
            log_path.write_text("\n".join(log_lines), encoding="utf-8", errors="ignore")
            log_written = True
        except Exception:
            log_written = False

    return {
        "ok": rc == 0,
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr,
        "log_name": log_name if log_written else None,
        "log_path": str(log_path) if (log_written and log_path is not None) else None,
    }


def list_logs(limit: int = 50) -> list[dict[str, Any]]:
    if limit < 1:
        limit = 1
    if limit > 200:
        limit = 200
    if not ANSIBLE_LOG_DIR.exists():
        return []

    items: list[dict[str, Any]] = []
    for path in ANSIBLE_LOG_DIR.glob("*.log"):
        try:
            stat = path.stat()
        except OSError:
            continue
        items.append({"name": path.name, "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(), "size": stat.st_size})
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items[:limit]


def get_log_file(log_name: str) -> str:
    if not log_name or log_name != Path(log_name).name or "/" in log_name or "\\" in log_name:
        raise HTTPException(400, "Invalid log name")
    log_path = ANSIBLE_LOG_DIR / log_name
    if not log_path.exists():
        raise HTTPException(404, "Log not found")
    return str(log_path)
