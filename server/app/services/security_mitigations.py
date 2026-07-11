from __future__ import annotations


MITIGATIONS: dict[str, dict] = {
    "linux-rds-disable": {
        "id": "linux-rds-disable",
        "version": 1,
        "name": "Disable the Linux RDS kernel module",
        "summary": "Assess exposure to RDS kernel module vulnerabilities such as PinTheft.",
        "severity": "high",
        "supported_os": ["debian", "ubuntu", "rhel", "rocky", "almalinux"],
        "assessment": {
            "checks": [
                "Whether the rds module is available and currently loaded",
                "Whether modprobe is configured to prevent loading rds",
                "Whether rds is configured for boot-time loading",
            ]
        },
        "apply_available": True,
        "approval_required": True,
        "reboot_required": "when_loaded",
        "references": [],
    }
}


def mitigation_catalog() -> list[dict]:
    return [dict(item) for item in MITIGATIONS.values()]


def get_mitigation(mitigation_id: str) -> dict | None:
    item = MITIGATIONS.get(str(mitigation_id or "").strip())
    return dict(item) if item else None
