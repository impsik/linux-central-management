from __future__ import annotations

from datetime import datetime, timezone

import httpx


def post_teams_message(webhook_url: str, title: str, lines: list[str]) -> None:
    """Send a simple MessageCard payload to Microsoft Teams incoming webhook."""
    if not webhook_url:
        raise ValueError("teams webhook url is not configured")

    text = "\n".join([f"- {x}" for x in (lines or []) if x])
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "themeColor": "0078D7",
        "title": title,
        "text": text,
        "sections": [
            {
                "activityTitle": "Fleet Alert",
                "activitySubtitle": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            }
        ],
    }

    with httpx.Client(timeout=10.0) as client:
        r = client.post(webhook_url, json=payload)
        if r.status_code >= 400:
            raise RuntimeError(f"teams webhook failed ({r.status_code}): {r.text[:300]}")
