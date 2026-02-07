from __future__ import annotations

from fastapi import Request


def get_client_ip(request: Request) -> str | None:
    """Extract client IP address from request, handling common proxy headers."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    if request.client:
        return request.client.host

    return None
