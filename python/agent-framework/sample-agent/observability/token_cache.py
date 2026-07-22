# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Simple in-memory token cache for Agent 365 observability S2S tokens."""

from datetime import datetime, timedelta, timezone
from threading import Lock

_CACHE: dict[str, tuple[str, datetime]] = {}
_CACHE_LOCK = Lock()
_EXPIRY_BUFFER = timedelta(minutes=5)


def _cache_key(agent_id: str, tenant_id: str) -> str:
    return f"{agent_id}:{tenant_id}"


def cache_token(
    agent_id: str,
    tenant_id: str,
    token: str,
    expires_in: timedelta = timedelta(hours=1),
) -> None:
    """Cache an observability token for a specific agent/tenant pair."""
    expires_at = datetime.now(timezone.utc) + expires_in
    with _CACHE_LOCK:
        _CACHE[_cache_key(agent_id, tenant_id)] = (token, expires_at)


def get_cached_token(agent_id: str, tenant_id: str) -> str | None:
    """Return a valid cached token or None when missing/expired."""
    with _CACHE_LOCK:
        entry = _CACHE.get(_cache_key(agent_id, tenant_id))
        if entry is None:
            return None

        token, expires_at = entry
        if datetime.now(timezone.utc) + _EXPIRY_BUFFER >= expires_at:
            del _CACHE[_cache_key(agent_id, tenant_id)]
            return None

        return token

