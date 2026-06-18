#!/usr/bin/env python3
"""Shared cached HTTP session helpers for trusted network lookups.

The `nixprs` report-phase enrichment intentionally reuses sbomnix's persistent
HTTP cache path so the action's existing cache restore/save logic also applies
to flakevuln's GitHub API queries.
"""

import os
import tempfile
from collections.abc import Collection
from getpass import getuser
from pathlib import Path
from typing import Any

from requests import Session
from requests.adapters import HTTPAdapter
from requests_cache import CacheMixin
from requests_ratelimiter import LimiterMixin
from urllib3.util.retry import Retry

DEFAULT_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


class CachedLimiterSession(CacheMixin, LimiterMixin, Session):  # pyright: ignore[reportIncompatibleMethodOverride]
    """Requests session with persistent caching and rate limiting."""


def _shared_cache_root():
    """Return the shared sbomnix-compatible cache root."""
    candidates = []
    xdg_cache_home = os.environ.get("XDG_CACHE_HOME")
    if xdg_cache_home:
        candidates.append(lambda: Path(xdg_cache_home).expanduser() / "sbomnix")
    candidates.append(lambda: Path.home() / ".cache" / "sbomnix")
    candidates.append(
        lambda: Path(tempfile.gettempdir()) / f"{getuser()}_sbomnix_cache"
    )
    last_error = None
    for get_path in candidates:
        try:
            path = get_path()
            path.mkdir(parents=True, exist_ok=True)
            if not os.access(path, os.W_OK | os.X_OK):
                raise PermissionError(f"Cache root is not writable: {path}")
            return path
        except (OSError, RuntimeError) as error:
            last_error = error
    if last_error is not None:
        raise last_error
    raise RuntimeError("Failed determining shared HTTP cache root")


def shared_http_cache_name():
    """Return the persistent requests-cache base path."""
    return _shared_cache_root() / "http_cache"


def mount_retries(
    session: Session,
    *,
    allowed_methods: Collection[str] = frozenset(("GET", "HEAD")),
) -> Session:
    """Attach a retrying adapter to a requests session."""
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=1,
        status_forcelist=DEFAULT_RETRY_STATUS_CODES,
        allowed_methods=allowed_methods,
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def create_cached_limited_session(  # noqa: PLR0913
    *,
    per_second: int | None = None,
    per_minute: int | None = None,
    expire_after: int | None = None,
    user_agent: str | None = None,
    allowed_methods: Collection[str] = frozenset(("GET", "HEAD")),
    cache_name: str | None = None,
) -> Session:
    """Create a cached, rate-limited session with retry policy attached."""
    kwargs: dict[str, Any] = {}
    if per_second is not None:
        kwargs["per_second"] = per_second
    if per_minute is not None:
        kwargs["per_minute"] = per_minute
    if expire_after is not None:
        kwargs["expire_after"] = expire_after
    if cache_name is None:
        cache_name = str(shared_http_cache_name())
    kwargs["cache_name"] = cache_name
    session = CachedLimiterSession(**kwargs)
    mount_retries(session, allowed_methods=allowed_methods)
    if user_agent:
        session.headers.update({"User-Agent": user_agent})
    return session
