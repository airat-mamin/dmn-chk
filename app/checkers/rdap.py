"""RDAP checker against rdap.nic.ru."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx

from ..config import settings
from ..models import CheckResult, DomainStatus, Source
from .ratelimit import TokenBucket

# RDAP 'status' vocabulary we care about for .ru lifecycle.
_PENDING_DELETE_STATUSES = {"pending delete", "redemption period"}


def parse_rdap_status(body: dict[str, Any]) -> DomainStatus:
    statuses = {s.strip().lower() for s in (body.get("status") or [])}
    if "pending delete" in statuses:
        return DomainStatus.PENDING_DELETE
    if "redemption period" in statuses:
        return DomainStatus.REDEMPTION_PERIOD
    if statuses & _PENDING_DELETE_STATUSES:
        return DomainStatus.PENDING_DELETE
    return DomainStatus.REGISTERED


class RdapChecker:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.bucket = TokenBucket(settings.rdap_rps)

    async def check(self, domain: str) -> CheckResult | None:
        """Return CheckResult or None if RDAP is unusable (retry next source)."""
        await self.bucket.acquire()
        url = f"{settings.rdap_url.rstrip('/')}/{domain}"
        headers = {"accept": "application/rdap+json"}
        now = datetime.now(UTC)
        try:
            r = await self.client.get(url, headers=headers, timeout=settings.http_timeout)
        except (httpx.HTTPError, OSError) as exc:
            return _error_result(domain, f"rdap_exception:{type(exc).__name__}")

        if r.status_code == 404:
            return CheckResult(
                domain=domain,
                status=DomainStatus.FREE,
                source=Source.RDAP,
                checked_at=now,
                confidence=0.98,
                metadata={"http_status": 404},
            )
        if r.status_code == 429 or 500 <= r.status_code < 600:
            # Signal "unusable" so pipeline tries next source.
            return None
        if r.status_code != 200:
            return _error_result(domain, f"rdap_http_{r.status_code}")
        try:
            body = r.json()
        except ValueError:
            return _error_result(domain, "rdap_invalid_json")
        status = parse_rdap_status(body)
        return CheckResult(
            domain=domain,
            status=status,
            source=Source.RDAP,
            checked_at=now,
            confidence=0.98,
            metadata={
                "http_status": 200,
                "rdap_status": body.get("status") or [],
            },
        )


def _error_result(domain: str, reason: str) -> CheckResult:
    return CheckResult(
        domain=domain,
        status=DomainStatus.ERROR,
        source=Source.RDAP,
        checked_at=datetime.now(UTC),
        confidence=0.0,
        metadata={"reason": reason},
    )
