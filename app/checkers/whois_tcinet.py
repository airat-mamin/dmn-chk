"""WHOIS fallback checker against whois.tcinet.ru (TCP/43).

Used only when RDAP is unavailable or rate-limited. tcinet returns a simple
key:value format where 'No entries found' / 'No match' indicates a free domain,
otherwise a 'state:' line lists statuses like 'REGISTERED, DELEGATED, VERIFIED'.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from ..config import settings
from ..models import CheckResult, DomainStatus, Source
from .ratelimit import TokenBucket

_FREE_MARKERS = ("no entries found", "no match", "not found")


def parse_whois(text: str) -> tuple[DomainStatus, dict[str, str]]:
    low = text.lower()
    for marker in _FREE_MARKERS:
        if marker in low:
            return DomainStatus.FREE, {}
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip().lower()] = value.strip()
    state = fields.get("state", "").upper()
    if "PENDING DELETE" in state or "PENDINGDELETE" in state:
        return DomainStatus.PENDING_DELETE, fields
    if "REDEMPTION" in state:
        return DomainStatus.REDEMPTION_PERIOD, fields
    if "REGISTERED" in state or fields.get("registrar") or fields.get("nserver"):
        return DomainStatus.REGISTERED, fields
    return DomainStatus.UNKNOWN, fields


class WhoisChecker:
    def __init__(self) -> None:
        self.bucket = TokenBucket(settings.whois_rps)

    async def check(self, domain: str) -> CheckResult:
        await self.bucket.acquire()
        now = datetime.now(UTC)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(settings.whois_host, settings.whois_port),
                timeout=settings.whois_timeout,
            )
            writer.write((domain + "\r\n").encode("ascii"))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(65536), timeout=settings.whois_timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (TimeoutError, OSError) as exc:
            return CheckResult(
                domain=domain,
                status=DomainStatus.ERROR,
                source=Source.WHOIS,
                checked_at=now,
                confidence=0.0,
                metadata={"reason": f"whois_exception:{type(exc).__name__}"},
            )
        text = data.decode("utf-8", errors="replace")
        status, fields = parse_whois(text)
        confidence = 0.95 if status != DomainStatus.UNKNOWN else 0.3
        meta = {k: v for k, v in fields.items() if k in {"state", "registrar", "nserver", "paid-till"}}
        return CheckResult(
            domain=domain,
            status=status,
            source=Source.WHOIS,
            checked_at=now,
            confidence=confidence,
            metadata=meta,
        )
