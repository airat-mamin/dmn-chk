"""DoH prefilter: NXDOMAIN heuristic via Cloudflare DNS-over-HTTPS.

IMPORTANT: DoH results are an internal heuristic only. They are never returned
to the client as a final status — the pipeline always confirms 'free' via
RDAP/WHOIS before responding.
"""
from __future__ import annotations

from enum import Enum

import httpx

from ..config import settings
from .ratelimit import TokenBucket


class DohFlag(str, Enum):
    NXDOMAIN = "nxdomain"       # RCODE 3 — strong hint domain is unregistered
    HAS_RECORDS = "has_records"  # NOERROR + answers
    NO_RECORDS = "no_records"    # NOERROR without answers (NS-only, etc.)
    ERROR = "error"


class DohChecker:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.bucket = TokenBucket(settings.doh_rps)

    async def check(self, domain: str) -> DohFlag:
        await self.bucket.acquire()
        params = {"name": domain, "type": "A"}
        headers = {"accept": "application/dns-json"}
        try:
            r = await self.client.get(
                settings.doh_url, params=params, headers=headers, timeout=settings.http_timeout
            )
        except (httpx.HTTPError, OSError):
            return DohFlag.ERROR
        if r.status_code != 200:
            return DohFlag.ERROR
        try:
            data = r.json()
        except ValueError:
            return DohFlag.ERROR
        status = data.get("Status")
        if status == 3:
            return DohFlag.NXDOMAIN
        if status == 0:
            return DohFlag.HAS_RECORDS if data.get("Answer") else DohFlag.NO_RECORDS
        return DohFlag.ERROR
