"""Orchestrator: DoH prefilter -> RDAP -> WHOIS fallback with cache and singleflight.

Flow per domain:
  1. Cache hit -> return.
  2. Singleflight: if another coroutine is already checking this domain, await it.
  3. DoH prefilter (internal flag only, never returned as final status).
  4. RDAP. If returns a definite result -> done. If returns None (429/5xx) -> fall
     through to WHOIS.
  5. WHOIS fallback (rate-limited).
  6. Cache the final result with TTL keyed to the status.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx
import structlog

from .cache import ResultCache
from .checkers.doh import DohChecker, DohFlag
from .checkers.rdap import RdapChecker
from .checkers.whois_tcinet import WhoisChecker
from .models import CheckResult, DomainStatus, Source

log = structlog.get_logger(__name__)


class Pipeline:
    def __init__(
        self,
        client: httpx.AsyncClient,
        cache: ResultCache,
    ) -> None:
        self.cache = cache
        self.doh = DohChecker(client)
        self.rdap = RdapChecker(client)
        self.whois = WhoisChecker()
        self._inflight: dict[str, asyncio.Future[CheckResult]] = {}
        self._inflight_lock = asyncio.Lock()

    async def check(self, domain: str, *, fresh: bool = False) -> CheckResult:
        if not fresh:
            cached = await self.cache.get(domain)
            if cached is not None:
                # cache.get already sets cache_hit=True; keep original `source`
                # so callers can see who actually made the decision.
                return cached

        async with self._inflight_lock:
            fut = self._inflight.get(domain)
            if fut is None:
                fut = asyncio.get_running_loop().create_future()
                self._inflight[domain] = fut
                owner = True
            else:
                owner = False

        if not owner:
            return await fut

        try:
            result = await self._run_chain(domain)
            await self.cache.set(result)
            fut.set_result(result)
            return result
        except Exception as exc:  # noqa: BLE001
            fut.set_exception(exc)
            raise
        finally:
            async with self._inflight_lock:
                self._inflight.pop(domain, None)

    async def _run_chain(self, domain: str) -> CheckResult:
        now = datetime.now(UTC)

        # Stage 1: DoH prefilter (heuristic only).
        doh_flag = DohFlag.ERROR
        cached_flag = await self.cache.get_doh_flag(domain)
        if cached_flag is not None:
            try:
                doh_flag = DohFlag(cached_flag)
            except ValueError:
                doh_flag = DohFlag.ERROR
        else:
            doh_flag = await self.doh.check(domain)
            await self.cache.set_doh_flag(domain, doh_flag.value)

        # Stage 2: RDAP (authoritative for .ru).
        rdap_result = await self.rdap.check(domain)
        if rdap_result is not None and rdap_result.status != DomainStatus.ERROR:
            rdap_result.metadata["doh_flag"] = doh_flag.value
            return rdap_result

        # Stage 3: WHOIS fallback.
        log.info("rdap_fallback_to_whois", domain=domain, rdap=rdap_result is None)
        whois_result = await self.whois.check(domain)
        whois_result.metadata["doh_flag"] = doh_flag.value
        if rdap_result is not None:
            whois_result.metadata["rdap_reason"] = rdap_result.metadata.get("reason")

        if whois_result.status != DomainStatus.ERROR:
            return whois_result

        # Both failed: return an error result marked with unknown.
        return CheckResult(
            domain=domain,
            status=DomainStatus.UNKNOWN,
            source=Source.WHOIS,
            checked_at=now,
            confidence=0.0,
            metadata={
                "doh_flag": doh_flag.value,
                "rdap_reason": (rdap_result.metadata.get("reason") if rdap_result else "rdap_unusable"),
                "whois_reason": whois_result.metadata.get("reason"),
            },
        )
