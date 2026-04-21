"""Redis-backed cache for domain check results and DoH prefilter flags."""
from __future__ import annotations

import json

from redis.asyncio import Redis

from .config import settings
from .models import CheckResult, DomainStatus

CACHE_PREFIX = "cache:v1:"
DOH_PREFIX = "doh:v1:"


class ResultCache:
    def __init__(self, redis: Redis) -> None:
        self.redis = redis

    @staticmethod
    def ttl_for(status: DomainStatus) -> int:
        return {
            DomainStatus.FREE: settings.ttl_free,
            DomainStatus.REGISTERED: settings.ttl_registered,
            DomainStatus.PENDING_DELETE: settings.ttl_pending,
            DomainStatus.REDEMPTION_PERIOD: settings.ttl_pending,
            DomainStatus.UNKNOWN: settings.ttl_unknown,
            DomainStatus.ERROR: settings.ttl_error,
            DomainStatus.INVALID: settings.ttl_registered,
        }[status]

    async def get(self, domain: str) -> CheckResult | None:
        raw = await self.redis.get(CACHE_PREFIX + domain)
        if not raw:
            return None
        data = json.loads(raw)
        result = CheckResult.model_validate(data)
        result.cache_hit = True
        return result

    async def set(self, result: CheckResult) -> None:
        ttl = self.ttl_for(result.status)
        result.ttl_seconds = ttl
        payload = result.model_dump(mode="json")
        # Don't persist cache_hit=True — it's per-response.
        payload["cache_hit"] = False
        await self.redis.set(CACHE_PREFIX + result.domain, json.dumps(payload), ex=ttl)

    async def get_doh_flag(self, domain: str) -> str | None:
        raw = await self.redis.get(DOH_PREFIX + domain)
        return raw.decode() if isinstance(raw, bytes) else raw

    async def set_doh_flag(self, domain: str, flag: str) -> None:
        await self.redis.set(DOH_PREFIX + domain, flag, ex=settings.ttl_doh)
