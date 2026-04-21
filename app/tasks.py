"""Batch task manager backed by Redis.

Schema:
  task:{id}:meta    -> hash {total, processed, state, created_at, updated_at}
  task:{id}:results -> list of CheckResult JSON payloads (RPUSH)
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime

import structlog
from redis.asyncio import Redis

from .config import settings
from .models import CheckResult, TaskStatus
from .pipeline import Pipeline

log = structlog.get_logger(__name__)

TASK_META_PREFIX = "task:v1:meta:"
TASK_RESULTS_PREFIX = "task:v1:results:"
TASK_TTL = 7 * 86_400  # keep task records for a week


class TaskManager:
    def __init__(self, redis: Redis, pipeline: Pipeline) -> None:
        self.redis = redis
        self.pipeline = pipeline

    async def create(self, domains: list[str]) -> str:
        task_id = uuid.uuid4().hex
        now = datetime.now(UTC).isoformat()
        meta = {
            "total": str(len(domains)),
            "processed": "0",
            "state": "running",
            "created_at": now,
            "updated_at": now,
        }
        await self.redis.hset(TASK_META_PREFIX + task_id, mapping=meta)
        await self.redis.expire(TASK_META_PREFIX + task_id, TASK_TTL)
        asyncio.create_task(self._run(task_id, domains))
        return task_id

    async def _run(self, task_id: str, domains: list[str]) -> None:
        sem = asyncio.Semaphore(settings.worker_concurrency)

        async def worker(d: str) -> None:
            async with sem:
                try:
                    result = await self.pipeline.check(d)
                except Exception as exc:  # noqa: BLE001
                    log.exception("task_domain_failed", task_id=task_id, domain=d, error=str(exc))
                    result = CheckResult(
                        domain=d,
                        status="error",  # type: ignore[arg-type]
                        source="whois",  # type: ignore[arg-type]
                        checked_at=datetime.now(UTC),
                        metadata={"reason": f"pipeline_exception:{type(exc).__name__}"},
                    )
                await self._record(task_id, result)

        try:
            await asyncio.gather(*(worker(d) for d in domains))
            await self.redis.hset(
                TASK_META_PREFIX + task_id,
                mapping={"state": "done", "updated_at": datetime.now(UTC).isoformat()},
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("task_failed", task_id=task_id, error=str(exc))
            await self.redis.hset(
                TASK_META_PREFIX + task_id,
                mapping={"state": "failed", "updated_at": datetime.now(UTC).isoformat()},
            )

    async def _record(self, task_id: str, result: CheckResult) -> None:
        payload = json.dumps(result.model_dump(mode="json"))
        pipe = self.redis.pipeline()
        pipe.rpush(TASK_RESULTS_PREFIX + task_id, payload)
        pipe.expire(TASK_RESULTS_PREFIX + task_id, TASK_TTL)
        pipe.hincrby(TASK_META_PREFIX + task_id, "processed", 1)
        pipe.hset(
            TASK_META_PREFIX + task_id, "updated_at", datetime.now(UTC).isoformat()
        )
        await pipe.execute()

    async def status(self, task_id: str) -> TaskStatus | None:
        meta = await self.redis.hgetall(TASK_META_PREFIX + task_id)
        if not meta:
            return None
        m = {
            (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in meta.items()
        }
        total = int(m.get("total", "0"))
        processed = int(m.get("processed", "0"))
        return TaskStatus(
            task_id=task_id,
            state=m.get("state", "unknown"),
            total=total,
            processed=processed,
            remaining=max(total - processed, 0),
            created_at=datetime.fromisoformat(m["created_at"]),
            updated_at=datetime.fromisoformat(m["updated_at"]),
        )

    async def results(
        self, task_id: str, offset: int = 0, limit: int = 500
    ) -> tuple[list[CheckResult], int | None]:
        limit = max(1, min(limit, 2000))
        end = offset + limit - 1
        raw = await self.redis.lrange(TASK_RESULTS_PREFIX + task_id, offset, end)
        items = [CheckResult.model_validate(json.loads(r)) for r in raw]
        total_stored = await self.redis.llen(TASK_RESULTS_PREFIX + task_id)
        next_offset: int | None = offset + len(items) if offset + len(items) < total_stored else None
        return items, next_offset
