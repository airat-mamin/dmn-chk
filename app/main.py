"""FastAPI entrypoint."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
import structlog
from fastapi import Depends, FastAPI, HTTPException, Query
from redis.asyncio import Redis

from .cache import ResultCache
from .config import settings
from .models import BatchAccepted, BatchRequest, BatchResults, CheckResult, TaskStatus
from .pipeline import Pipeline
from .tasks import TaskManager
from .validator import DomainValidationError, validate_ru_domain


def _configure_logging() -> None:
    logging.basicConfig(level=settings.log_level.upper(), format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    app.state.redis = Redis.from_url(settings.redis_url)
    app.state.http = httpx.AsyncClient(http2=False, timeout=settings.http_timeout)
    app.state.cache = ResultCache(app.state.redis)
    app.state.pipeline = Pipeline(app.state.http, app.state.cache)
    app.state.tasks = TaskManager(app.state.redis, app.state.pipeline)
    try:
        yield
    finally:
        await app.state.http.aclose()
        await app.state.redis.aclose()


app = FastAPI(
    title="ru-domain-checker",
    version="0.1.0",
    description="Mass .ru domain availability checker (DoH prefilter -> RDAP -> WHOIS fallback).",
    lifespan=lifespan,
)


def get_pipeline() -> Pipeline:
    return app.state.pipeline


def get_tasks() -> TaskManager:
    return app.state.tasks


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    try:
        await asyncio.wait_for(app.state.redis.ping(), timeout=1.0)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"redis_unreachable:{exc}") from exc
    return {"status": "ok"}


@app.get("/domain/{name}", response_model=CheckResult)
async def check_domain(
    name: str,
    fresh: Annotated[bool, Query(description="Bypass cache and force a fresh check")] = False,
    pipeline: Pipeline = Depends(get_pipeline),
) -> CheckResult:
    try:
        canonical = validate_ru_domain(name)
    except DomainValidationError as exc:
        raise HTTPException(status_code=400, detail=f"invalid_domain:{exc}") from exc
    return await pipeline.check(canonical, fresh=fresh)


@app.post("/check/batch", response_model=BatchAccepted, status_code=202)
async def check_batch(
    req: BatchRequest, tasks: TaskManager = Depends(get_tasks)
) -> BatchAccepted:
    if len(req.domains) > settings.batch_max_size:
        raise HTTPException(
            status_code=413,
            detail=f"batch too large (max {settings.batch_max_size})",
        )
    accepted: list[str] = []
    rejected: list[str] = []
    seen: set[str] = set()
    for raw in req.domains:
        try:
            c = validate_ru_domain(raw)
        except DomainValidationError:
            rejected.append(raw)
            continue
        if c in seen:
            continue
        seen.add(c)
        accepted.append(c)
    if not accepted:
        raise HTTPException(status_code=400, detail="no valid .ru domains in batch")
    task_id = await tasks.create(accepted)
    return BatchAccepted(
        task_id=task_id,
        accepted=len(accepted),
        rejected=len(rejected),
        rejected_samples=rejected[:20],
    )


@app.get("/tasks/{task_id}", response_model=TaskStatus)
async def task_status(task_id: str, tasks: TaskManager = Depends(get_tasks)) -> TaskStatus:
    status = await tasks.status(task_id)
    if status is None:
        raise HTTPException(status_code=404, detail="task not found")
    return status


@app.get("/results/{task_id}", response_model=BatchResults)
async def task_results(
    task_id: str,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    tasks: TaskManager = Depends(get_tasks),
) -> BatchResults:
    status = await tasks.status(task_id)
    if status is None:
        raise HTTPException(status_code=404, detail="task not found")
    items, next_offset = await tasks.results(task_id, offset=offset, limit=limit)
    return BatchResults(
        task_id=task_id,
        total=status.total,
        processed=status.processed,
        items=items,
        next_offset=next_offset,
    )
