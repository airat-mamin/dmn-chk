"""API-level smoke test using a fake pipeline and fakeredis.

Verifies the happy path of POST /check/batch -> GET /tasks/{id} -> GET /results/{id}
without hitting the real internet.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app import main as main_mod
from app.models import CheckResult, DomainStatus, Source
from app.tasks import TaskManager


class FakePipeline:
    async def check(self, domain: str, *, fresh: bool = False) -> CheckResult:
        status = DomainStatus.FREE if domain.startswith("free") else DomainStatus.REGISTERED
        return CheckResult(
            domain=domain,
            status=status,
            source=Source.RDAP,
            checked_at=datetime.now(UTC),
            confidence=0.98,
        )


@pytest.fixture
def client(monkeypatch):
    pytest.importorskip("fakeredis")
    from fakeredis import aioredis as fake_aioredis

    fake_redis = fake_aioredis.FakeRedis()

    async def _patched_lifespan(app):
        app.state.redis = fake_redis
        app.state.http = None
        app.state.pipeline = FakePipeline()
        app.state.cache = None
        app.state.tasks = TaskManager(fake_redis, app.state.pipeline)
        yield
        await fake_redis.aclose()

    # Replace lifespan with patched version
    from contextlib import asynccontextmanager

    main_mod.app.router.lifespan_context = asynccontextmanager(_patched_lifespan)
    with TestClient(main_mod.app) as c:
        yield c


def test_batch_happy_path(client):
    r = client.post(
        "/check/batch",
        json={"domains": ["free-one.ru", "busy-two.ru", "not-a-domain", "free-one.ru"]},
    )
    assert r.status_code == 202, r.text
    data = r.json()
    assert data["accepted"] == 2  # deduped
    assert data["rejected"] == 1
    task_id = data["task_id"]

    # Wait for background task to complete
    for _ in range(50):
        s = client.get(f"/tasks/{task_id}").json()
        if s["state"] == "done":
            break
        asyncio.run(asyncio.sleep(0.05))
    else:
        raise AssertionError(f"task did not complete: {s}")

    res = client.get(f"/results/{task_id}").json()
    assert res["processed"] == 2
    statuses = {item["domain"]: item["status"] for item in res["items"]}
    assert statuses == {"free-one.ru": "free", "busy-two.ru": "registered"}


def test_domain_validation_error(client):
    r = client.get("/domain/example.com")
    assert r.status_code == 400
    assert "invalid_domain" in r.json()["detail"]


def test_batch_rejects_empty(client):
    r = client.post("/check/batch", json={"domains": ["bad", "also.bad"]})
    assert r.status_code == 400
