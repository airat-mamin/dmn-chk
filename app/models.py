from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DomainStatus(str, Enum):
    FREE = "free"
    REGISTERED = "registered"
    PENDING_DELETE = "pending_delete"
    REDEMPTION_PERIOD = "redemption_period"
    UNKNOWN = "unknown"
    ERROR = "error"
    INVALID = "invalid"


class Source(str, Enum):
    DOH = "doh"
    RDAP = "rdap"
    WHOIS = "whois"
    CACHE = "cache"
    VALIDATOR = "validator"


class CheckResult(BaseModel):
    domain: str
    status: DomainStatus
    source: Source
    checked_at: datetime
    cache_hit: bool = False
    ttl_seconds: int = 0
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class BatchRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1)


class BatchAccepted(BaseModel):
    task_id: str
    accepted: int
    rejected: int
    rejected_samples: list[str] = Field(default_factory=list)


class TaskStatus(BaseModel):
    task_id: str
    state: str
    total: int
    processed: int
    remaining: int
    created_at: datetime
    updated_at: datetime


class BatchResults(BaseModel):
    task_id: str
    total: int
    processed: int
    items: list[CheckResult]
    next_offset: int | None = None
