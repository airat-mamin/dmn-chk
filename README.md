# ru-domain-checker

Минимальный MVP сервиса массовой проверки доступности `.ru` доменов.

Пайплайн: **DoH-префильтр → RDAP → WHOIS-фолбэк**, с кешем в Redis, singleflight, per-source rate limiting и асинхронными батчами.

> **Статус:** MVP/proof-of-concept. Предназначен для проверки концепции, не для продакшена.

---

## Возможности

- `GET /domain/{name}` — проверка одного домена. Флаг `?fresh=true` обходит кеш.
- `POST /check/batch` — батч доменов → асинхронная задача с `task_id`.
- `GET /tasks/{task_id}` — прогресс задачи.
- `GET /results/{task_id}?offset=&limit=` — результаты с пагинацией.
- `GET /healthz` — liveness.

### Как принимаются решения о статусе

1. **DoH** (Cloudflare DNS-over-HTTPS) — быстрый NXDOMAIN-хеурист. Никогда не отдаётся наружу как финальный статус (в ревью это критиковалось; здесь используется только как внутренний флаг в metadata).
2. **RDAP** (`rdap.nic.ru`) — авторитетный источник. 404 → `free`, 200 с `status=[pending delete]` → `pending_delete`, иначе `registered`. При 429/5xx — автоматический fallback на WHOIS.
3. **WHOIS** (`whois.tcinet.ru`, TCP/43) — парсер `state:` полей. `No entries found` → `free`.

### TTL кеша (см. `.env.example`)

| Статус | TTL по умолчанию | Почему |
|--------|------------------|--------|
| `free` | 5 мин | домен могут зарегистрировать в любую секунду |
| `registered` | 24 ч | регистрации стабильны |
| `pending_delete` / `redemption_period` | 60 сек | жизненный цикл быстрый |
| `error` | 5 мин | не долбим падающий источник |
| `doh:*` (внутренний) | 10 мин | сокращаем расход DoH-квоты |

---

## Сканер трёхбуквенных `.ru` доменов

Быстрый CLI-скрипт для оригинальной задачи: найти все свободные трёхбуквенные `.ru`.

```bash
python scripts/scan_3letter.py            # a-z, 17576 доменов, 15–30 мин
python scripts/scan_3letter.py --alphabet abcdefghijklmnopqrstuvwxyz0123456789  # с цифрами, 46656
python scripts/scan_3letter.py --limit 200 --out-dir /tmp/scan  # smoke-тест
```

Логика (в обход пайплайна, так как `.ru` **нет** в IANA RDAP bootstrap — `rdap.nic.ru` отвечает только за домены NIC.RU):

1. **Phase 1 — DoH** (Cloudflare, ~50 rps): классифицирует все кандидаты как `HAS_RECORDS` / `NXDOMAIN` / `NO_RECORDS` / `ERROR`.
2. **Phase 2 — WHOIS** (`whois.tcinet.ru`, TCP/43, авторитет для `.ru`): подтверждает только `NXDOMAIN`/`NO_RECORDS`/`ERROR`; парсит `No entries found` vs `state: REGISTERED...`.

Выход: `scan_3letter_doh.csv`, `scan_3letter_free.csv`, `scan_3letter_full.csv`.

---

## Локальный запуск (docker-compose)

```bash
cp .env.example .env
docker compose up --build
```

API: http://localhost:8000 · OpenAPI: http://localhost:8000/docs

### Примеры

```bash
# одиночная проверка
curl -s http://localhost:8000/domain/example.ru | jq

# принудительно мимо кеша
curl -s 'http://localhost:8000/domain/example.ru?fresh=true' | jq

# батч
TASK=$(curl -s -X POST http://localhost:8000/check/batch \
  -H 'content-type: application/json' \
  -d '{"domains":["example.ru","google.ru","some-very-unlikely-xyz123.ru"]}' | jq -r .task_id)

curl -s "http://localhost:8000/tasks/$TASK" | jq
curl -s "http://localhost:8000/results/$TASK" | jq
```

---

## Локальный запуск без Docker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# поднять Redis (например, докером)
docker run -d --name ru-domain-redis -p 6379:6379 redis:7-alpine

export REDIS_URL=redis://localhost:6379/0
uvicorn app.main:app --reload --port 8000
```

---

## Тесты

```bash
pip install -e ".[dev]" fakeredis
pytest -q
```

Покрывают:
- валидатор доменов (`.ru`-only, нормализация, ограничения MVP на второй уровень),
- парсеры RDAP и WHOIS на синтетических выборках,
- TTL-маппинг кеша + политика «free ≤ 15 минут»,
- E2E API-smoke с fake-pipeline и fakeredis (без сетевых вызовов).

---

## Архитектура (что реализовано из документа)

| Слой | Реализовано | Отложено |
|------|-------------|----------|
| Валидатор `.ru` | ✓ | IDN → ACE конверсия (сейчас принимаем только ASCII/ACE-форму) |
| DoH-префильтр | ✓ (внутренний флаг, не наружу) | wildcard-детект регистраторов |
| RDAP | ✓ | consensus с Partner API |
| WHOIS | ✓ | парсинг большего числа полей, extended statuses |
| Redis-кеш с разными TTL | ✓ | ключевая ротация версий, многоуровневый |
| Singleflight | ✓ (in-process asyncio.Lock) | Redis-распределённый лок для multi-worker |
| Rate limiting per-source | ✓ (token bucket в процессе) | AIMD, пул egress-IP |
| Асинхронные батчи | ✓ (Redis-backed meta + results list) | восстановление после рестарта, priority lanes |
| Auth API | — | API keys / JWT |
| Идемпотентность POST | — | `Idempotency-Key` |
| Трейсинг/метрики | базовые логи `structlog` | OpenTelemetry, Prometheus |
| Partner API | — | вынесено в Stable |

---

## Известные ограничения MVP

- Singleflight только в пределах одного процесса воркера. При горизонтальном масштабировании нужен распределённый лок (Redis SETNX).
- При рестарте процесса незавершённые батчи «зависают» в состоянии `running` — нужно отдельно чинить (скан `task:*:meta` на старте).
- Нет защиты API: нет ключей, нет квот, нет CORS-политики. Не выставлять наружу без reverse-proxy.
- WHOIS rate limit по умолчанию 0.5 rps — можно ещё снизить при ловле банов от tcinet.
- `SQLite` специально не добавлен: для состояния используется Redis, для аналитики/истории — подключите Postgres в `Stable`-фазе.
