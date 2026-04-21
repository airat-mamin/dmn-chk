#!/usr/bin/env python3
"""Scan all 3-letter .ru domains for availability.

Strategy (avoids zone-level RDAP because .ru is not in the IANA RDAP bootstrap —
rdap.nic.ru only answers for NIC.RU-managed domains):

  Phase 1: DoH over all N candidates via Cloudflare (~50 rps). Classifies each as
    NXDOMAIN / NO_RECORDS / HAS_RECORDS / ERROR.
  Phase 2: WHOIS (TCP/43 whois.tcinet.ru, authoritative for .ru) on every domain
    that DoH did NOT mark HAS_RECORDS. Parse 'No entries found' vs 'state:
    REGISTERED...' to determine final status.

Outputs under --out-dir:
  scan_3letter_doh.csv    - full DoH flags for every candidate
  scan_3letter_free.csv   - confirmed-free domains (WHOIS-verified)
  scan_3letter_full.csv   - full per-domain result (status, evidence)
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import itertools
import socket
import string
import sys
import time
from pathlib import Path

import httpx

DOH_URL = "https://cloudflare-dns.com/dns-query"
WHOIS_HOST = "whois.tcinet.ru"
WHOIS_PORT = 43


# -- DoH --------------------------------------------------------------------

async def doh_check(client: httpx.AsyncClient, domain: str) -> str:
    """Return one of: nxdomain, no_records, has_records, error."""
    try:
        r = await client.get(
            DOH_URL,
            params={"name": domain, "type": "A"},
            headers={"accept": "application/dns-json"},
            timeout=10.0,
        )
    except (httpx.HTTPError, OSError):
        return "error"
    if r.status_code != 200:
        return "error"
    try:
        data = r.json()
    except ValueError:
        return "error"
    status = data.get("Status")
    if status == 3:
        return "nxdomain"
    if status == 0:
        return "has_records" if data.get("Answer") else "no_records"
    return "error"


# -- WHOIS ------------------------------------------------------------------

def _whois_sync(domain: str, timeout: float = 10.0) -> str:
    s = socket.create_connection((WHOIS_HOST, WHOIS_PORT), timeout=timeout)
    try:
        s.sendall(domain.encode("ascii") + b"\r\n")
        chunks: list[bytes] = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", errors="replace")
    finally:
        s.close()


async def whois_check(domain: str) -> tuple[str, str]:
    """Return (status, raw_state_line). status ∈ {free, registered, pending, error}."""
    loop = asyncio.get_running_loop()
    try:
        raw = await loop.run_in_executor(None, _whois_sync, domain)
    except (OSError, TimeoutError) as exc:
        return "error", f"whois_error:{type(exc).__name__}"
    lowered = raw.lower()
    if "no entries found" in lowered:
        return "free", ""
    state_line = ""
    for line in raw.splitlines():
        ls = line.strip()
        if ls.lower().startswith("state:"):
            state_line = ls
            break
    ls = state_line.lower()
    if "pending delete" in ls or "redemption" in ls:
        return "pending", state_line
    if "registered" in ls:
        return "registered", state_line
    if not state_line:
        return "error", "whois_parse_no_state"
    return "registered", state_line


# -- Main -------------------------------------------------------------------

def gen_domains(alphabet: str) -> list[str]:
    return ["".join(t) + ".ru" for t in itertools.product(alphabet, repeat=3)]


def write_csv(path: Path, header: list[str], rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow(row)


async def phase_doh(
    domains: list[str], concurrency: int
) -> dict[str, str]:
    results: dict[str, str] = {}
    sem = asyncio.Semaphore(concurrency)
    start = time.monotonic()
    processed = 0
    total = len(domains)

    async with httpx.AsyncClient(
        http2=False, timeout=10.0, limits=httpx.Limits(max_connections=concurrency * 2)
    ) as client:

        async def one(d: str) -> None:
            nonlocal processed
            async with sem:
                flag = await doh_check(client, d)
            results[d] = flag
            processed += 1
            if processed % 500 == 0:
                elapsed = time.monotonic() - start
                rate = processed / max(elapsed, 1e-9)
                eta = (total - processed) / max(rate, 1e-9)
                print(
                    f"  DoH {processed}/{total} | {rate:.0f} rps | ETA {eta:.0f}s",
                    file=sys.stderr,
                )

        await asyncio.gather(*(one(d) for d in domains))

    elapsed = time.monotonic() - start
    print(f"Phase 1 (DoH) done in {elapsed:.0f}s.", file=sys.stderr)
    return results


async def phase_whois(
    candidates: list[str], concurrency: int
) -> dict[str, tuple[str, str]]:
    results: dict[str, tuple[str, str]] = {}
    sem = asyncio.Semaphore(concurrency)
    start = time.monotonic()
    processed = 0
    total = len(candidates)

    async def one(d: str) -> None:
        nonlocal processed
        async with sem:
            status, evidence = await whois_check(d)
        results[d] = (status, evidence)
        processed += 1
        if processed % 25 == 0 or processed == total:
            elapsed = time.monotonic() - start
            rate = processed / max(elapsed, 1e-9)
            eta = (total - processed) / max(rate, 1e-9)
            free_so_far = sum(1 for s, _ in results.values() if s == "free")
            print(
                f"  WHOIS {processed}/{total} | {rate:.1f} rps | "
                f"ETA {eta:.0f}s | free so far: {free_so_far}",
                file=sys.stderr,
            )

    await asyncio.gather(*(one(d) for d in candidates))
    return results


async def main() -> int:
    ap = argparse.ArgumentParser(
        description="Scan all 3-letter .ru domains for availability."
    )
    ap.add_argument(
        "--alphabet",
        default=string.ascii_lowercase,
        help="Characters to enumerate (default: a-z, yielding 17576 domains).",
    )
    ap.add_argument("--doh-concurrency", type=int, default=50)
    ap.add_argument(
        "--whois-concurrency",
        type=int,
        default=4,
        help="Keep low to be polite to whois.tcinet.ru; too high risks a ban.",
    )
    ap.add_argument("--out-dir", type=Path, default=Path("."))
    ap.add_argument(
        "--skip-doh",
        action="store_true",
        help="Skip DoH and WHOIS every domain (much slower).",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="For smoke tests: only scan this many domains (0 = all).",
    )
    args = ap.parse_args()

    domains = gen_domains(args.alphabet)
    if args.limit:
        domains = domains[: args.limit]
    print(f"Total candidates: {len(domains)}", file=sys.stderr)

    doh_flags: dict[str, str] = {}
    if not args.skip_doh:
        doh_flags = await phase_doh(domains, args.doh_concurrency)
        write_csv(
            args.out_dir / "scan_3letter_doh.csv",
            ["domain", "doh_flag"],
            sorted(doh_flags.items()),
        )
        candidates = [
            d
            for d, flag in doh_flags.items()
            if flag in {"nxdomain", "no_records", "error"}
        ]
    else:
        candidates = list(domains)

    print(
        f"WHOIS candidates: {len(candidates)} "
        f"(skipped {len(domains) - len(candidates)} HAS_RECORDS)",
        file=sys.stderr,
    )

    whois_results = await phase_whois(candidates, args.whois_concurrency)

    free = [d for d, (s, _) in whois_results.items() if s == "free"]
    free.sort()

    write_csv(
        args.out_dir / "scan_3letter_free.csv",
        ["domain"],
        ([d] for d in free),
    )

    def full_rows():
        for d in sorted(domains):
            flag = doh_flags.get(d, "skipped")
            whois_status, evidence = whois_results.get(d, ("skipped", ""))
            yield [d, flag, whois_status, evidence]

    write_csv(
        args.out_dir / "scan_3letter_full.csv",
        ["domain", "doh_flag", "whois_status", "whois_evidence"],
        full_rows(),
    )

    print(f"\nFREE 3-letter .ru domains: {len(free)}")
    for d in free:
        print(d)
    print(f"\nCSVs written under {args.out_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
