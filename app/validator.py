"""Validation and normalization for .ru domain inputs."""
from __future__ import annotations

import re

# .ru zone is ASCII-only per ICANN/CC .RU rules.
# Labels: letters/digits/hyphens, not starting or ending with hyphen, 1..63 chars.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class DomainValidationError(ValueError):
    pass


def normalize(raw: str) -> str:
    """Strip whitespace, lowercase, remove trailing dot, strip scheme/path if present."""
    s = raw.strip().lower()
    if not s:
        raise DomainValidationError("empty")
    # Strip scheme
    for prefix in ("http://", "https://"):
        if s.startswith(prefix):
            s = s[len(prefix) :]
    # Strip path/query
    for sep in ("/", "?", "#"):
        idx = s.find(sep)
        if idx != -1:
            s = s[:idx]
    # Strip trailing dot
    if s.endswith("."):
        s = s[:-1]
    return s


def validate_ru_domain(raw: str) -> str:
    """Return the canonical normalized form or raise.

    MVP: only accepts second-level .ru domains (e.g. 'example.ru').
    IDN (xn--...) labels in .ru ASCII form are accepted as-is.
    """
    s = normalize(raw)
    if not s.endswith(".ru"):
        raise DomainValidationError("not a .ru domain")
    parts = s.split(".")
    if len(parts) != 2:
        # MVP: no subdomains, reject third-level
        raise DomainValidationError("only second-level .ru domains are supported")
    label = parts[0]
    if not _LABEL_RE.match(label):
        raise DomainValidationError("invalid label")
    return s
