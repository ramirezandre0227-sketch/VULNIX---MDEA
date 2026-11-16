"""Redacción de secretos (manual §5: no almacenar secretos detectados en texto plano).

Nunca se conserva el secreto ni un hash suyo (un hash de un secreto débil es atacable por diccionario):
solo su longitud.
"""

from __future__ import annotations

import math
import re
from collections import Counter

MAX_SNIPPET = 300


def redact_span(line: str, start: int, end: int) -> str:
    secret = line[start:end]
    redacted = f"{line[:start]}[REDACTED len={len(secret)}]{line[end:]}"
    return truncate(redacted)


def truncate(text: str, limit: int = MAX_SNIPPET) -> str:
    text = text.rstrip("\r\n")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_ALWAYS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----"),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{16,}\b"),
]


def scrub_text(text: str) -> str:
    """Red de seguridad para textos libres (stderr, mensajes de error) antes de persistirlos."""
    for pattern in _ALWAYS:
        text = pattern.sub(lambda m: f"[REDACTED len={len(m.group(0))}]", text)
    return text
