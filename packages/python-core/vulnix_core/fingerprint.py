"""Huellas estables de hallazgos y claves de correlación.

La huella NO incluye el número de línea: sobrevive a desplazamientos del código entre versiones
(permite comparar versiones y arrastrar excepciones). Incluye el índice de ocurrencia para
distinguir repeticiones idénticas dentro del mismo fichero.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from .models import Finding

_WS = re.compile(r"\s+")


def normalize_code(text: str | None) -> str:
    return _WS.sub(" ", (text or "")).strip()[:500]


def compute_fingerprint(rule_id: str, file: str | None, anchor: str, occurrence: int) -> str:
    material = "|".join([rule_id, file or "", normalize_code(anchor), str(occurrence)])
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def assign_fingerprints(findings: list[Finding], anchors: dict[int, str] | None = None) -> list[Finding]:
    """Asigna huellas deterministas. `anchors` permite sustituir el texto ancla (p. ej. secreto redactado)."""
    seen: dict[tuple[str, str, str], int] = defaultdict(int)
    for idx, f in enumerate(findings):
        anchor = (anchors or {}).get(idx, f.snippet or f.metadata.get("anchor", "") or f.title)
        key = (f.rule_id, f.file or "", normalize_code(anchor))
        occurrence = seen[key]
        seen[key] += 1
        f.fingerprint = compute_fingerprint(f.rule_id, f.file, anchor, occurrence)
    return findings


def correlation_key(file: str | None, line: int | None, cwe: str | None, category: str) -> str:
    """Agrupa hallazgos de distintos analizadores sobre el mismo problema (fichero + línea + CWE)."""
    material = "|".join([file or "", str(line or 0), cwe or category])
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()
