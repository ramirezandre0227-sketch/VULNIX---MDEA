"""Correlación de componentes con avisos OSV: rangos de versiones y severidad (CVSS v3.x).

Formato OSV: https://ossf.github.io/osv-schema/ (affected[].ranges[].events: introduced/fixed/last_affected,
affected[].versions: lista explícita).
"""

from __future__ import annotations

import math
import re
from functools import total_ordering
from typing import Any

_PRE_ORDER = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "pre": 3, "preview": 3, "": 4, "patch": 5, "p": 5, "pl": 5}


@total_ordering
class Version:
    """Comparación tolerante para SemVer (npm) y versiones Composer (1.2.3.4, v1.2, 1.2.3-beta2)."""

    __slots__ = ("raw", "nums", "pre", "valid")

    def __init__(self, raw: str):
        self.raw = raw
        text = raw.strip().lower().lstrip("v").split("+", 1)[0]
        m = re.match(r"^(\d+(?:\.\d+)*)(?:[-_.]?([a-z]+)\.?(\d*))?", text)
        if not m:
            self.nums, self.pre, self.valid = (), (4, 0), False
            return
        nums = [int(x) for x in m.group(1).split(".")]
        while len(nums) < 3:
            nums.append(0)
        self.nums = tuple(nums)
        tag = m.group(2) or ""
        self.pre = (_PRE_ORDER.get(tag, 1), int(m.group(3) or 0))
        self.valid = True

    def _key(self):
        n = list(self.nums)
        while len(n) > 3 and n[-1] == 0:
            n.pop()
        return (tuple(n), self.pre)

    def __eq__(self, other):
        return isinstance(other, Version) and self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())


ZERO = Version("0")


def _range_affects(version: Version, events: list[dict]) -> bool:
    def ev_version(e: dict) -> Version:
        val = next(iter(e.values()))
        return ZERO if val == "0" else Version(str(val))

    ordered = sorted(events, key=lambda e: (ev_version(e), 0 if "introduced" in e else 1))
    affected = False
    for e in ordered:
        if "introduced" in e and version >= ev_version(e):
            affected = True
        elif "fixed" in e and version >= ev_version(e):
            affected = False
        elif "last_affected" in e and version > ev_version(e):
            affected = False
        elif "limit" in e and version >= ev_version(e):
            affected = False
    return affected


def is_affected(advisory: dict, ecosystem: str, name: str, version: str) -> tuple[bool, list[str]]:
    """Devuelve (afectado, versiones_corregidas)."""
    if advisory.get("withdrawn"):
        return False, []
    v = Version(version)
    hit, fixed = False, []
    for aff in advisory.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != ecosystem or pkg.get("name", "").lower() != name.lower():
            continue
        if version in (aff.get("versions") or []) or (version.lstrip("v") in (aff.get("versions") or [])):
            hit = True
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            events = rng.get("events", [])
            fixed += [e["fixed"] for e in events if "fixed" in e]
            if v.valid and _range_affects(v, events):
                hit = True
    return hit, sorted(set(fixed), key=Version)


# ----------------------------------------------------------------------------- CVSS v3.x (base score)
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62}, "C": {"H": 0.56, "L": 0.22, "N": 0}, "I": {"H": 0.56, "L": 0.22, "N": 0},
    "A": {"H": 0.56, "L": 0.22, "N": 0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _W["C"][parts["C"]]) * (1 - _W["I"][parts["I"]]) * (1 - _W["A"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        exploit = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + exploit), 10) if scope_changed else min(impact + exploit, 10)
        return _roundup(raw)
    except (KeyError, ValueError):
        return None


def severity_of(advisory: dict) -> tuple[str, float | None]:
    if str(advisory.get("id", "")).startswith("MAL-"):
        return "CRITICAL", None  # paquete malicioso conocido
    label = (advisory.get("database_specific") or {}).get("severity")
    score = None
    for s in advisory.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3") and s.get("score"):
            score = cvss3_base_score(s["score"])
    if isinstance(label, str) and label.upper() in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        return {"MODERATE": "MEDIUM"}.get(label.upper(), label.upper()), score
    if score is not None:
        return ("CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "INFO"), score
    return "MEDIUM", None


def summarize(advisory: dict[str, Any]) -> dict[str, Any]:
    aliases = [a for a in advisory.get("aliases", []) if isinstance(a, str)]
    cwes = (advisory.get("database_specific") or {}).get("cwe_ids") or []
    return {
        "id": advisory.get("id"),
        "aliases": aliases,
        "summary": (advisory.get("summary") or advisory.get("details") or "").strip()[:500],
        "cwe": cwes[0] if cwes else None,
        "references": [r.get("url") for r in advisory.get("references", [])[:8] if r.get("url")],
    }
