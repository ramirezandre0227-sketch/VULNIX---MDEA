"""Contratos de datos (manual §4 y §6): hallazgo normalizado, plan de ejecución, artefacto bruto y estado de herramienta."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
CATEGORIES = ("sast", "sca", "secrets", "quality", "dast")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    analyzer: str
    description: str
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    cwe: str | None = None
    remediation: str | None = None
    verify: str | None = None
    references: list[str] = field(default_factory=list)
    snippet: str | None = None
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severidad inválida: {self.severity}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"confianza inválida: {self.confidence}")
        if self.category not in CATEGORIES:
            raise ValueError(f"categoría inválida: {self.category}")

    def to_dict(self) -> dict[str, Any]:
        """Formato normalizado del manual §6."""
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "analyzer": self.analyzer,
            "cwe": self.cwe,
            "location": {"file": self.file, "line": self.line, "end_line": self.end_line},
            "description": self.description,
            "remediation": self.remediation,
            "verify": self.verify,
            "references": self.references,
            "snippet": self.snippet,
            "metadata": self.metadata,
        }


@dataclass
class ToolStatus:
    name: str
    version: str
    healthy: bool
    detail: str = ""


@dataclass
class AnalysisContext:
    analysis_id: str
    job_id: str
    artifact_sha256: str
    workspace: Path
    out_dir: Path
    technologies: dict[str, Any]


@dataclass
class ExecutionPlan:
    argv: list[str]
    timeout_s: int
    expected_exit_codes: tuple[int, ...] = (0,)
    outputs: dict[str, str] = field(default_factory=dict)  # nombre lógico -> fichero relativo en out_dir
    env: dict[str, str] = field(default_factory=dict)
    cwd: Path | None = None


@dataclass
class RawArtifact:
    exit_code: int | None
    timed_out: bool
    duration_s: float
    files: dict[str, Path]  # nombre lógico -> ruta absoluta (salidas de la herramienta)
    stderr_tail: str = ""
    killed_reason: str | None = None

    def load_json(self, name: str) -> Any:
        path = self.files.get(name)
        if path is None or not path.is_file():
            raise FileNotFoundError(f"salida '{name}' no producida por la herramienta")
        return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def as_plain(obj: Any) -> Any:
    return asdict(obj) if hasattr(obj, "__dataclass_fields__") else obj
