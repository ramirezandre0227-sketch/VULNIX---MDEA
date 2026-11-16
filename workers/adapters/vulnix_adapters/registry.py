"""Registro de adaptadores disponibles en este worker.

Un analizador requerido por la política que no esté registrado (p. ej. vulnix-dast, pendiente de la fase 4)
produce un job FAILED con ANALYZER_NOT_INSTALLED -> la decisión será INCONCLUSIVE (fail closed).
"""

from __future__ import annotations

import os

from .base import AnalyzerAdapter
from .builtin_adapters import IntelStore, VulnixQuality, VulnixSast, VulnixSca, VulnixSecrets
from .external import Gitleaks, Semgrep


def build_registry(intel: IntelStore | None, php_bin: str = "php", node_bin: str = "node") -> dict[str, AnalyzerAdapter]:
    adapters: list[AnalyzerAdapter] = [
        VulnixSast(),
        VulnixSecrets(),
        VulnixSca(intel),
        VulnixQuality(php_bin, node_bin, os.environ.get("VULNIX_TSC_BIN") or None),
        Semgrep(),
        Gitleaks(),
    ]
    return {a.name: a for a in adapters}
