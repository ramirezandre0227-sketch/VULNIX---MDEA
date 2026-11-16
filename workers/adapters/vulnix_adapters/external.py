"""Adaptadores de herramientas externas opcionales. Solo se ejecutan si están instaladas y configuradas
para operar SIN red (reglas locales / repositorio offline aprobado, manual §8)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import Any

from vulnix_core.models import AnalysisContext, ExecutionPlan, Finding, RawArtifact, ToolStatus

from .base import AdapterError, AnalyzerAdapter

_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW", "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def _version(argv: list[str]) -> str | None:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"\d+\.\d+(\.\d+)?", r.stdout + r.stderr)
    return m.group(0) if r.returncode == 0 and m else None


def _cwe(values: Any) -> str | None:
    if isinstance(values, str):
        values = [values]
    for v in values or []:
        m = re.search(r"CWE-(\d+)", str(v))
        if m:
            return f"CWE-{m.group(1)}"
    return None


class Semgrep(AnalyzerAdapter):
    """Requiere VULNIX_SEMGREP_RULES (directorio local de reglas): nunca se usa --config auto (red)."""

    name = "semgrep"
    category = "sast"
    timeout_s = 900
    expected_exit_codes = (0, 1)
    mandatory_default = False

    def __init__(self):
        self.bin = shutil.which(os.environ.get("VULNIX_SEMGREP_BIN", "semgrep"))
        self.rules = os.environ.get("VULNIX_SEMGREP_RULES")

    def prepare(self, context: AnalysisContext) -> ExecutionPlan:
        if not self.bin or not self.rules:
            raise AdapterError("TOOL_UNAVAILABLE", "semgrep no instalado o sin VULNIX_SEMGREP_RULES")
        return ExecutionPlan([self.bin, "scan", "--config", self.rules, "--json", "--metrics=off", "--disable-version-check",
                              "--output", str(context.out_dir / "semgrep.json"), str(context.workspace)],
                             self.timeout_s, self.expected_exit_codes, {"report": "semgrep.json"}, env={"SEMGREP_SEND_METRICS": "off"})

    def normalize(self, raw: RawArtifact) -> list[Finding]:
        self.check_exit(raw)
        data = raw.load_json("report")
        out = []
        for r in data.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            conf = str(meta.get("confidence", "MEDIUM")).upper()
            out.append(Finding(
                rule_id=str(r.get("check_id"))[:160], title=str(extra.get("message", r.get("check_id")))[:255],
                severity=_SEV.get(str(extra.get("severity", "WARNING")).upper(), "MEDIUM"),
                confidence=conf if conf in ("HIGH", "MEDIUM", "LOW") else "MEDIUM",
                category="sast", analyzer=self.name, description=str(extra.get("message", ""))[:8000] or "Hallazgo de Semgrep",
                file=_rel(r.get("path"), raw), line=r.get("start", {}).get("line"), end_line=r.get("end", {}).get("line"),
                cwe=_cwe(meta.get("cwe")), remediation=meta.get("fix") or extra.get("fix"),
                references=[str(u) for u in (meta.get("references") or [])][:10], snippet=None,
                metadata={"anchor": str(extra.get("lines", ""))[:300]},
            ))
        return self.finalize(out)

    def healthcheck(self) -> ToolStatus:
        v = _version([self.bin, "--version"]) if self.bin else None
        return ToolStatus(self.name, v or "unknown", bool(v and self.rules), "ok" if v and self.rules else "no instalado o sin reglas locales")

    def config_material(self) -> Any:
        return {"name": self.name, "rules": self.rules}


class Gitleaks(AnalyzerAdapter):
    name = "gitleaks"
    category = "secrets"
    timeout_s = 600
    expected_exit_codes = (0,)
    mandatory_default = False

    def __init__(self):
        self.bin = shutil.which(os.environ.get("VULNIX_GITLEAKS_BIN", "gitleaks"))

    def prepare(self, context: AnalysisContext) -> ExecutionPlan:
        if not self.bin:
            raise AdapterError("TOOL_UNAVAILABLE", "gitleaks no instalado")
        return ExecutionPlan([self.bin, "detect", "--no-git", "--redact", "--no-banner", "--exit-code", "0",
                              "--report-format", "json", "--report-path", str(context.out_dir / "gitleaks.json"),
                              "--source", str(context.workspace)], self.timeout_s, self.expected_exit_codes, {"report": "gitleaks.json"})

    def normalize(self, raw: RawArtifact) -> list[Finding]:
        self.check_exit(raw)
        out = []
        for r in raw.load_json("report") or []:
            out.append(Finding(
                rule_id=f"gitleaks.{r.get('RuleID', 'secret')}"[:160], title=f"Secreto expuesto: {r.get('Description') or r.get('RuleID')}"[:255],
                severity="HIGH", confidence="MEDIUM", category="secrets", analyzer=self.name, cwe="CWE-798",
                description="Gitleaks detectó un posible secreto (valor redactado por la herramienta).",
                file=_rel(r.get("File"), raw), line=r.get("StartLine") or None,
                remediation="Revocar y rotar la credencial; moverla a un gestor de secretos.",
                snippet="[REDACTED]", metadata={"anchor": f"{r.get('RuleID')}|{r.get('StartLine')}"},
            ))
        return self.finalize(out)

    def healthcheck(self) -> ToolStatus:
        v = _version([self.bin, "version"]) if self.bin else None
        return ToolStatus(self.name, v or "unknown", bool(v), "ok" if v else "no instalado")


def _rel(path: Any, raw: RawArtifact) -> str | None:
    if not path:
        return None
    p = str(path).replace("\\", "/")
    marker = "/src/"
    return p.split(marker, 1)[1] if marker in p else p


def normalize_sarif(data: dict, analyzer: str = "sarif-import", category: str = "sast") -> list[Finding]:
    """Normalizador genérico SARIF 2.1.0 (importación de resultados de otras herramientas)."""
    from vulnix_core.fingerprint import assign_fingerprints

    level = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
    out: list[Finding] = []
    for run in data.get("runs", []):
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = str(res.get("ruleId", "sarif.unknown"))[:160]
            rule = rules.get(rid, {})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            msg = str(res.get("message", {}).get("text", rid))
            out.append(Finding(
                rule_id=rid, title=msg[:255], severity=level.get(res.get("level", "warning"), "MEDIUM"), confidence="MEDIUM",
                category=category, analyzer=analyzer, description=msg[:8000],
                file=loc.get("artifactLocation", {}).get("uri"), line=loc.get("region", {}).get("startLine"),
                cwe=_cwe(rule.get("properties", {}).get("tags")), metadata={"anchor": msg[:200]},
            ))
    return assign_fingerprints(out)
