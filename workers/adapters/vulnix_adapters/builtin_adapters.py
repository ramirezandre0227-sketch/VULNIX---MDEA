"""Adaptadores de los analizadores integrados (offline, deterministas, sin red)."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from typing import Any, Protocol

from vulnix_core.models import AnalysisContext, ExecutionPlan, Finding, RawArtifact, ToolStatus
from vulnix_sandbox.runner import python_cmd

from .base import AdapterError, AnalyzerAdapter
from .builtin import RUNNER_VERSION
from .builtin.sast_rules import RULES as SAST_RULES, RULESET_VERSION
from .builtin.secrets_runner import RULES as SECRET_RULES, SECRETS_RULESET_VERSION
from .osv import is_affected, severity_of, summarize

SAST_INDEX = {r.id: r for r in SAST_RULES}


class IntelStore(Protocol):
    def snapshot(self, ecosystem: str) -> dict | None: ...
    def advisories(self, ecosystem: str, name: str) -> list[dict]: ...


# ============================================================================= SAST
class VulnixSast(AnalyzerAdapter):
    name = "vulnix-sast"
    category = "sast"
    timeout_s = 600

    def prepare(self, context: AnalysisContext) -> ExecutionPlan:
        return ExecutionPlan(python_cmd("vulnix_adapters.builtin.sast_runner", str(context.workspace), str(context.out_dir / "sast.json")),
                             self.timeout_s, outputs={"report": "sast.json"})

    def normalize(self, raw: RawArtifact) -> list[Finding]:
        self.check_exit(raw)
        data = raw.load_json("report")
        findings = []
        for item in data.get("findings", []):
            rule = SAST_INDEX.get(item["rule_id"])
            if rule is None:
                raise AdapterError("NORMALIZATION_INVALID", f"regla desconocida {item['rule_id']}")
            findings.append(Finding(
                rule_id=rule.id, title=rule.title, severity=item["severity"], confidence=item["confidence"],
                category="sast", analyzer=self.name, description=rule.description, file=item["file"], line=item["line"],
                cwe=rule.cwe, remediation=rule.remediation, verify=rule.verify, references=list(rule.references),
                snippet=item.get("snippet"), metadata={"tainted": item.get("tainted", False), "column": item.get("column")},
            ))
        return self.finalize(findings)

    def job_metadata(self, raw: RawArtifact) -> dict[str, Any]:
        data = raw.load_json("report")
        return {"files_scanned": data.get("files_scanned"), "rules": data.get("rules"), "ruleset_version": RULESET_VERSION}

    def healthcheck(self) -> ToolStatus:
        return ToolStatus(self.name, f"{RUNNER_VERSION}+rules.{RULESET_VERSION}", True, f"{len(SAST_RULES)} reglas integradas")

    def config_material(self) -> Any:
        return {"name": self.name, "rules": [(r.id, r.pattern.pattern, r.severity, r.confidence, r.taint) for r in SAST_RULES]}


# ============================================================================= Secretos
class VulnixSecrets(AnalyzerAdapter):
    name = "vulnix-secrets"
    category = "secrets"
    timeout_s = 600

    def prepare(self, context: AnalysisContext) -> ExecutionPlan:
        return ExecutionPlan(python_cmd("vulnix_adapters.builtin.secrets_runner", str(context.workspace), str(context.out_dir / "secrets.json")),
                             self.timeout_s, outputs={"report": "secrets.json"})

    def normalize(self, raw: RawArtifact) -> list[Finding]:
        self.check_exit(raw)
        findings = []
        for item in raw.load_json("report").get("findings", []):
            findings.append(Finding(
                rule_id=item["rule_id"], title=f"Secreto expuesto: {item['title']}", severity=item["severity"],
                confidence=item["confidence"], category="secrets", analyzer=self.name, cwe="CWE-798",
                description="Se detectó una credencial o secreto en el código o la configuración versionada. "
                            "Cualquiera con acceso al artefacto puede usarla. El valor ha sido redactado.",
                file=item["file"], line=item["line"],
                remediation="Revocar y rotar la credencial inmediatamente; moverla a variables de entorno o a un gestor de secretos "
                            "y eliminarla del historial del repositorio.",
                verify="Confirmar que la credencial antigua ya no es válida y que el nuevo análisis no la detecta.",
                references=["https://cwe.mitre.org/data/definitions/798.html",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                snippet=item["redacted_line"], metadata={"secret_length": item["secret_length"], "entropy": item["entropy"]},
            ))
        return self.finalize(findings)

    def healthcheck(self) -> ToolStatus:
        return ToolStatus(self.name, f"{RUNNER_VERSION}+rules.{SECRETS_RULESET_VERSION}", True, f"{len(SECRET_RULES)} reglas integradas")

    def config_material(self) -> Any:
        return {"name": self.name, "rules": [(r.id, r.pattern.pattern, r.min_entropy) for r in SECRET_RULES]}


# ============================================================================= SCA
class VulnixSca(AnalyzerAdapter):
    name = "vulnix-sca"
    category = "sca"
    timeout_s = 300

    def __init__(self, intel: IntelStore | None = None):
        self.intel = intel
        self._intel_used: dict[str, dict] = {}
        self._components = 0

    def prepare(self, context: AnalysisContext) -> ExecutionPlan:
        return ExecutionPlan(
            python_cmd("vulnix_adapters.builtin.sca_runner", str(context.workspace), str(context.out_dir / "components.json"), str(context.out_dir / "sbom.cdx.json")),
            self.timeout_s, expected_exit_codes=(0,), outputs={"report": "components.json", "sbom": "sbom.cdx.json"})

    def normalize(self, raw: RawArtifact) -> list[Finding]:
        if raw.exit_code == 3:
            inv = raw.load_json("report")
            raise AdapterError("MISSING_LOCKFILE",
                               "Sin lockfile no se pueden determinar versiones exactas: " + json.dumps(inv.get("manifests_without_lockfile", []) + inv.get("errors", []))[:500])
        self.check_exit(raw)
        if self.intel is None:
            raise AdapterError("INTEL_UNAVAILABLE", "No hay almacén de inteligencia configurado")
        inv = raw.load_json("report")
        components = inv.get("components", [])
        self._components = len(components)
        self._intel_used = {}
        findings: list[Finding] = []
        for eco in sorted({c["ecosystem"] for c in components}):
            snap = self.intel.snapshot(eco)
            if not snap:
                raise AdapterError("INTEL_UNAVAILABLE", f"No hay inteligencia importada para el ecosistema {eco}; ejecute vulnix-intel import.")
            self._intel_used[eco] = snap
        for comp in components:
            for adv in self.intel.advisories(comp["ecosystem"], comp["name"]):
                hit, fixed = is_affected(adv, comp["ecosystem"], comp["name"], comp["version"])
                if not hit:
                    continue
                info = summarize(adv)
                severity, score = severity_of(adv)
                ids = ", ".join([info["id"], *info["aliases"]][:4])
                fix = f"Actualizar {comp['name']} a {' o '.join(fixed[:3])} o superior." if fixed else \
                    f"No hay versión corregida publicada: sustituir {comp['name']} o mitigar según el aviso."
                findings.append(Finding(
                    rule_id=info["id"][:160], title=f"{comp['name']}@{comp['version']}: {info['summary'][:150] or 'vulnerabilidad conocida'}"[:255],
                    severity=severity, confidence="HIGH", category="sca", analyzer=self.name,
                    description=f"El componente {comp['ecosystem']}/{comp['name']} {comp['version']} ({comp['scope']}) está afectado por {ids}. {info['summary']}"[:8000],
                    file=comp["source"], line=None, cwe=info["cwe"] if info["cwe"] and info["cwe"].startswith("CWE-") else None,
                    remediation=fix, verify="Regenerar el lockfile tras actualizar y repetir el análisis: el aviso no debe aparecer.",
                    references=[u for u in info["references"] if isinstance(u, str)][:8],
                    snippet=f"{comp['name']}@{comp['version']}",
                    metadata={"ecosystem": comp["ecosystem"], "package": comp["name"], "version": comp["version"], "scope": comp["scope"],
                              "advisory": info["id"], "aliases": info["aliases"], "fixed": fixed, "cvss": score,
                              "anchor": f"{comp['ecosystem']}|{comp['name']}|{comp['version']}"},
                ))
        return self.finalize(findings)

    def job_metadata(self, raw: RawArtifact) -> dict[str, Any]:
        return {"components": self._components,
                "intel": {"ecosystems": {eco: {"imported_at": s["imported_at"], "records": s.get("records"), "feed_sha256": s.get("sha256")}
                                         for eco, s in self._intel_used.items()}}}

    def evidence_files(self, raw: RawArtifact) -> dict[str, str]:
        return {"report": "RAW_OUTPUT", "sbom": "SBOM"}

    def healthcheck(self) -> ToolStatus:
        return ToolStatus(self.name, f"{RUNNER_VERSION}+osv", self.intel is not None,
                          "inteligencia OSV local" if self.intel else "sin almacén de inteligencia")


# ============================================================================= Calidad
class VulnixQuality(AnalyzerAdapter):
    name = "vulnix-quality"
    category = "quality"
    timeout_s = 900

    def __init__(self, php_bin: str = "php", node_bin: str = "node", tsc_bin: str | None = None):
        self.php_bin = shutil.which(php_bin) or php_bin
        self.node_bin = shutil.which(node_bin) or node_bin
        self.tsc_bin = (shutil.which(tsc_bin) or tsc_bin) if tsc_bin else None
        self._meta: dict[str, Any] = {}

    def prepare(self, context: AnalysisContext) -> ExecutionPlan:
        argv = python_cmd("vulnix_adapters.builtin.quality_runner", str(context.workspace), str(context.out_dir / "quality.json"),
                          "--php", self.php_bin, "--node", self.node_bin)
        if self.tsc_bin:
            argv += ["--tsc", self.tsc_bin]
        return ExecutionPlan(argv, self.timeout_s, outputs={"report": "quality.json"})

    def normalize(self, raw: RawArtifact) -> list[Finding]:
        self.check_exit(raw)
        data = raw.load_json("report")
        self._meta = {k: data.get(k) for k in ("build", "tests", "coverage", "metrics")}
        titles = {"quality.syntax-error": "Error de sintaxis", "quality.debug-output": "Salida de depuración en el código",
                  "quality.debugger-statement": "Sentencia debugger olvidada", "quality.high-complexity": "Complejidad elevada"}
        remediation = {"quality.syntax-error": "Corregir el error de sintaxis; el fichero no puede ejecutarse.",
                       "quality.debug-output": "Eliminar las llamadas de depuración o protegerlas tras un flag de entorno.",
                       "quality.debugger-statement": "Eliminar la sentencia debugger.",
                       "quality.high-complexity": "Dividir el fichero/función en unidades más pequeñas y cubrirlas con pruebas."}
        findings = [Finding(
            rule_id=i["rule_id"], title=titles.get(i["rule_id"], i["rule_id"]), severity=i["severity"], confidence=i["confidence"],
            category="quality", analyzer=self.name, description=i["message"][:8000], file=i["file"], line=i.get("line"),
            remediation=remediation.get(i["rule_id"]), verify="Repetir el análisis de calidad.",
            metadata={"anchor": i["message"][:200]},
        ) for i in data.get("findings", [])]
        return self.finalize(findings)

    def job_metadata(self, raw: RawArtifact) -> dict[str, Any]:
        return self._meta

    def healthcheck(self) -> ToolStatus:
        php_ok = shutil.which(self.php_bin) is not None
        node_ok = shutil.which(self.node_bin) is not None
        detail = f"php={'ok' if php_ok else 'NO'} node={'ok' if node_ok else 'NO'} tsc={'ok' if self.tsc_bin else 'no configurado'}"
        return ToolStatus(self.name, RUNNER_VERSION, php_ok and node_ok, detail)

    def config_material(self) -> Any:
        return {"name": self.name, "php": self.php_bin, "node": self.node_bin, "tsc": self.tsc_bin}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]
