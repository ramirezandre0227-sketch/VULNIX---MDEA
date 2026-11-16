"""Contrato de adaptador de herramienta (manual §4).

interface AnalyzerAdapter:
    supports(project_manifest) -> bool
    prepare(context) -> ExecutionPlan
    execute(plan, sandbox) -> RawArtifact
    normalize(raw) -> list[Finding]
    healthcheck() -> ToolStatus

Cada adaptador declara: nombre, versión, formato de salida, timeout, necesidades de red,
recursos máximos, códigos de salida esperados y si es obligatorio por defecto.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any, ClassVar

from vulnix_core.fingerprint import assign_fingerprints
from vulnix_core.models import AnalysisContext, ExecutionPlan, Finding, RawArtifact, ToolStatus
from vulnix_core.schema import validate_finding
from vulnix_sandbox.runner import Sandbox


class AdapterError(Exception):
    """Error clasificado de un adaptador. `retryable` indica fallo transitorio."""

    def __init__(self, error_type: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.error_type = error_type
        self.retryable = retryable


class AnalyzerAdapter(ABC):
    name: ClassVar[str]
    category: ClassVar[str]
    output_format: ClassVar[str] = "json"
    timeout_s: ClassVar[int] = 600
    network: ClassVar[str] = "none"            # none | internal-repos | lab-target
    max_memory_mb: ClassVar[int] = 1024
    max_processes: ClassVar[int] = 32
    expected_exit_codes: ClassVar[tuple[int, ...]] = (0,)
    mandatory_default: ClassVar[bool] = True

    # ------------------------------------------------------------------ contrato
    def supports(self, project_manifest: dict[str, Any]) -> bool:
        return True

    @abstractmethod
    def prepare(self, context: AnalysisContext) -> ExecutionPlan: ...

    def execute(self, plan: ExecutionPlan, sandbox: Sandbox) -> RawArtifact:
        result = sandbox.run(plan.argv, plan.timeout_s, plan.env, plan.cwd)
        files = {name: sandbox.out / rel for name, rel in plan.outputs.items()}
        files["stdout"] = result.stdout_path
        files["stderr"] = result.stderr_path
        return RawArtifact(
            exit_code=result.exit_code, timed_out=result.timed_out, duration_s=result.duration_s,
            files=files, stderr_tail=result.stderr_tail(), killed_reason=result.killed_reason,
        )

    @abstractmethod
    def normalize(self, raw: RawArtifact) -> list[Finding]: ...

    @abstractmethod
    def healthcheck(self) -> ToolStatus: ...

    # ------------------------------------------------------------------ utilidades comunes
    def version(self) -> str:
        return self.healthcheck().version

    def config_hash(self) -> str:
        """Hash de la configuración efectiva (reglas incluidas): forma parte de la identidad del analizador."""
        return hashlib.sha256(json.dumps(self.config_material(), sort_keys=True, default=str).encode()).hexdigest()

    def config_material(self) -> Any:
        return {"name": self.name, "timeout": self.timeout_s}

    def job_metadata(self, raw: RawArtifact) -> dict[str, Any]:
        return {}

    def evidence_files(self, raw: RawArtifact) -> dict[str, str]:
        """Salidas a conservar como evidencia: nombre lógico -> tipo de evidencia."""
        return {"report": "RAW_OUTPUT"}

    def declaration(self) -> dict[str, Any]:
        return {
            "name": self.name, "category": self.category, "output_format": self.output_format,
            "timeout_s": self.timeout_s, "network": self.network, "max_memory_mb": self.max_memory_mb,
            "max_processes": self.max_processes, "expected_exit_codes": list(self.expected_exit_codes),
            "mandatory_default": self.mandatory_default,
        }

    def finalize(self, findings: list[Finding]) -> list[Finding]:
        """Asigna huellas y valida contra el JSON Schema: un hallazgo inválido es un fallo del adaptador."""
        findings = assign_fingerprints(findings)
        for f in findings:
            errors = validate_finding(f.to_dict())
            if errors:
                raise AdapterError("NORMALIZATION_INVALID", f"{f.rule_id}: {errors[:3]}")
        return findings

    def check_exit(self, raw: RawArtifact) -> None:
        if raw.timed_out:
            raise AdapterError("TIMEOUT", f"tiempo máximo excedido ({self.timeout_s}s)")
        if raw.killed_reason:
            raise AdapterError("RESOURCE_LIMIT", f"proceso detenido: {raw.killed_reason}")
        if raw.exit_code not in self.expected_exit_codes:
            raise AdapterError("TOOL_ERROR", f"código de salida inesperado {raw.exit_code}: {raw.stderr_tail[-500:]}", retryable=True)
