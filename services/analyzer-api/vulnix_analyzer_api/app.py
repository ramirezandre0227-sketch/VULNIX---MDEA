"""Servicio interno de analizadores (manual §2: "Servicio Python: adaptadores de analizadores y normalización").

Escucha solo en 127.0.0.1 y exige el token de servicio. Endpoints:
  GET  /internal/v1/health                 estado del servicio
  GET  /internal/v1/analyzers              declaración y salud de cada adaptador (contrato manual §4)
  GET  /internal/v1/rules                  catálogo de reglas integradas (SAST y secretos)
  POST /internal/v1/normalize/sarif        normaliza SARIF 2.1.0 de herramientas externas al formato VULNIX
  POST /internal/v1/validate/finding       valida un hallazgo contra el JSON Schema
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from vulnix_adapters.builtin.sast_rules import RULES as SAST_RULES, RULESET_VERSION
from vulnix_adapters.builtin.secrets_runner import RULES as SECRET_RULES, SECRETS_RULESET_VERSION
from vulnix_adapters.external import normalize_sarif
from vulnix_adapters.registry import build_registry
from vulnix_core import __version__
from vulnix_core.config import Settings
from vulnix_core.schema import validate_finding

MAX_BODY = 20 * 1024 * 1024


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.load()
    app = FastAPI(title="VULNIX analyzer-api", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)

    def require_service(x_vulnix_service_token: str = Header(default="")) -> None:
        expected = settings.internal_token
        if len(expected) < 32 or not hmac.compare_digest(expected, x_vulnix_service_token):
            raise HTTPException(status_code=401, detail={"code": "SERVICE_UNAUTHENTICATED"})

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        if int(request.headers.get("content-length") or 0) > MAX_BODY:
            return JSONResponse({"error": {"code": "PAYLOAD_TOO_LARGE"}}, status_code=413)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/internal/v1/health", dependencies=[Depends(require_service)])
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/internal/v1/analyzers", dependencies=[Depends(require_service)])
    def analyzers() -> dict[str, Any]:
        registry = build_registry(None, settings.php_bin, settings.node_bin)
        out = []
        for adapter in registry.values():
            st = adapter.healthcheck()
            out.append({**adapter.declaration(), "version": st.version, "healthy": st.healthy, "detail": st.detail,
                        "config_hash": adapter.config_hash()})
        return {"analyzers": out, "note": "vulnix-sca requiere el almacén de inteligencia del orquestador para estar operativo."}

    @app.get("/internal/v1/rules", dependencies=[Depends(require_service)])
    def rules() -> dict[str, Any]:
        return {
            "sast": {"version": RULESET_VERSION, "rules": [
                {"id": r.id, "languages": sorted(r.languages), "severity": r.severity, "confidence": r.confidence, "cwe": r.cwe,
                 "title": r.title, "taint": r.taint} for r in SAST_RULES]},
            "secrets": {"version": SECRETS_RULESET_VERSION, "rules": [
                {"id": r.id, "severity": r.severity, "confidence": r.confidence, "title": r.title} for r in SECRET_RULES]},
        }

    @app.post("/internal/v1/normalize/sarif", dependencies=[Depends(require_service)])
    async def normalize(request: Request, analyzer: str = "sarif-import", category: str = "sast") -> dict[str, Any]:
        if category not in ("sast", "sca", "secrets", "quality", "dast"):
            raise HTTPException(422, detail={"code": "CATEGORY_INVALID"})
        try:
            data = await request.json()
            findings = normalize_sarif(data, analyzer, category)
        except (ValueError, AttributeError, TypeError) as exc:
            raise HTTPException(422, detail={"code": "SARIF_INVALID", "message": str(exc)[:200]}) from exc
        items = [f.to_dict() for f in findings]
        invalid = [{"index": i, "errors": e} for i, f in enumerate(items) if (e := validate_finding(f))]
        return {"findings": items, "invalid": invalid}

    @app.post("/internal/v1/validate/finding", dependencies=[Depends(require_service)])
    async def validate(request: Request) -> dict[str, Any]:
        errors = validate_finding(await request.json())
        return {"valid": not errors, "errors": errors}

    return app


def main() -> None:
    import uvicorn

    host = os.environ.get("VULNIX_ANALYZER_API_HOST", "127.0.0.1")
    port = int(os.environ.get("VULNIX_ANALYZER_API_PORT", "8100"))
    uvicorn.run(create_app(), host=host, port=port, log_level="info", server_header=False)


if __name__ == "__main__":
    main()
