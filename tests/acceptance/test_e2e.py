"""Aceptación de extremo a extremo contra la plataforma en ejecución (API + orquestador + analyzer-api).

Ejecutar con:  VULNIX_E2E=1 .venv/Scripts/python -m pytest tests/acceptance -v
Credenciales: fichero VULNIX_E2E_CREDENTIALS (por defecto ~/.vulnix-local/dev-users.txt, formato "usuario (rol): contraseña").
"""

from __future__ import annotations

import base64
import io
import json
import os
import time
import zipfile
from pathlib import Path

import httpx
import pytest

from vulnix_core.verify import verify_token

pytestmark = [pytest.mark.e2e, pytest.mark.skipif(os.environ.get("VULNIX_E2E") != "1", reason="requiere VULNIX_E2E=1 y la plataforma en ejecución")]

BASE = os.environ.get("VULNIX_E2E_URL", "http://127.0.0.1:8000")
CORPUS = Path(__file__).resolve().parents[1] / "corpus"
TERMINAL = {"COMPLETED", "INCONCLUSIVE", "FAILED", "CANCELLED", "TIMED_OUT"}


def creds(role: str) -> tuple[str, str]:
    path = Path(os.environ.get("VULNIX_E2E_CREDENTIALS", Path.home() / ".vulnix-local" / "dev-users.txt"))
    for line in path.read_text(encoding="utf-8").splitlines():
        user, _, pwd = line.partition(": ")
        if f"({role})" in user:
            return user.split(" ")[0], pwd.strip()
    raise RuntimeError(f"sin credenciales para {role}")


@pytest.fixture(scope="module")
def dev() -> httpx.Client:
    user, pwd = creds("developer")
    r = httpx.post(f"{BASE}/api/v1/auth/login", json={"username": user, "password": pwd, "token_name": "e2e"}, headers={"Accept": "application/json"})
    r.raise_for_status()
    return httpx.Client(base_url=f"{BASE}/api/v1", headers={"Authorization": f"Bearer {r.json()['token']}", "Accept": "application/json"}, timeout=60)


def zip_project(name: str, extra: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted((CORPUS / name).rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(CORPUS / name).as_posix())
        for rel, content in (extra or {}).items():
            zf.writestr(rel, content)
    return buf.getvalue()


def composer(guzzle: str) -> dict[str, str]:
    return {"composer.json": json.dumps({"require": {"guzzlehttp/guzzle": "^7.0"}}),
            "composer.lock": json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": guzzle}], "packages-dev": []})}


def analyze(c: httpx.Client, payload: bytes, profile: str = "web-development") -> dict:
    project = c.post("/projects", json={"name": f"E2E {time.time_ns()}", "criticality": "HIGH", "default_profile": "web-development"}).raise_for_status().json()["data"]
    version = c.post(f"/projects/{project['id']}/versions", data={"version": "1.0.0"}, files={"file": ("app.zip", payload, "application/zip")}).raise_for_status().json()["data"]
    analysis_id = c.post("/analyses", json={"project_version_id": version["id"], "profile": profile}).raise_for_status().json()["analysis_id"]
    deadline = time.time() + 240
    while time.time() < deadline:
        a = c.get(f"/analyses/{analysis_id}").raise_for_status().json()["data"]
        if a["status"] in TERMINAL and a["decision"]:
            return a
        time.sleep(2)
    raise AssertionError(f"el análisis {analysis_id} no terminó: {a['status']}")


def codes(a: dict) -> set[str]:
    return {r["code"] for r in a["decision"]["reasons"]}


def test_vulnerable_php_project_is_blocked(dev):
    a = analyze(dev, zip_project("php-vulnerable"))
    assert a["decision"]["result"] in ("REJECTED", "REVIEW_REQUIRED"), a["decision"]
    assert {"CRITICAL_FINDINGS", "EXPOSED_SECRETS"} <= codes(a)
    assert a["decision"]["deployable"] is False
    findings = dev.get(f"/analyses/{a['id']}/findings", params={"per_page": 200}).json()["data"]
    blob = json.dumps(findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob and "S3cr3t-Pr0d-P4ss!" not in blob, "los secretos nunca se almacenan en claro"


def test_clean_project_is_approved_and_gate_blocks_on_hash_change(dev, tmp_path):
    payload = zip_project("php-clean", composer("7.15.2"))
    a = analyze(dev, payload)
    assert a["decision"]["result"] == "APPROVED", a["decision"]["reasons"]
    assert all(j["status"] == "SUCCEEDED" for j in a["jobs"] if j["mandatory"])

    token = dev.get(f"/analyses/{a['id']}/decision/token").raise_for_status().text
    pub = dev.get("/authorization/public-key").json()["data"]["public_key_b64"]
    artifact = tmp_path / "app.zip"
    artifact.write_bytes(payload)
    import hashlib

    sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert verify_token(token, pub, sha, "vulnix-local")["valid"]
    tampered = hashlib.sha256(payload + b"\n").hexdigest()
    result = verify_token(token, pub, tampered, "vulnix-local")
    assert not result["valid"] and "ARTIFACT_HASH_MISMATCH" in result["errors"]

    for fmt in ("pdf", "sarif", "json", "html"):
        r = dev.get(f"/analyses/{a['id']}/report", params={"format": fmt})
        assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == r.headers["X-Vulnix-SHA256"]


def test_known_vulnerable_dependency_is_rejected(dev):
    a = analyze(dev, zip_project("php-clean", composer("7.8.0")))
    assert a["decision"]["result"] == "REJECTED", a["decision"]["reasons"]
    assert "HIGH_FINDINGS" in codes(a)
    sca = dev.get(f"/analyses/{a['id']}/findings", params={"category": "sca"}).json()["data"]
    assert any(f["rule_id"] == "GHSA-v5mv-p594-2x33" for f in sca)


def test_strict_profile_is_inconclusive_without_dast_and_tests(dev):
    a = analyze(dev, zip_project("php-clean", composer("7.15.2")), profile="web-production-strict")
    assert a["status"] == "INCONCLUSIVE" and a["decision"]["result"] == "INCONCLUSIVE"
    assert {"REQUIRED_CONTROL_NOT_EXECUTED", "TESTS_NOT_EXECUTED"} <= codes(a)
    dast = next(j for j in a["jobs"] if j["analyzer"] == "vulnix-dast")
    assert dast["status"] == "FAILED" and dast["error_type"] == "ANALYZER_NOT_INSTALLED"


def test_missing_lockfile_is_inconclusive(dev):
    a = analyze(dev, zip_project("js-clean", {"package.json": json.dumps({"dependencies": {"express": "^4"}})}))
    assert a["decision"]["result"] == "INCONCLUSIVE"
    sca = next(j for j in a["jobs"] if j["analyzer"] == "vulnix-sca")
    assert sca["error_type"] == "MISSING_LOCKFILE"


def test_hostile_zip_is_rejected_at_ingest(dev):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../../evil.php", "<?php system($_GET['c']);")
    project = dev.post("/projects", json={"name": f"E2E hostil {time.time_ns()}", "criticality": "LOW"}).json()["data"]
    r = dev.post(f"/projects/{project['id']}/versions", data={"version": "1.0.0"}, files={"file": ("x.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 422 and r.json()["error"]["code"] == "ZIP_PATH_TRAVERSAL"
