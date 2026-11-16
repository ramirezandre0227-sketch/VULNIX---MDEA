"""Integración: adaptadores reales ejecutados en el sandbox (subproceso aislado) sobre el corpus empaquetado."""

import json
import shutil
from pathlib import Path

import pytest

from conftest import zip_dir
from vulnix_adapters.base import AdapterError
from vulnix_adapters.builtin_adapters import VulnixQuality, VulnixSast, VulnixSca, VulnixSecrets
from vulnix_core.models import AnalysisContext
from vulnix_core.schema import validate_finding
from vulnix_sandbox.runner import Sandbox

CORPUS = Path(__file__).resolve().parents[1] / "corpus"


def run_adapter(adapter, project: str, tmp_path, extra_files: dict | None = None):
    src = tmp_path / "proj"
    shutil.copytree(CORPUS / project, src)
    for rel, content in (extra_files or {}).items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(content, encoding="utf-8")
    zpath = tmp_path / "a.zip"
    zpath.write_bytes(zip_dir(src))
    with Sandbox(tmp_path / "sbx", "itest") as sb:
        sb.materialize(zpath, "ZIP", "a.zip")
        ctx = AnalysisContext("a", "j", "x" * 64, sb.src, sb.out, {})
        raw = adapter.execute(adapter.prepare(ctx), sb)
        findings = adapter.normalize(raw)
        meta = adapter.job_metadata(raw)
    return findings, meta


def test_sast_adapter_end_to_end(tmp_path):
    findings, meta = run_adapter(VulnixSast(), "php-vulnerable", tmp_path)
    rules = {f.rule_id for f in findings}
    assert {"php.sql-injection", "php.xss.reflected", "php.command-injection", "php.file-inclusion"} <= rules
    assert all(validate_finding(f.to_dict()) == [] for f in findings)
    assert meta["files_scanned"] >= 3


def test_secrets_adapter_never_persists_secret_values(tmp_path):
    findings, _ = run_adapter(VulnixSecrets(), "php-vulnerable", tmp_path)
    blob = json.dumps([f.to_dict() for f in findings])
    for secret in ("AKIAIOSFODNN7EXAMPLE", "sk_live_51HxQ2bLkdj39sKd02mZ", "S3cr3t-Pr0d-P4ss!", "Pr0dPassw0rd2026"):
        assert secret not in blob
    assert len(findings) >= 5 and all("[REDACTED len=" in f.snippet for f in findings)


class FakeIntel:
    def __init__(self, advisories, imported_at="2026-11-14T00:00:00+00:00"):
        self._adv, self._at = advisories, imported_at

    def snapshot(self, eco):
        return {"imported_at": self._at, "records": len(self._adv), "sha256": "f" * 64}

    def advisories(self, eco, name):
        return [a for a in self._adv if any(x["package"]["name"] == name for x in a["affected"])]


LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"},
                                                      "node_modules/express": {"version": "4.19.2"}}})
ADV = {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "summary": "Command Injection in lodash",
       "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
       "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-77"]}}


def test_sca_adapter_matches_lockfile_against_intel(tmp_path):
    findings, meta = run_adapter(VulnixSca(FakeIntel([ADV])), "js-clean", tmp_path,
                                 {"package.json": '{"dependencies":{"lodash":"^4.17.0"}}', "package-lock.json": LOCK})
    assert [f.rule_id for f in findings] == ["GHSA-35jh-r3h4-6jhm"]
    assert findings[0].severity == "HIGH" and "4.17.21" in findings[0].remediation
    assert meta["components"] == 2 and "npm" in meta["intel"]["ecosystems"]


def test_sca_fails_closed_without_lockfile(tmp_path):
    with pytest.raises(AdapterError) as exc:
        run_adapter(VulnixSca(FakeIntel([])), "js-clean", tmp_path, {"package.json": '{"dependencies":{"lodash":"^4"}}'})
    assert exc.value.error_type == "MISSING_LOCKFILE"


def test_sca_fails_closed_without_intel(tmp_path):
    with pytest.raises(AdapterError) as exc:
        run_adapter(VulnixSca(None), "js-clean", tmp_path, {"package.json": "{}", "package-lock.json": LOCK})
    assert exc.value.error_type == "INTEL_UNAVAILABLE"


@pytest.mark.skipif(not (shutil.which("php") or Path("C:/xampp/php/php.exe").exists()) or not shutil.which("node"), reason="requiere php y node")
def test_quality_detects_syntax_errors_and_reports_tests_not_executed(tmp_path):
    php = shutil.which("php") or "C:/xampp/php/php.exe"
    findings, meta = run_adapter(VulnixQuality(php, "node"), "php-clean", tmp_path,
                                 {"broken.php": "<?php\n$y = ;\n", "ok.js": "const a = 1;\n", "bad.js": "const = ;\n"})
    syntax = sorted((f.file, f.rule_id) for f in findings if f.rule_id == "quality.syntax-error")
    assert syntax == [("bad.js", "quality.syntax-error"), ("broken.php", "quality.syntax-error")]
    assert meta["build"]["passed"] is False
    assert meta["tests"]["executed"] is False and meta["tests"]["passed"] is None
