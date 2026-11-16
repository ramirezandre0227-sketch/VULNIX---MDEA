"""Unitarias: huellas, normalización, OSV/CVSS, verificador de autorizaciones."""

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnix_adapters.osv import Version, cvss3_base_score, is_affected, severity_of
from vulnix_core.fingerprint import assign_fingerprints, compute_fingerprint, correlation_key
from vulnix_core.models import Finding
from vulnix_core.redact import scrub_text
from vulnix_core.schema import validate_finding
from vulnix_core.verify import TYP, verify_token


def _finding(**kw):
    base = dict(rule_id="php.sql-injection", title="t", severity="HIGH", confidence="HIGH", category="sast",
                analyzer="vulnix-sast", description="d", file="src/a.php", line=10, snippet="$x = 1;")
    base.update(kw)
    return Finding(**base)


# ----------------------------------------------------------------------------- huellas
def test_fingerprint_is_stable_across_line_moves():
    a = assign_fingerprints([_finding(line=10)])[0].fingerprint
    b = assign_fingerprints([_finding(line=99)])[0].fingerprint
    assert a == b and a.startswith("sha256:")


def test_fingerprint_distinguishes_repeated_occurrences():
    fs = assign_fingerprints([_finding(line=1), _finding(line=2)])
    assert fs[0].fingerprint != fs[1].fingerprint


def test_fingerprint_ignores_whitespace_changes():
    assert compute_fingerprint("r", "f", "a  =   b", 0) == compute_fingerprint("r", "f", "a = b", 0)


def test_correlation_key_groups_same_location_and_cwe():
    assert correlation_key("a.php", 3, "CWE-89", "sast") == correlation_key("a.php", 3, "CWE-89", "sast")
    assert correlation_key("a.php", 3, "CWE-89", "sast") != correlation_key("a.php", 3, "CWE-79", "sast")


def test_finding_validation_rejects_bad_enums():
    with pytest.raises(ValueError):
        _finding(severity="SEVERE")
    data = assign_fingerprints([_finding()])[0].to_dict()
    assert validate_finding(data) == []
    data["cwe"] = "89"
    assert validate_finding(data)


def test_scrub_text_redacts_known_secret_formats():
    out = scrub_text("key=AKIAIOSFODNN7EXAMPLE token=ghp_" + "a" * 36)
    assert "AKIA" not in out and "ghp_" not in out and "[REDACTED len=" in out


# ----------------------------------------------------------------------------- OSV
def test_version_ordering():
    assert Version("1.2.3") < Version("1.10.0")
    assert Version("1.0.0-beta.1") < Version("1.0.0")
    assert Version("v2.0") == Version("2.0.0")
    assert Version("1.2.3.4") > Version("1.2.3")


ADV = {"id": "GHSA-test", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
       "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]}}


@pytest.mark.parametrize("version,affected", [("4.17.20", True), ("4.17.21", False), ("5.0.0", False), ("1.0.0", True)])
def test_semver_range_matching(version, affected):
    assert is_affected(ADV, "npm", "lodash", version)[0] is affected


def test_last_affected_and_explicit_versions():
    adv = {"id": "X", "affected": [{"package": {"ecosystem": "Packagist", "name": "vendor/pkg"}, "versions": ["2.0.5"],
                                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.4.2"}]}]}]}
    assert is_affected(adv, "Packagist", "vendor/pkg", "1.4.2")[0]
    assert not is_affected(adv, "Packagist", "vendor/pkg", "1.4.3")[0]
    assert is_affected(adv, "Packagist", "vendor/pkg", "2.0.5")[0]


def test_withdrawn_advisories_are_ignored():
    assert not is_affected({**ADV, "withdrawn": "2024-01-01T00:00:00Z"}, "npm", "lodash", "1.0.0")[0]


def test_cvss_v31_reference_scores():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H") == 9.9
    assert cvss3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:L") == 1.8


def test_severity_mapping():
    assert severity_of(ADV)[0] == "HIGH"
    assert severity_of({"id": "MAL-2024-1"})[0] == "CRITICAL"
    assert severity_of({"id": "Y", "database_specific": {"severity": "MODERATE"}})[0] == "MEDIUM"


# ----------------------------------------------------------------------------- verificador de despliegue
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _token(key: Ed25519PrivateKey, claims: dict, typ: str = TYP) -> tuple[str, str]:
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    header = {"alg": "EdDSA", "typ": typ, "kid": hashlib.sha256(pub).hexdigest()[:16]}
    signing_input = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(claims).encode())}"
    return f"{signing_input}.{_b64u(key.sign(signing_input.encode()))}", base64.b64encode(pub).decode()


SHA = "a" * 64


def _claims(**kw):
    c = {"iss": "vulnix-local", "exp": int(time.time()) + 3600, "result": "APPROVED", "artifact_sha256": SHA,
         "analysis_id": "x", "policy_code": "p", "policy_version": "1", "expires_at": "z"}
    c.update(kw)
    return c


def test_verify_accepts_valid_authorization():
    key = Ed25519PrivateKey.generate()
    tok, pub = _token(key, _claims())
    assert verify_token(tok, pub, SHA, "vulnix-local")["valid"]


@pytest.mark.parametrize("claims,artifact,error", [
    (_claims(), "b" * 64, "ARTIFACT_HASH_MISMATCH"),          # cambio de hash invalida la autorización
    (_claims(result="REJECTED"), SHA, "NOT_APPROVED"),
    (_claims(result="INCONCLUSIVE"), SHA, "NOT_APPROVED"),
    (_claims(exp=int(time.time()) - 1), SHA, "EXPIRED"),
    (_claims(iss="otro"), SHA, "ISSUER_MISMATCH"),
])
def test_verify_blocks_invalid_authorizations(claims, artifact, error):
    tok, pub = _token(Ed25519PrivateKey.generate(), claims)
    r = verify_token(tok, pub, artifact, "vulnix-local")
    assert not r["valid"] and error in r["errors"]


def test_verify_rejects_tampered_payload_and_foreign_key():
    key = Ed25519PrivateKey.generate()
    tok, pub = _token(key, _claims(result="REJECTED"))
    h, _, s = tok.split(".")
    forged = f"{h}.{_b64u(json.dumps(_claims()).encode())}.{s}"
    assert verify_token(forged, pub, SHA)["errors"] == ["SIGNATURE_INVALID"]
    _, other_pub = _token(Ed25519PrivateKey.generate(), _claims())
    assert "SIGNATURE_INVALID" in verify_token(tok, other_pub, SHA)["errors"]


def test_verify_rejects_alg_confusion():
    tok, pub = _token(Ed25519PrivateKey.generate(), _claims(), typ="JWT")
    assert verify_token(tok, pub, SHA)["errors"] == ["UNSUPPORTED_ALGORITHM"]
