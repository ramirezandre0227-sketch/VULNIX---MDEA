"""Verificador fuera de línea de autorizaciones de despliegue (manual §7).

El pipeline de despliegue ejecuta:
    vulnix-verify --token autorizacion.jws --artifact build.zip --public-key vulnix-ed25519.pub
y SOLO instala si el código de salida es 0. Comprueba firma Ed25519 (JWS EdDSA), emisor, vigencia,
resultado APPROVED e identidad exacta del artefacto (SHA-256). Un cambio de hash invalida la autorización.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TYP = "vulnix-deploy-authz+jwt"


def _b64url_decode(text: str) -> bytes:
    if not text or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in text):
        raise ValueError("base64url inválido")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def verify_token(token: str, public_key_b64: str, artifact_sha256: str | None, issuer: str | None = None,
                 now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else now
    errors: list[str] = []
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"valid": False, "errors": ["MALFORMED_TOKEN"], "claims": None}
    try:
        header = json.loads(_b64url_decode(parts[0]))
        claims = json.loads(_b64url_decode(parts[1]))
        signature = _b64url_decode(parts[2])
    except (ValueError, json.JSONDecodeError):
        return {"valid": False, "errors": ["MALFORMED_TOKEN"], "claims": None}

    if header.get("alg") != "EdDSA" or header.get("typ") != TYP:
        return {"valid": False, "errors": ["UNSUPPORTED_ALGORITHM"], "claims": claims}
    try:
        raw_pub = base64.b64decode(public_key_b64.strip(), validate=True)
        key = Ed25519PublicKey.from_public_bytes(raw_pub)
    except ValueError:
        return {"valid": False, "errors": ["PUBLIC_KEY_INVALID"], "claims": claims}
    if header.get("kid") != hashlib.sha256(raw_pub).hexdigest()[:16]:
        errors.append("KEY_ID_MISMATCH")
    try:
        key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
    except InvalidSignature:
        return {"valid": False, "errors": ["SIGNATURE_INVALID"], "claims": claims}

    if issuer is not None and claims.get("iss") != issuer:
        errors.append("ISSUER_MISMATCH")
    exp = claims.get("exp")
    if not isinstance(exp, int) or exp <= now:
        errors.append("EXPIRED")
    if claims.get("result") != "APPROVED":
        errors.append("NOT_APPROVED")
    if artifact_sha256 is not None and claims.get("artifact_sha256") != artifact_sha256.lower():
        errors.append("ARTIFACT_HASH_MISMATCH")
    return {"valid": not errors, "errors": errors, "claims": claims}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verifica una autorización de despliegue VULNIX contra el artefacto exacto.")
    p.add_argument("--token", required=True, type=Path, help="Fichero .jws emitido por VULNIX")
    p.add_argument("--artifact", required=True, type=Path, help="Artefacto que se va a desplegar")
    p.add_argument("--public-key", required=True, type=Path, help="Clave pública Ed25519 (base64) fijada en el pipeline")
    p.add_argument("--issuer", default="vulnix-local")
    p.add_argument("--json", action="store_true", help="Salida JSON")
    args = p.parse_args(argv)

    try:
        token = args.token.read_text(encoding="ascii")
        pub = args.public_key.read_text(encoding="ascii")
        sha = _sha256(args.artifact)
    except OSError as exc:
        print(f"DESPLIEGUE BLOQUEADO: no se pudo leer la entrada ({exc.__class__.__name__})", file=sys.stderr)
        return 2
    result = verify_token(token, pub, sha, args.issuer)
    result["artifact_sha256"] = sha
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif result["valid"]:
        c = result["claims"]
        print(f"AUTORIZADO: análisis {c['analysis_id']} · política {c['policy_code']} v{c['policy_version']} · vence {c['expires_at']}")
    else:
        print("DESPLIEGUE BLOQUEADO: " + ", ".join(result["errors"]), file=sys.stderr)
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
