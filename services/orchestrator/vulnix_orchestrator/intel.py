"""Inteligencia de vulnerabilidades OSV: sincronización offline firmada e importación (manual §13).

Flujo recomendado (red interna sin acceso a Internet):
  1) En una máquina con salida controlada:
       vulnix-intel fetch --ecosystem npm --out ./intel --sign-key org-intel.key
     descarga https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip y genera un manifiesto
     firmado (Ed25519) con el SHA-256 del zip y la fecha de obtención.
  2) Se transfiere por el canal aprobado y en VULNIX:
       vulnix-intel import --file ./intel/npm-all.zip --manifest ./intel/npm-all.manifest.json --public-key org-intel.pub
La frescura (intelligence.max_age_days) se mide con la fecha de los DATOS (fetched_at firmado o, sin manifiesto,
la modificación más reciente de los avisos), nunca con la fecha de importación.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from vulnix_core.config import Settings

ECOSYSTEMS = {"npm": "npm", "packagist": "Packagist", "Packagist": "Packagist"}
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"


class DbIntelStore:
    """Lectura de la inteligencia importada (rol del orquestador: solo SELECT)."""

    def __init__(self, conn: psycopg.Connection):
        self.conn = conn
        self._cache: dict[tuple[str, str], list[dict]] = {}

    def snapshot(self, ecosystem: str) -> dict | None:
        with self.conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""SELECT imported_at, record_count, sha256 FROM catalog.intel_feeds
                           WHERE ecosystem = %s ORDER BY imported_at DESC LIMIT 1""", (ecosystem,))
            row = cur.fetchone()
        if not row:
            return None
        return {"imported_at": row["imported_at"].astimezone(timezone.utc).isoformat(), "records": row["record_count"], "sha256": row["sha256"]}

    def advisories(self, ecosystem: str, name: str) -> list[dict]:
        key = (ecosystem, name.lower())
        if key not in self._cache:
            with self.conn.cursor() as cur:
                cur.execute("SELECT data FROM catalog.advisories WHERE ecosystem = %s AND lower(package_name) = %s", key)
                self._cache[key] = [r[0] for r in cur.fetchall()]
        return self._cache[key]


# ----------------------------------------------------------------------------- importación
def _iter_advisories(path: Path) -> Iterator[dict]:
    if path.is_dir():
        for f in sorted(path.rglob("*.json")):
            yield json.loads(f.read_text(encoding="utf-8"))
        return
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.filename.endswith(".json") and info.file_size < 5 * 1024 * 1024:
                yield json.loads(zf.read(info))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    if path.is_dir():
        for f in sorted(path.rglob("*.json")):
            h.update(f.read_bytes())
        return h.hexdigest()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest(manifest_path: Path, public_key_path: Path, file_sha: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    doc = json.loads(manifest_path.read_text(encoding="utf-8"))
    body = json.dumps(doc["manifest"], sort_keys=True, separators=(",", ":")).encode()
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_path.read_text().strip()))
    key.verify(base64.b64decode(doc["signature"]), body)  # lanza InvalidSignature
    if doc["manifest"]["sha256"] != file_sha:
        raise ValueError("el SHA-256 del fichero no coincide con el manifiesto firmado")
    return doc["manifest"]


def import_feed(dsn: str, ecosystem: str, path: Path, manifest: dict | None = None) -> dict:
    eco = ECOSYSTEMS.get(ecosystem, ecosystem)
    file_sha = _sha256(path)
    rows, latest_modified = [], None
    for adv in _iter_advisories(path):
        if adv.get("withdrawn"):
            continue
        modified = adv.get("modified")
        if modified and (latest_modified is None or modified > latest_modified):
            latest_modified = modified
        for aff in adv.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != eco or not pkg.get("name"):
                continue
            sev = (adv.get("database_specific") or {}).get("severity")
            rows.append((adv["id"][:128], eco, pkg["name"][:255], sev[:16] if isinstance(sev, str) else None, Jsonb(adv), modified))
    if manifest:
        data_as_of = manifest["fetched_at"]
    elif latest_modified:
        data_as_of = min(latest_modified, datetime.now(timezone.utc).isoformat())
    else:
        raise ValueError("el feed no contiene avisos con fecha de modificación")

    dedup = {}
    for r in rows:
        dedup[(r[0], r[1], r[2])] = r
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("""INSERT INTO catalog.intel_feeds (ecosystem, source, sha256, record_count, imported_at)
                       VALUES (%s, %s, %s, %s, %s) RETURNING id""", (eco, path.name[:255], file_sha, len(dedup), data_as_of))
        feed_id = cur.fetchone()[0]
        cur.execute("DELETE FROM catalog.advisories WHERE ecosystem = %s", (eco,))
        with cur.copy("COPY catalog.advisories (osv_id, ecosystem, package_name, severity, data, modified, feed_id) FROM STDIN") as copy:
            for r in dedup.values():
                copy.write_row((*r, feed_id))
        cur.execute("""INSERT INTO audit.audit_logs (actor_type, action, entity_type, entity_id, event_json)
                       VALUES ('SYSTEM', 'intel.imported', 'intel_feed', %s, %s)""",
                    (str(feed_id), Jsonb({"ecosystem": eco, "sha256": file_sha, "records": len(dedup), "data_as_of": data_as_of,
                                          "signed_manifest": manifest is not None})))
    return {"ecosystem": eco, "records": len(dedup), "sha256": file_sha, "data_as_of": data_as_of, "signed": manifest is not None}


def fetch_feed(ecosystem: str, out_dir: Path, sign_key: Path | None) -> Path:
    eco = ECOSYSTEMS.get(ecosystem, ecosystem)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"{eco.lower()}-all.zip"
    with urllib.request.urlopen(OSV_URL.format(eco=eco), timeout=300) as resp, target.open("wb") as fh:  # noqa: S310 - URL fija
        while chunk := resp.read(1 << 20):
            fh.write(chunk)
    manifest = {"ecosystem": eco, "source": OSV_URL.format(eco=eco), "sha256": _sha256(target),
                "fetched_at": datetime.now(timezone.utc).isoformat()}
    doc = {"manifest": manifest}
    if sign_key:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(sign_key.read_text().strip()))
        doc["signature"] = base64.b64encode(key.sign(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())).decode()
    (out_dir / f"{eco.lower()}-all.manifest.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vulnix-intel", description="Gestión offline de la inteligencia de vulnerabilidades OSV")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="Descargar un feed OSV (máquina con salida controlada)")
    f.add_argument("--ecosystem", required=True, choices=["npm", "Packagist"])
    f.add_argument("--out", type=Path, required=True)
    f.add_argument("--sign-key", type=Path, help="Clave privada Ed25519 (base64, 32 bytes) para firmar el manifiesto")
    i = sub.add_parser("import", help="Importar un feed (zip o directorio de JSON OSV)")
    i.add_argument("--ecosystem", required=True, choices=["npm", "Packagist"])
    i.add_argument("--file", type=Path, required=True)
    i.add_argument("--manifest", type=Path)
    i.add_argument("--public-key", type=Path)
    i.add_argument("--require-signature", action="store_true", help="Rechazar feeds sin manifiesto firmado")
    s = sub.add_parser("status", help="Estado de la inteligencia importada")
    k = sub.add_parser("keygen", help="Generar par Ed25519 para firmar manifiestos de inteligencia")
    k.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    settings = Settings.load()

    if args.cmd == "fetch":
        path = fetch_feed(args.ecosystem, args.out, args.sign_key)
        print(f"Descargado {path} ({path.stat().st_size} bytes)")
        return 0
    if args.cmd == "keygen":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        args.out.mkdir(parents=True, exist_ok=True)
        raw_priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        raw_pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (args.out / "intel-signing.key").write_text(base64.b64encode(raw_priv).decode())
        (args.out / "intel-signing.pub").write_text(base64.b64encode(raw_pub).decode())
        print(f"Claves generadas en {args.out}")
        return 0
    if args.cmd == "import":
        if not settings.admin_dsn:
            print("VULNIX_ADMIN_DSN no configurado: la importación es una operación administrativa.", file=sys.stderr)
            return 2
        manifest = None
        if args.manifest:
            if not args.public_key:
                print("--manifest requiere --public-key", file=sys.stderr)
                return 2
            manifest = verify_manifest(args.manifest, args.public_key, _sha256(args.file))
        elif args.require_signature:
            print("Feed sin manifiesto firmado rechazado (--require-signature).", file=sys.stderr)
            return 2
        result = import_feed(settings.admin_dsn, args.ecosystem, args.file, manifest)
        print(json.dumps(result, indent=2))
        return 0
    if args.cmd == "status":
        with psycopg.connect(settings.db_dsn) as conn, conn.cursor() as cur:
            cur.execute("""SELECT ecosystem, max(imported_at), max(record_count) FROM catalog.intel_feeds GROUP BY ecosystem""")
            for eco, at, n in cur.fetchall():
                age = (datetime.now(timezone.utc) - at).total_seconds() / 86400
                print(f"{eco:10} datos a {at.isoformat()}  ({age:.1f} días)  {n} registros")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
