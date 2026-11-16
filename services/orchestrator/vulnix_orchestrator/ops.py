"""Respaldo cifrado y restauración (manual §11: respaldo cifrado, RPO/RTO, restauración ensayada).

  python -m vulnix_orchestrator.ops backup  --out <dir>                       (VULNIX_BACKUP_PASSPHRASE)
  python -m vulnix_orchestrator.ops restore --file <backup.vxb> --dsn <dsn_destino> --data-dir <dir>
  python -m vulnix_orchestrator.ops verify-restore --dsn <dsn_destino>

Formato .vxb: cabecera JSON + tar (pg_dump -Fc + directorio de datos + claves públicas) cifrado por bloques
con AES-256-GCM; clave derivada con scrypt de una frase de paso que NUNCA se guarda junto al respaldo.
La clave privada de firma NO se incluye: debe custodiarse aparte (ver runbook de rotación de claves).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from vulnix_core.config import Settings

MAGIC = b"VULNIXBK1"
CHUNK = 1 << 20


def _key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 16:
        raise SystemExit("La frase de paso del respaldo debe tener al menos 16 caracteres.")
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def encrypt_stream(src: io.BufferedReader, dst: io.BufferedWriter, passphrase: str, meta: dict) -> None:
    salt, prefix = os.urandom(16), os.urandom(8)
    header = json.dumps({**meta, "kdf": "scrypt-n32768-r8-p1", "cipher": "AES-256-GCM-chunked", "chunk": CHUNK}).encode()
    aead = AESGCM(_key(passphrase, salt))
    dst.write(MAGIC + salt + prefix + struct.pack(">I", len(header)) + header)
    index, chunk = 0, src.read(CHUNK)
    while True:
        nxt = src.read(CHUNK)
        last = not nxt
        aad = header + struct.pack(">Q?", index, last)
        ct = aead.encrypt(prefix + struct.pack(">I", index), chunk, aad)
        dst.write(struct.pack(">I", len(ct)) + ct)
        if last:
            break
        index, chunk = index + 1, nxt


def decrypt_stream(src: io.BufferedReader, dst: io.BufferedWriter, passphrase: str) -> dict:
    if src.read(len(MAGIC)) != MAGIC:
        raise SystemExit("No es un respaldo VULNIX.")
    salt, prefix = src.read(16), src.read(8)
    header = src.read(struct.unpack(">I", src.read(4))[0])
    aead = AESGCM(_key(passphrase, salt))
    index = 0
    while True:
        size_raw = src.read(4)
        if not size_raw:
            raise SystemExit("Respaldo truncado: falta el bloque final.")
        ct = src.read(struct.unpack(">I", size_raw)[0])
        for last in (False, True):
            try:
                pt = aead.decrypt(prefix + struct.pack(">I", index), ct, header + struct.pack(">Q?", index, last))
                break
            except Exception:  # noqa: BLE001 - etiqueta inválida para esta hipótesis
                pt = None
        if pt is None:
            raise SystemExit("Integridad del respaldo comprometida o frase de paso incorrecta.")
        dst.write(pt)
        if last:
            return json.loads(header)
        index += 1


def _pg(tool: str) -> str:
    bindir = os.environ.get("VULNIX_PG_BIN_DIR", r"C:\Program Files\PostgreSQL\16\bin" if os.name == "nt" else "/usr/bin")
    exe = Path(bindir) / (f"{tool}.exe" if os.name == "nt" else tool)
    return str(exe) if exe.exists() else tool


def _pg_env(dsn: str) -> tuple[list[str], dict]:
    u = urlparse(dsn)
    env = {**os.environ, "PGPASSWORD": u.password or ""}
    return ["-h", u.hostname or "127.0.0.1", "-p", str(u.port or 5432), "-U", u.username or "", "-d", u.path.lstrip("/")], env


def backup(settings: Settings, out_dir: Path, passphrase: str) -> Path:
    if not settings.admin_dsn:
        raise SystemExit("VULNIX_ADMIN_DSN es necesario para el respaldo.")
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with tempfile.TemporaryDirectory() as tmp:
        dump = Path(tmp) / "vulnix.dump"
        args, env = _pg_env(settings.admin_dsn)
        subprocess.run([_pg("pg_dump"), "-Fc", "--no-owner", "-f", str(dump), *args], check=True, env=env)
        tar_path = Path(tmp) / "bundle.tar"
        with tarfile.open(tar_path, "w") as tar:
            tar.add(dump, "db/vulnix.dump")
            if settings.data_dir.exists():
                tar.add(settings.data_dir, "data")
        target = out_dir / f"vulnix-{stamp}.vxb"
        with tar_path.open("rb") as src, target.open("wb") as dst:
            encrypt_stream(src, dst, passphrase, {"created_at": stamp, "source_db": urlparse(settings.admin_dsn).path.lstrip("/")})
    return target


def restore(file: Path, dsn: str, data_dir: Path, passphrase: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "bundle.tar"
        with file.open("rb") as src, tar_path.open("wb") as dst:
            meta = decrypt_stream(src, dst, passphrase)
        with tarfile.open(tar_path) as tar:
            tar.extractall(tmp, filter="data")  # filtro seguro de Python 3.12 (sin rutas absolutas ni enlaces fuera)
        args, env = _pg_env(dsn)
        subprocess.run([_pg("pg_restore"), "--clean", "--if-exists", "--no-owner", "--exit-on-error", *args, str(Path(tmp) / "db" / "vulnix.dump")], check=True, env=env)
        if (Path(tmp) / "data").exists():
            data_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(Path(tmp) / "data", data_dir, dirs_exist_ok=True)
    return meta


def verify_restore(dsn: str) -> dict:
    import psycopg

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        counts = {}
        for t in ("identity.users", "catalog.projects", "catalog.project_versions", "catalog.policies", "evaluation.analyses",
                  "evaluation.findings", "evaluation.decisions", "audit.audit_logs"):
            cur.execute(f"SELECT count(*) FROM {t}")  # noqa: S608 - nombres fijos
            counts[t] = cur.fetchone()[0]
        cur.execute("""SELECT count(*) FROM (
                         SELECT hash, prev_hash, lag(hash) OVER (ORDER BY seq) AS expected_prev,
                                audit.row_hash(prev_hash, seq, actor_id, actor_type, action, entity_type, entity_id, event_json, created_at) AS recomputed
                         FROM audit.audit_logs) t
                       WHERE hash IS DISTINCT FROM recomputed OR prev_hash IS DISTINCT FROM expected_prev""")
        broken = cur.fetchone()[0]
    return {"counts": counts, "audit_chain_valid": broken == 0}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vulnix-ops")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--out", type=Path, required=True)
    r = sub.add_parser("restore")
    r.add_argument("--file", type=Path, required=True)
    r.add_argument("--dsn", required=True, help="Base de datos DESTINO (vacía o de ensayo)")
    r.add_argument("--data-dir", type=Path, required=True)
    v = sub.add_parser("verify-restore")
    v.add_argument("--dsn", required=True)
    args = p.parse_args(argv)
    settings = Settings.load()
    passphrase = os.environ.get("VULNIX_BACKUP_PASSPHRASE", "")
    started = time.time()
    if args.cmd == "backup":
        path = backup(settings, args.out, passphrase)
        print(f"Respaldo cifrado: {path} ({path.stat().st_size} bytes, {time.time() - started:.1f}s)")
    elif args.cmd == "restore":
        meta = restore(args.file, args.dsn, args.data_dir, passphrase)
        print(f"Restaurado respaldo {meta['created_at']} en {time.time() - started:.1f}s")
    else:
        print(json.dumps(verify_restore(args.dsn), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
