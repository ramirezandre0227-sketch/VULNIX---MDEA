"""Extracción segura de ZIP bajo supuesto de entrada adversarial (manual §8).

Defensa en profundidad: la API ya validó el ZIP en la ingesta, pero el worker vuelve a validar
con las mismas reglas antes de escribir un solo byte, y cuenta bytes reales (no confía en cabeceras).
"""

from __future__ import annotations

import os
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.I)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class ExtractionError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ExtractLimits:
    max_files: int = 20000
    max_total_bytes: int = 500 * 1024 * 1024
    max_file_bytes: int = 50 * 1024 * 1024
    max_ratio: int = 100
    max_path_length: int = 1024
    max_depth: int = 48


def validate_member_name(name: str, limits: ExtractLimits) -> str:
    if not name or _CONTROL.search(name):
        raise ExtractionError("ZIP_PATH_INVALID", "nombre de entrada inválido")
    name = name.replace("\\", "/")  # misma normalización que la API
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ExtractionError("ZIP_PATH_TRAVERSAL", f"ruta absoluta: {name!r}")
    if len(name) > limits.max_path_length:
        raise ExtractionError("ZIP_PATH_INVALID", "ruta demasiado larga")
    parts = name.rstrip("/").split("/")
    if len(parts) > limits.max_depth:
        raise ExtractionError("ZIP_PATH_INVALID", "profundidad excesiva")
    for seg in parts:
        if seg in ("", ".", ".."):
            raise ExtractionError("ZIP_PATH_TRAVERSAL", f"recorrido de directorios: {name!r}")
        if ":" in seg or _WINDOWS_RESERVED.match(seg) or seg.endswith((" ", ".")):
            raise ExtractionError("ZIP_PATH_INVALID", f"nombre reservado o ambiguo: {name!r}")
    return name


def safe_extract(zip_path: Path, dest: Path, limits: ExtractLimits | None = None) -> list[str]:
    """Extrae `zip_path` en `dest` (que debe existir y estar vacío). Devuelve las rutas relativas extraídas."""
    limits = limits or ExtractLimits()
    dest = dest.resolve()
    archive_size = max(zip_path.stat().st_size, 1)
    extracted: list[str] = []
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > limits.max_files:
            raise ExtractionError("ZIP_TOO_MANY_FILES", "demasiadas entradas")
        seen: set[str] = set()
        declared_total = 0
        plan: list[tuple[zipfile.ZipInfo, str]] = []
        for info in infos:
            name = validate_member_name(info.filename, limits)
            if info.flag_bits & 0x1:
                raise ExtractionError("ZIP_ENCRYPTED_ENTRY", f"entrada cifrada: {name!r}")
            mode = (info.external_attr >> 16) & 0xFFFF
            ftype = stat.S_IFMT(mode)
            if info.create_system == 3 and ftype not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ExtractionError("ZIP_SPECIAL_ENTRY", f"enlace simbólico o fichero especial: {name!r}")
            key = name.rstrip("/").lower()
            if key in seen:
                raise ExtractionError("ZIP_DUPLICATE_ENTRY", f"entrada duplicada: {name!r}")
            seen.add(key)
            if name.endswith("/"):
                continue
            if info.file_size > limits.max_file_bytes:
                raise ExtractionError("ZIP_FILE_TOO_LARGE", f"fichero demasiado grande: {name!r}")
            if info.file_size > (1 << 20) and info.compress_size and info.file_size // info.compress_size > limits.max_ratio:
                raise ExtractionError("ZIP_BOMB_SUSPECTED", f"razón de compresión anómala: {name!r}")
            declared_total += info.file_size
            if declared_total > limits.max_total_bytes:
                raise ExtractionError("ZIP_TOO_LARGE", "contenido descomprimido excesivo")
            plan.append((info, name))
        if declared_total > (1 << 20) and declared_total // archive_size > limits.max_ratio:
            raise ExtractionError("ZIP_BOMB_SUSPECTED", "razón de compresión global anómala")

        real_total = 0
        for info, name in plan:
            target = (dest / PurePosixPath(name)).resolve()
            if dest not in target.parents:
                raise ExtractionError("ZIP_PATH_TRAVERSAL", f"destino fuera del sandbox: {name!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            # O_EXCL: nunca sobrescribir ni seguir un enlace preexistente.
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with zf.open(info) as src, os.fdopen(fd, "wb") as out:
                while chunk := src.read(1 << 16):
                    written += len(chunk)
                    real_total += len(chunk)
                    if written > info.file_size or written > limits.max_file_bytes or real_total > limits.max_total_bytes:
                        raise ExtractionError("ZIP_SIZE_MISMATCH", f"tamaño real excede la cabecera: {name!r}")
                    out.write(chunk)
            if written != info.file_size:
                raise ExtractionError("ZIP_SIZE_MISMATCH", f"tamaño real distinto de la cabecera: {name!r}")
            os.chmod(target, stat.S_IREAD)  # el código analizado es de solo lectura
            extracted.append(name)
    return extracted
