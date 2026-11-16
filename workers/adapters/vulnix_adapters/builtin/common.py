"""Utilidades de los runners integrados: recorrido acotado del árbol de código y escritura de resultados."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor", "bower_components", ".idea", ".vscode", "dist", "build", "coverage", ".next", ".nuxt", "storage"}
MAX_FILE_BYTES = 1_000_000
MAX_LINE_LEN = 4000

LANG_BY_EXT = {
    ".php": "php", ".phtml": "php",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".vue": "js",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "css",
}


def language_of(rel: str) -> str | None:
    lower = rel.lower()
    if lower.endswith(".blade.php"):
        return "php"
    if lower.endswith((".min.js", ".min.css", ".map")):
        return None
    return LANG_BY_EXT.get(os.path.splitext(lower)[1])


def iter_source_files(root: Path, include_all: bool = False) -> Iterator[tuple[Path, str]]:
    """Recorre el código sin seguir enlaces, saltando dependencias de terceros y binarios."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            if include_all or language_of(rel):
                yield path, rel


def read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def runner_args() -> tuple[Path, Path]:
    if len(sys.argv) < 3:
        print("uso: runner <workspace> <output.json> [opciones]", file=sys.stderr)
        sys.exit(64)
    return Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
