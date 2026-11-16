"""Runner de calidad: verificación sintáctica (equivalente de "build" en lenguajes interpretados),
métricas y patrones de depuración olvidados.

- PHP: `php -n -l` por fichero (solo analiza, no ejecuta).
- JavaScript: `node --check` (solo analiza, no ejecuta).
- TypeScript: solo si hay compilador configurado (--tsc); se consideran los diagnósticos sintácticos TS1xxx.
  Sin compilador, los .ts/.tsx quedan como NO verificados -> build.passed = null (fail closed).
- Pruebas y cobertura: NO se ejecutan aquí. Ejecutar código del proyecto exige un sandbox de ejecución
  aislado (VM desechable, manual §8). Se informa explícitamente como no ejecutado.

Uso: python -I -m vulnix_adapters.builtin.quality_runner <src> <out.json> --php <bin> --node <bin> [--tsc <bin>]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import RUNNER_VERSION
from .common import iter_source_files, read_text, write_json

MAX_LINT_FILES = 5000
_PHP_ERR = re.compile(r"(?:PHP )?(Parse error|Fatal error):\s*(.+?) in (.+?) on line (\d+)")
_NODE_LINE = re.compile(r":(\d+)\s*$")
_NODE_ERR = re.compile(r"^(SyntaxError|TypeError|ReferenceError):\s*(.+)$", re.M)
_TSC_ERR = re.compile(r"^(.+?)\((\d+),(\d+)\):\s*error\s+TS(1\d{3}):\s*(.+)$", re.M)
_DECISION = re.compile(r"\b(if|elseif|for|foreach|while|case|catch)\b|&&|\|\||\?\?|(?<![?.])\?(?![?.:])")
_PHP_DEBUG = re.compile(r"\b(var_dump|print_r|var_export|dd|dump|debug_zval_dump|error_log)\s*\(")
_JS_DEBUG = re.compile(r"^\s*debugger\s*;?\s*$")


def tool_version(argv: list[str]) -> str | None:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return (r.stdout or r.stderr).strip().splitlines()[0][:120] if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


def lint_php(php: str, path: Path, rel: str) -> dict | None:
    r = subprocess.run([php, "-n", "-d", "display_errors=1", "-l", str(path)], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        return None
    m = _PHP_ERR.search(r.stdout + r.stderr)
    return {"file": rel, "line": int(m.group(4)) if m else None, "message": (m.group(2) if m else (r.stdout + r.stderr).strip())[:300], "tool": "php -l"}


def lint_node(node: str, path: Path, rel: str) -> dict | None:
    r = subprocess.run([node, "--check", str(path)], capture_output=True, text=True, timeout=30)
    if r.returncode == 0:
        return None
    first = (r.stderr.splitlines() or [""])[0]
    line = _NODE_LINE.search(first)
    msg = _NODE_ERR.search(r.stderr)
    return {"file": rel, "line": int(line.group(1)) if line else None,
            "message": (msg.group(0) if msg else r.stderr.strip())[:300], "tool": "node --check"}


def lint_ts(tsc: str, src: Path, files: list[tuple[Path, str]]) -> list[dict]:
    errors: list[dict] = []
    for i in range(0, len(files), 200):
        chunk = files[i:i + 200]
        r = subprocess.run([tsc, "--noEmit", "--noResolve", "--skipLibCheck", "--pretty", "false", "--jsx", "preserve",
                            *[str(p) for p, _ in chunk]], capture_output=True, text=True, timeout=300, cwd=src)
        for m in _TSC_ERR.finditer(r.stdout):  # TS1xxx = errores sintácticos
            try:
                rel = Path(m.group(1)).resolve().relative_to(src).as_posix()
            except ValueError:
                rel = m.group(1)
            errors.append({"file": rel, "line": int(m.group(2)), "message": f"TS{m.group(4)}: {m.group(5)}"[:300], "tool": "tsc"})
    return errors


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("src", type=Path)
    p.add_argument("out", type=Path)
    p.add_argument("--php", default="php")
    p.add_argument("--node", default="node")
    p.add_argument("--tsc", default=None)
    args = p.parse_args()
    src = args.src.resolve()
    started = time.time()

    php_files, js_files, ts_files, unverified = [], [], [], {"jsx_vue": 0, "typescript": 0}
    metrics = {"files": 0, "loc": {}, "max_complexity": 0, "high_complexity_files": 0}
    findings: list[dict] = []
    for path, rel in iter_source_files(src):
        lower = rel.lower()
        text = read_text(path)
        if text is None:
            continue
        lang = "php" if lower.endswith((".php", ".phtml")) else "ts" if lower.endswith((".ts", ".tsx")) else \
            "js" if lower.endswith((".js", ".mjs", ".cjs")) else "jsx" if lower.endswith((".jsx", ".vue")) else "markup"
        metrics["files"] += 1
        lines = text.splitlines()
        loc = sum(1 for ln in lines if ln.strip())
        metrics["loc"][lang] = metrics["loc"].get(lang, 0) + loc
        if lang in ("php", "js", "ts", "jsx"):
            complexity = 1 + len(_DECISION.findall(text))
            metrics["max_complexity"] = max(metrics["max_complexity"], complexity)
            if complexity > 120 and loc > 300:
                metrics["high_complexity_files"] += 1
                findings.append({"rule_id": "quality.high-complexity", "file": rel, "line": 1, "severity": "LOW", "confidence": "MEDIUM",
                                 "message": f"Complejidad ciclomática aproximada {complexity} en {loc} líneas de código."})
        for no, ln in enumerate(lines, 1):
            if lang == "php" and _PHP_DEBUG.search(ln) and not ln.lstrip().startswith(("//", "#", "*")):
                findings.append({"rule_id": "quality.debug-output", "file": rel, "line": no, "severity": "LOW", "confidence": "MEDIUM",
                                 "message": "Salida de depuración (var_dump/print_r/dd...) en el código."})
            elif lang in ("js", "ts", "jsx") and _JS_DEBUG.match(ln):
                findings.append({"rule_id": "quality.debugger-statement", "file": rel, "line": no, "severity": "LOW", "confidence": "HIGH",
                                 "message": "Sentencia debugger olvidada."})
        if lang == "php":
            php_files.append((path, rel))
        elif lang == "js":
            js_files.append((path, rel))
        elif lang == "ts":
            ts_files.append((path, rel))
        elif lang == "jsx":
            unverified["jsx_vue"] += 1

    tools = {"php": tool_version([args.php, "-n", "-v"]) if php_files else None,
             "node": tool_version([args.node, "--version"]) if js_files else None,
             "tsc": tool_version([args.tsc, "--version"]) if (args.tsc and ts_files) else None}
    errors: list[dict] = []
    complete = len(php_files) + len(js_files) <= MAX_LINT_FILES
    missing_tool = (php_files and not tools["php"]) or (js_files and not tools["node"])
    if complete and not missing_tool:
        with ThreadPoolExecutor(max_workers=4) as pool:
            jobs = [pool.submit(lint_php, args.php, p, r) for p, r in php_files] + [pool.submit(lint_node, args.node, p, r) for p, r in js_files]
            errors = [e for j in jobs if (e := j.result())]
        if ts_files and tools["tsc"]:
            errors += lint_ts(args.tsc, src, ts_files)
        elif ts_files:
            unverified["typescript"] = len(ts_files)

    for e in errors:
        findings.append({"rule_id": "quality.syntax-error", "file": e["file"], "line": e["line"], "severity": "MEDIUM",
                         "confidence": "HIGH", "message": f"{e['tool']}: {e['message']}"})

    fully_verified = complete and not missing_tool and unverified["typescript"] == 0
    if errors:
        passed: bool | None = False
    else:
        passed = True if fully_verified else None
    reason = None
    if not complete:
        reason = f"Más de {MAX_LINT_FILES} ficheros: verificación incompleta."
    elif missing_tool:
        reason = "Intérprete PHP/Node no disponible para la verificación sintáctica."
    elif unverified["typescript"]:
        reason = "Ficheros TypeScript sin compilador configurado (VULNIX_TSC_BIN): no verificados."

    write_json(args.out, {
        "tool": "vulnix-quality", "runner_version": RUNNER_VERSION,
        "build": {"executed": True, "passed": passed, "errors": len(errors), "checked_files": len(php_files) + len(js_files) + (len(ts_files) if tools["tsc"] else 0),
                  "unverified": unverified, "tools": tools, "reason": reason},
        "tests": {"executed": False, "passed": None,
                  "reason": "La ejecución de pruebas requiere un sandbox de ejecución aislado (VM desechable); no habilitado en este entorno."},
        "coverage": {"line_pct": None},
        "metrics": metrics, "duration_s": round(time.time() - started, 3), "findings": findings,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
