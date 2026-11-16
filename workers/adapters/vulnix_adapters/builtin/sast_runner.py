"""Runner SAST integrado. Uso (dentro del sandbox): python -I -m vulnix_adapters.builtin.sast_runner <src> <out.json>"""

from __future__ import annotations

import re
import sys
import time

from . import RUNNER_VERSION
from .common import MAX_LINE_LEN, iter_source_files, language_of, read_text, runner_args, write_json
from .sast_rules import (JS_ASSIGN, JS_DESTRUCT, JS_SANITIZERS, JS_SOURCE, PHP_ASSIGN, PHP_SANITIZERS, PHP_SOURCE,
                         RULES, RULESET_VERSION, Rule)

_COMMENT_LINE = {
    "php": re.compile(r"^\s*(//|#(?!\[)|\*|/\*|<!--)"),
    "js": re.compile(r"^\s*(//|\*|/\*|<!--)"),
    "html": re.compile(r"^\s*(<!--|//|\*|/\*)"),
    "css": re.compile(r"^\s*(/\*|\*)"),
}
_PHP_VAR = re.compile(r"\$[A-Za-z_]\w*")
_INDEX = re.compile(r"\[[^\[\]]*\]")
_JS_IDENT = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*")


def _strip_trailing_comment(line: str) -> str:
    # Elimina comentarios // finales sin romper URLs (http://) ni cadenas simples.
    out, quote, i = [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(line):
                out.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
            out.append(ch)
        elif line.startswith("//", i) and (i == 0 or line[i - 1] != ":"):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


class TaintTracker:
    """Rastreo de contaminación intra-fichero (orden de aparición; sin análisis interprocedural)."""

    def __init__(self, lang: str):
        self.lang = lang
        self.tainted: set[str] = set()

    @staticmethod
    def _strip_indexes(rhs: str) -> str:
        """Elimina expresiones de índice: $mapa[$_GET['k']] es una búsqueda en lista blanca, no un valor contaminado.
        Las superglobales siguen detectándose ($_GET['id'] -> $_GET)."""
        prev = None
        while prev != rhs:
            prev, rhs = rhs, _INDEX.sub("", rhs)
        return rhs

    def observe(self, line: str) -> None:
        if self.lang == "php":
            for m in PHP_ASSIGN.finditer(line):
                var, rhs = m.group(1), self._strip_indexes(m.group(2))
                if (PHP_SOURCE.search(rhs) or self._uses_tainted(rhs)) and not PHP_SANITIZERS.search(rhs):
                    self.tainted.add(var)
                elif var in self.tainted and not self._uses_tainted(rhs) and not PHP_SOURCE.search(rhs):
                    self.tainted.discard(var)
        elif self.lang == "js":
            d = JS_DESTRUCT.search(line)
            if d and JS_SOURCE.search(d.group(2)):
                for name in re.split(r"[,\s]+", d.group(1)):
                    name = name.split(":")[-1].strip()
                    if name:
                        self.tainted.add(name)
            m = JS_ASSIGN.search(line)
            if m:
                var, rhs = m.group(1), self._strip_indexes(m.group(2))
                if (JS_SOURCE.search(rhs) or self._uses_tainted(rhs)) and not JS_SANITIZERS.search(rhs):
                    self.tainted.add(var)

    def _uses_tainted(self, text: str) -> bool:
        if not self.tainted:
            return False
        names = _PHP_VAR.findall(text) if self.lang == "php" else _JS_IDENT.findall(text)
        return any(n in self.tainted for n in names)

    def is_tainted(self, line: str) -> bool:
        source = PHP_SOURCE if self.lang == "php" else JS_SOURCE
        return bool(source.search(line)) or self._uses_tainted(line)


def _applies(rule: Rule, lang: str, rel: str) -> bool:
    if lang not in rule.languages:
        return False
    return not (rule.path_filter and not rule.path_filter.search(rel))


def scan_text(text: str, rel: str, lang: str) -> list[dict]:
    results: list[dict] = []
    rules = [r for r in RULES if _applies(r, lang, rel) and not (r.file_requires and not r.file_requires.search(text))]
    if not rules:
        return results
    taint_lang = "php" if lang == "php" else "js" if lang in ("js", "html") else None
    tracker = TaintTracker(taint_lang) if taint_lang else None
    in_block = False
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line[:MAX_LINE_LEN]
        stripped = line.strip()
        if in_block:
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith("/*") and "*/" not in stripped:
            in_block = True
            continue
        if not stripped or _COMMENT_LINE[lang].match(line):
            continue
        code = _strip_trailing_comment(line) if lang in ("js", "php") else line
        for rule in rules:
            m = rule.pattern.search(code)
            if not m or (rule.exclude and rule.exclude.search(code)):
                continue
            # El dato contaminado debe llegar al sumidero: se examina desde el inicio de la coincidencia
            # (o tras ella, para sumideros cuyo propio token es una fuente, p. ej. location.href = ...).
            scope = code[m.end():] if rule.extra.get("taint_scope") == "after" else code[m.start():]
            tainted = tracker.is_tainted(scope) if tracker else False
            if rule.taint == "required" and not tainted:
                continue
            severity, confidence = rule.severity, rule.confidence
            if rule.taint == "upgrade" and tainted:
                confidence = "HIGH"
                severity = rule.extra.get("tainted_severity", severity)
            results.append({
                "rule_id": rule.id, "file": rel, "line": lineno, "column": m.start() + 1,
                "severity": severity, "confidence": confidence, "tainted": tainted,
                "snippet": stripped[:300],
            })
        if tracker:
            tracker.observe(code)
    return results


def main() -> int:
    src, out = runner_args()
    started = time.time()
    findings: list[dict] = []
    files = skipped = 0
    for path, rel in iter_source_files(src):
        text = read_text(path)
        lang = language_of(rel)
        if text is None or lang is None:
            skipped += 1
            continue
        files += 1
        findings.extend(scan_text(text, rel, lang))
    write_json(out, {
        "tool": "vulnix-sast", "runner_version": RUNNER_VERSION, "ruleset_version": RULESET_VERSION,
        "rules": len(RULES), "files_scanned": files, "files_skipped": skipped,
        "duration_s": round(time.time() - started, 3), "findings": findings,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
