"""Runner de detección de secretos. Redacta EN ORIGEN: el valor del secreto nunca sale del sandbox.

Uso: python -I -m vulnix_adapters.builtin.secrets_runner <src> <out.json>
"""

from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import RUNNER_VERSION
from .common import MAX_LINE_LEN, read_text, runner_args, write_json

SECRETS_RULESET_VERSION = "2026.11.1"
SKIP_DIRS = {".git", "node_modules", "vendor", "bower_components"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".lock"}
EXAMPLE_FILE = re.compile(r"(?i)(\.example|\.sample|\.dist|\.template)$|(^|/)(test|tests|__tests__|fixtures?|spec)/")
PLACEHOLDER = re.compile(r"(?i)^(changeme|change_me|example|sample|placeholder|dummy|test|testing|secret|password|null|none|undefined|true|false|xxx+|\*+|your[_-].*|<.*>|\$\{.*\}|%.*%|\{\{.*\}\}|env\(.*|process\.env.*|getenv\(.*|config\(.*)$")


@dataclass(frozen=True)
class SecretRule:
    id: str
    pattern: re.Pattern[str]
    group: int
    severity: str
    confidence: str
    title: str
    min_entropy: float = 0.0
    files: re.Pattern[str] | None = None


RULES = [
    SecretRule("secrets.private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), 0, "CRITICAL", "HIGH", "Clave privada embebida"),
    SecretRule("secrets.aws-access-key-id", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 1, "CRITICAL", "HIGH", "AWS Access Key ID"),
    SecretRule("secrets.aws-secret-access-key", re.compile(r"(?i)aws.{0,20}(?:secret|private).{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]"), 1, "CRITICAL", "HIGH", "AWS Secret Access Key"),
    SecretRule("secrets.github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), 1, "HIGH", "HIGH", "Token de GitHub"),
    SecretRule("secrets.gitlab-token", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"), 1, "HIGH", "HIGH", "Token de GitLab"),
    SecretRule("secrets.slack-token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), 1, "HIGH", "HIGH", "Token de Slack"),
    SecretRule("secrets.stripe-live-key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b"), 1, "CRITICAL", "HIGH", "Clave live de Stripe"),
    SecretRule("secrets.google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 1, "HIGH", "HIGH", "Clave de API de Google"),
    SecretRule("secrets.sendgrid-key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"), 1, "HIGH", "HIGH", "Clave de SendGrid"),
    SecretRule("secrets.jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), 1, "MEDIUM", "MEDIUM", "JSON Web Token embebido"),
    SecretRule("secrets.laravel-app-key", re.compile(r"\bAPP_KEY\s*=\s*(base64:[A-Za-z0-9+/=]{40,})"), 1, "HIGH", "HIGH", "APP_KEY de Laravel"),
    SecretRule("secrets.connection-string", re.compile(r"\b(?:mysql|mariadb|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqps?|mssql|sqlserver)://[^:\s/'\"]+:([^@\s/'\"]{4,})@"), 1, "HIGH", "HIGH", "Cadena de conexión con contraseña"),
    SecretRule("secrets.dotenv-credential", re.compile(r"^\s*([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*['\"]?([^\s'\"#]{6,})"), 2, "HIGH", "HIGH", "Credencial en fichero .env", 2.5, re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$")),
    SecretRule("secrets.hardcoded-credential", re.compile(r"(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key))['\"]?\s*(?:=>|:=|=|:)\s*['\"]([^'\"\s]{8,})['\"]"), 2, "HIGH", "MEDIUM", "Credencial embebida en el código", 3.0),
]


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or path.suffix.lower() in SKIP_EXT or name.endswith((".min.js", ".map")):
                continue
            yield path, path.relative_to(root).as_posix()


def entropy(value: str) -> float:
    from collections import Counter
    import math

    if not value:
        return 0.0
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in Counter(value).values())


def scan_text(text: str, rel: str) -> list[dict]:
    out: list[dict] = []
    is_example = bool(EXAMPLE_FILE.search(rel))
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw[:MAX_LINE_LEN]
        taken: list[tuple[int, int]] = []
        for rule in RULES:
            if rule.files and not rule.files.search(rel):
                continue
            for m in rule.pattern.finditer(line):
                start, end = m.span(rule.group)
                value = line[start:end]
                if any(s < end and start < e for s, e in taken):
                    continue  # ya cubierto por una regla más específica
                if PLACEHOLDER.match(value) or (rule.min_entropy and entropy(value) < rule.min_entropy):
                    continue
                taken.append((start, end))
                confidence = rule.confidence
                severity = rule.severity
                if is_example:  # ficheros de ejemplo o de pruebas: requiere revisión humana, no bloqueo
                    confidence, severity = "LOW", "MEDIUM" if severity in ("CRITICAL", "HIGH") else severity
                redacted = f"{line[:start]}[REDACTED len={len(value)}]{line[end:]}".strip()
                out.append({
                    "rule_id": rule.id, "title": rule.title, "file": rel, "line": lineno,
                    "severity": severity, "confidence": confidence,
                    "secret_length": len(value), "entropy": round(entropy(value), 2),
                    "redacted_line": redacted[:300],
                })
    return out


def main() -> int:
    src, out = runner_args()
    started = time.time()
    findings: list[dict] = []
    files = 0
    for path, rel in iter_files(src):
        text = read_text(path)
        if text is None:
            continue
        files += 1
        findings.extend(scan_text(text, rel))
    write_json(out, {
        "tool": "vulnix-secrets", "runner_version": RUNNER_VERSION, "ruleset_version": SECRETS_RULESET_VERSION,
        "files_scanned": files, "duration_s": round(time.time() - started, 3), "findings": findings,
    })
    return 0


if __name__ == "__main__":
    sys.exit(main())
