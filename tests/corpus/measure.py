"""Métricas del conjunto de referencia (manual §1 y §9): precisión y cobertura por clase de vulnerabilidad.

Uso:  python tests/corpus/measure.py [--json]
Proyectos *-vulnerable tienen <nombre>.expected.json; proyectos *-clean son negativos (todo hallazgo es FP).
No se deben prometer cifras de precisión fuera de lo medido sobre este corpus (manual §9).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from vulnix_adapters.builtin import sast_runner, secrets_runner
from vulnix_adapters.builtin.common import iter_source_files, language_of, read_text
from vulnix_adapters.builtin.sast_rules import RULES

CORPUS = Path(__file__).resolve().parent
CWE_CLASS = {
    "CWE-89": "sqli", "CWE-79": "xss", "CWE-78": "cmdi", "CWE-98": "lfi", "CWE-502": "deserialization",
    "CWE-22": "path-traversal", "CWE-916": "weak-crypto", "CWE-338": "weak-crypto", "CWE-353": "integrity",
    "CWE-601": "open-redirect", "CWE-95": "code-injection", "CWE-295": "tls", "CWE-345": "postmessage",
    "CWE-319": "transport", "CWE-1022": "tabnabbing", "CWE-918": "ssrf", "CWE-943": "nosqli",
}
RULE_CWE = {r.id: r.cwe for r in RULES}


def scan_project(root: Path) -> list[dict]:
    found: list[dict] = []
    for path, rel in iter_source_files(root):
        text = read_text(path)
        if text is not None and language_of(rel):
            for f in sast_runner.scan_text(text, rel, language_of(rel)):
                found.append({"class": CWE_CLASS.get(RULE_CWE[f["rule_id"]], RULE_CWE[f["rule_id"]]), "file": rel, "line": f["line"],
                              "rule_id": f["rule_id"], "severity": f["severity"], "confidence": f["confidence"]})
    for path, rel in secrets_runner.iter_files(root):
        text = read_text(path)
        if text is not None:
            for f in secrets_runner.scan_text(text, rel):
                found.append({"class": "secret", "file": rel, "line": f["line"], "rule_id": f["rule_id"],
                              "severity": f["severity"], "confidence": f["confidence"]})
    return found


def measure() -> dict:
    per_class = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    blocking_fp: list[dict] = []
    details = {}
    for project in sorted(p for p in CORPUS.iterdir() if p.is_dir()):
        expected_file = CORPUS / f"{project.name}.expected.json"
        expected = json.loads(expected_file.read_text(encoding="utf-8"))["expected"] if expected_file.exists() else []
        found = scan_project(project)
        exp_keys = {(e["class"], e["file"], e["line"]) for e in expected}
        found_keys = {(f["class"], f["file"], f["line"]) for f in found}
        for key in exp_keys:
            per_class[key[0]]["tp" if key in found_keys else "fn"] += 1
        for f in found:
            key = (f["class"], f["file"], f["line"])
            if key not in exp_keys:
                per_class[f["class"]]["fp"] += 1
                if f["severity"] in ("CRITICAL", "HIGH") and f["confidence"] == "HIGH":
                    blocking_fp.append({"project": project.name, **f})
        details[project.name] = {"expected": len(exp_keys), "detected": len(exp_keys & found_keys),
                                 "missed": sorted(exp_keys - found_keys), "unexpected": sorted(found_keys - exp_keys)}
    summary = {}
    for cls, c in sorted(per_class.items()):
        precision = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None
        recall = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None
        summary[cls] = {**c, "precision": None if precision is None else round(precision, 3), "recall": None if recall is None else round(recall, 3)}
    tp = sum(c["tp"] for c in per_class.values())
    fp = sum(c["fp"] for c in per_class.values())
    fn = sum(c["fn"] for c in per_class.values())
    return {"per_class": summary, "projects": details, "blocking_false_positives": blocking_fp,
            "overall": {"tp": tp, "fp": fp, "fn": fn, "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                        "recall": round(tp / (tp + fn), 3) if tp + fn else None}}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    m = measure()
    if args.json:
        print(json.dumps(m, indent=2, ensure_ascii=False))
        return 0
    print(f"{'clase':18} {'TP':>4} {'FP':>4} {'FN':>4} {'precisión':>10} {'cobertura':>10}")
    for cls, c in m["per_class"].items():
        fmt = lambda v: "   —" if v is None else f"{v:.0%}"  # noqa: E731
        print(f"{cls:18} {c['tp']:>4} {c['fp']:>4} {c['fn']:>4} {fmt(c['precision']):>10} {fmt(c['recall']):>10}")
    o = m["overall"]
    print(f"\nGLOBAL: TP={o['tp']} FP={o['fp']} FN={o['fn']} precisión={o['precision']} cobertura={o['recall']}")
    print(f"Falsos positivos bloqueantes (crítico/alto con confianza alta): {len(m['blocking_false_positives'])}")
    for name, d in m["projects"].items():
        if d["missed"] or d["unexpected"]:
            print(f"  {name}: no detectados={d['missed']} inesperados={d['unexpected']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
