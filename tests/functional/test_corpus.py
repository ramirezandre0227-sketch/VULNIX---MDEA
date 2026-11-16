"""Funcionales (manual §9): detección de vulnerabilidades conocidas y proyectos negativos de referencia."""

import importlib.util
from pathlib import Path

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
spec = importlib.util.spec_from_file_location("measure", CORPUS / "measure.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)


def test_corpus_recall_and_no_blocking_false_positives():
    m = measure.measure()
    missed = {name: d["missed"] for name, d in m["projects"].items() if d["missed"]}
    assert not missed, f"vulnerabilidades conocidas no detectadas: {missed}"
    assert m["blocking_false_positives"] == [], "un proyecto negativo no debe producir hallazgos bloqueantes"
    assert m["overall"]["recall"] == 1.0


def test_negative_projects_have_no_findings_at_medium_or_above():
    for name in ("php-clean", "js-clean"):
        found = [f for f in measure.scan_project(CORPUS / name) if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
        assert found == [], f"{name}: {found}"
