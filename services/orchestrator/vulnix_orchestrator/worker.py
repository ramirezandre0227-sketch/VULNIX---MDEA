"""Worker del orquestador.

Cola: PostgreSQL es la fuente de verdad (`SELECT ... FOR UPDATE SKIP LOCKED`), con lease por job.
Idempotencia: un job solo se reclama en estado QUEUED; el resultado se escribe en UNA transacción
condicionada a que el job siga RUNNING y bloqueado por este worker (si se canceló o se perdió el lease,
el resultado se descarta). Los reintentos crean una fila nueva (attempt + 1): el histórico es auditable.
El worker NO emite decisiones: al terminar todos los jobs deja el análisis en EVALUATING y pide a la API
que evalúe (la API es la única con política y clave de firma).
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from vulnix_adapters.base import AdapterError, AnalyzerAdapter
from vulnix_adapters.registry import build_registry
from vulnix_core.config import Settings
from vulnix_core.fingerprint import correlation_key
from vulnix_core.models import AnalysisContext, sha256_file
from vulnix_core.redact import scrub_text
from vulnix_sandbox.extract import ExtractionError
from vulnix_sandbox.runner import Sandbox, SandboxLimits

from .intel import DbIntelStore

log = logging.getLogger("vulnix.orchestrator")
TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED", "SKIPPED")


@dataclass
class Outcome:
    status: str
    error_type: str | None = None
    message: str | None = None
    exit_code: int | None = None
    retryable: bool = False
    metadata: dict | None = None


class Worker:
    def __init__(self, settings: Settings):
        self.s = settings
        self.conn = psycopg.connect(settings.db_dsn, autocommit=True, row_factory=dict_row)
        self.intel = DbIntelStore(psycopg.connect(settings.db_dsn, autocommit=True))
        self.registry: dict[str, AnalyzerAdapter] = build_registry(self.intel, settings.php_bin, settings.node_bin)
        self.analyzer_ids: dict[str, str] = {}
        self._last_heartbeat = 0.0

    # ------------------------------------------------------------------ catálogo y latido
    def register_analyzers(self) -> dict[str, dict]:
        report = {}
        for name, adapter in self.registry.items():
            status = adapter.healthcheck()
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO catalog.analyzers (name, version, category, config_hash, metadata, healthy, last_seen_at)
                    VALUES (%s, %s, %s, %s, %s, %s, now())
                    ON CONFLICT (name, version, config_hash)
                    DO UPDATE SET healthy = EXCLUDED.healthy, last_seen_at = now(), metadata = EXCLUDED.metadata
                    RETURNING id""",
                    (name, status.version[:64], adapter.category, adapter.config_hash(),
                     Jsonb({"detail": status.detail, "declaration": adapter.declaration()}), status.healthy))
                self.analyzer_ids[name] = str(cur.fetchone()["id"])
            report[name] = {"version": status.version, "healthy": status.healthy, "detail": status.detail}
        self._last_heartbeat = time.monotonic()
        return report

    def heartbeat(self) -> None:
        if time.monotonic() - self._last_heartbeat >= self.s.heartbeat_s:
            self.register_analyzers()

    # ------------------------------------------------------------------ bucle principal
    def run_forever(self) -> None:
        self.register_analyzers()
        log.info("worker %s listo con %d analizadores", self.s.worker_id, len(self.registry))
        while True:
            try:
                self.heartbeat()
                self.reap()
                if not self.run_once():
                    time.sleep(self.s.poll_interval)
            except psycopg.OperationalError:
                log.exception("conexión a la base de datos perdida; reintentando")
                time.sleep(5)
                self.conn = psycopg.connect(self.s.db_dsn, autocommit=True, row_factory=dict_row)

    def drain(self, max_jobs: int = 1000) -> int:
        """Procesa la cola hasta vaciarla (pruebas y ejecución puntual)."""
        self.register_analyzers()
        n = 0
        self.reap()
        while n < max_jobs and self.run_once():
            n += 1
        return n

    def run_once(self) -> bool:
        job = self.claim()
        if not job:
            return False
        outcome = self.process(job)
        self.complete(job, outcome)
        self.finalize_if_done(str(job["analysis_id"]))
        return True

    # ------------------------------------------------------------------ cola
    def claim(self) -> dict | None:
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute("""
                UPDATE evaluation.scan_jobs SET status = 'RUNNING', locked_by = %s, started_at = now(),
                       lease_expires_at = now() + make_interval(secs => %s)
                WHERE id = (
                    SELECT j.id FROM evaluation.scan_jobs j
                    JOIN evaluation.analyses a ON a.id = j.analysis_id
                    WHERE j.status = 'QUEUED' AND a.status IN ('QUEUED', 'RUNNING')
                    ORDER BY j.created_at, j.id
                    FOR UPDATE OF j SKIP LOCKED LIMIT 1)
                RETURNING *""", (self.s.worker_id, self._lease_seconds(None)))
            job = cur.fetchone()
            if not job:
                return None
            if job["analyzer_name"] in self.registry:
                cur.execute("UPDATE evaluation.scan_jobs SET lease_expires_at = now() + make_interval(secs => %s) WHERE id = %s",
                            (self._lease_seconds(self.registry[job["analyzer_name"]]), job["id"]))
            cur.execute("""UPDATE evaluation.analyses SET status = 'RUNNING', started_at = coalesce(started_at, now())
                           WHERE id = %s AND status = 'QUEUED'""", (job["analysis_id"],))
        log.info("job %s (%s) reclamado", job["id"], job["analyzer_name"])
        return job

    def _lease_seconds(self, adapter: AnalyzerAdapter | None) -> int:
        return (adapter.timeout_s if adapter else 600) + 300

    def reap(self) -> None:
        """Recupera jobs con lease vencido (worker caído) y aplica el timeout global del análisis."""
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute("""SELECT * FROM evaluation.scan_jobs WHERE status = 'RUNNING' AND lease_expires_at < now()
                           FOR UPDATE SKIP LOCKED""")
            for job in cur.fetchall():
                cur.execute("""UPDATE evaluation.scan_jobs SET status = 'FAILED', ended_at = now(), error_type = 'LEASE_EXPIRED',
                               error_message = 'El worker no completó el job dentro de su lease' WHERE id = %s""", (job["id"],))
                self._maybe_retry(cur, job)
            cur.execute("""SELECT id FROM evaluation.analyses WHERE status IN ('QUEUED', 'RUNNING')
                           AND created_at < now() - make_interval(secs => %s) FOR UPDATE SKIP LOCKED""", (self.s.analysis_timeout_s,))
            for row in cur.fetchall():
                cur.execute("""UPDATE evaluation.scan_jobs SET status = 'CANCELLED', ended_at = now(), error_type = 'ANALYSIS_TIMEOUT'
                               WHERE analysis_id = %s AND status IN ('QUEUED', 'RUNNING')""", (row["id"],))
                cur.execute("""UPDATE evaluation.analyses SET status = 'TIMED_OUT', finished_at = now(),
                               status_reason = 'Tiempo máximo del análisis excedido' WHERE id = %s""", (row["id"],))
                self._audit(cur, "analysis.timed_out", "analysis", str(row["id"]), {})

    def _maybe_retry(self, cur, job: dict) -> bool:
        if job["attempt"] >= job["max_attempts"]:
            return False
        attempt = job["attempt"] + 1
        key = hashlib.sha256(f"{job['analysis_id']}|{job['analyzer_name']}|retry|{attempt}".encode()).hexdigest()
        cur.execute("""INSERT INTO evaluation.scan_jobs (analysis_id, analyzer_name, category, mandatory, attempt, max_attempts, status, idempotency_key, metadata)
                       VALUES (%s, %s, %s, %s, %s, %s, 'QUEUED', %s, %s) ON CONFLICT DO NOTHING""",
                    (job["analysis_id"], job["analyzer_name"], job["category"], job["mandatory"], attempt, job["max_attempts"], key,
                     Jsonb({"retry_of": str(job["id"])})))
        return True

    # ------------------------------------------------------------------ ejecución
    def process(self, job: dict) -> Outcome:
        adapter = self.registry.get(job["analyzer_name"])
        if adapter is None:
            return Outcome("FAILED", "ANALYZER_NOT_INSTALLED", f"El analizador {job['analyzer_name']} no está instalado en este worker.")
        status = adapter.healthcheck()
        if not status.healthy:
            return Outcome("FAILED", "TOOL_UNAVAILABLE", f"{adapter.name}: {status.detail}")

        with self.conn.cursor() as cur:
            cur.execute("""SELECT v.uri, v.sha256, v.artifact_kind, v.original_filename, v.technologies, a.artifact_sha256
                           FROM evaluation.analyses a JOIN catalog.project_versions v ON v.id = a.version_id WHERE a.id = %s""",
                        (job["analysis_id"],))
            art = cur.fetchone()
        artifact = self._data_path(art["uri"])
        if not artifact.is_file() or sha256_file(artifact) != art["artifact_sha256"]:
            return Outcome("FAILED", "ARTIFACT_INTEGRITY", "El artefacto no existe o su SHA-256 no coincide.")

        limits = SandboxLimits(process_memory_mb=adapter.max_memory_mb, job_memory_mb=adapter.max_memory_mb * 2,
                               max_processes=adapter.max_processes, cpu_seconds=adapter.timeout_s)
        with Sandbox(self.s.sandbox_root, str(job["id"]), limits) as sb:
            try:
                sb.materialize(artifact, art["artifact_kind"], art["original_filename"])
            except ExtractionError as exc:
                return Outcome("FAILED", exc.code, str(exc))
            ctx = AnalysisContext(str(job["analysis_id"]), str(job["id"]), art["artifact_sha256"], sb.src, sb.out, art["technologies"] or {})
            if not adapter.supports(art["technologies"] or {}):
                return Outcome("SKIPPED", "NOT_APPLICABLE", "El analizador no aplica a las tecnologías detectadas.")
            try:
                plan = adapter.prepare(ctx)
                raw = adapter.execute(plan, sb)
                findings = adapter.normalize(raw)
                metadata = adapter.job_metadata(raw) or {}
            except AdapterError as exc:
                status_ = "TIMED_OUT" if exc.error_type == "TIMEOUT" else "FAILED"
                return Outcome(status_, exc.error_type, scrub_text(str(exc))[:2000], retryable=exc.retryable)
            except (FileNotFoundError, json.JSONDecodeError) as exc:
                return Outcome("FAILED", "TOOL_OUTPUT_INVALID", scrub_text(str(exc))[:2000], retryable=True)

            evidences = self._store_evidence(job, adapter, raw)
            metadata.update({"duration_s": raw.duration_s, "isolation_level": sb.isolation_level, "findings": len(findings),
                             "worker": self.s.worker_id})
            return Outcome("SUCCEEDED", exit_code=raw.exit_code, metadata={**metadata, "_findings": findings, "_evidences": evidences})

    def _store_evidence(self, job: dict, adapter: AnalyzerAdapter, raw) -> list[dict]:
        stored = []
        for logical, kind in adapter.evidence_files(raw).items():
            src = raw.files.get(logical)
            if not src or not src.is_file():
                continue
            rel = f"evidence/{job['analysis_id']}/{job['id']}/{logical}{''.join(src.suffixes) or '.json'}"
            dest = self._data_path(rel)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            dest.chmod(0o444)
            stored.append({"kind": kind, "uri": rel, "sha256": sha256_file(dest), "size": dest.stat().st_size})
        return stored

    def complete(self, job: dict, o: Outcome) -> None:
        meta = dict(o.metadata or {})
        findings = meta.pop("_findings", [])
        evidences = meta.pop("_evidences", [])
        analyzer_id = self.analyzer_ids.get(job["analyzer_name"])
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute("""UPDATE evaluation.scan_jobs SET status = %s, ended_at = now(), exit_code = %s, error_type = %s,
                           error_message = %s, analyzer_id = %s, metadata = %s, lease_expires_at = NULL
                           WHERE id = %s AND status = 'RUNNING' AND locked_by = %s""",
                        (o.status, o.exit_code, o.error_type, o.message, analyzer_id, Jsonb(meta), job["id"], self.s.worker_id))
            if cur.rowcount == 0:
                log.warning("job %s ya no pertenece a este worker (cancelado o lease perdido): resultado descartado", job["id"])
                return
            raw_ev = None
            for ev in evidences:
                cur.execute("""INSERT INTO evaluation.evidences (job_id, kind, uri, sha256, size_bytes) VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                            (job["id"], ev["kind"], ev["uri"], ev["sha256"], ev["size"]))
                eid = cur.fetchone()["id"]
                if ev["kind"] == "RAW_OUTPUT":
                    raw_ev = ev
            for f in findings:
                cur.execute("""
                    INSERT INTO evaluation.findings (analysis_id, job_id, fingerprint, rule_id, analyzer_name, category, title, description,
                        severity, confidence, file_path, start_line, end_line, cwe, snippet, remediation, metadata)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (job_id, fingerprint) DO NOTHING RETURNING id""",
                    (job["analysis_id"], job["id"], f.fingerprint, f.rule_id, f.analyzer, f.category, f.title, f.description,
                     f.severity, f.confidence, f.file, f.line, f.end_line, f.cwe, f.snippet, f.remediation, Jsonb(f.metadata)))
                row = cur.fetchone()
                if not row:
                    continue
                if f.remediation or f.verify:
                    cur.execute("""INSERT INTO evaluation.recommendations (finding_id, description, verify, "references") VALUES (%s, %s, %s, %s)""",
                                (row["id"], f.remediation or "", f.verify or "", Jsonb(f.references)))
                if raw_ev:
                    cur.execute("""INSERT INTO evaluation.evidences (finding_id, kind, uri, sha256, size_bytes) VALUES (%s, 'TOOL_OUTPUT', %s, %s, %s)""",
                                (row["id"], raw_ev["uri"], raw_ev["sha256"], raw_ev["size"]))
            if o.status != "SUCCEEDED" and o.retryable:
                self._maybe_retry(cur, job)
            self._audit(cur, "job.completed", "scan_job", str(job["id"]),
                        {"analysis_id": str(job["analysis_id"]), "analyzer": job["analyzer_name"], "status": o.status,
                         "error_type": o.error_type, "findings": len(findings)})
        log.info("job %s -> %s %s (%d hallazgos)", job["id"], o.status, o.error_type or "", len(findings))

    # ------------------------------------------------------------------ cierre del análisis
    def finalize_if_done(self, analysis_id: str) -> str | None:
        with self.conn.transaction(), self.conn.cursor() as cur:
            cur.execute("SELECT status FROM evaluation.analyses WHERE id = %s FOR UPDATE", (analysis_id,))
            row = cur.fetchone()
            if not row or row["status"] != "RUNNING":
                return None
            cur.execute("""SELECT count(*) AS n FROM evaluation.scan_jobs WHERE analysis_id = %s AND status IN ('QUEUED', 'RUNNING')""", (analysis_id,))
            if cur.fetchone()["n"] > 0:
                return None
            cur.execute("UPDATE evaluation.analyses SET status = 'NORMALIZING' WHERE id = %s", (analysis_id,))
            # Correlación entre analizadores: mismo fichero + línea + CWE -> mismo problema.
            cur.execute("SELECT id, file_path, start_line, cwe, category FROM evaluation.findings WHERE analysis_id = %s", (analysis_id,))
            for f in cur.fetchall():
                cur.execute("UPDATE evaluation.findings SET correlation_key = %s WHERE id = %s",
                            (correlation_key(f["file_path"], f["start_line"], f["cwe"], f["category"]), f["id"]))
            cur.execute("UPDATE evaluation.analyses SET status = 'EVALUATING' WHERE id = %s", (analysis_id,))
            self._audit(cur, "analysis.ready_for_evaluation", "analysis", analysis_id, {})
        self.request_evaluation(analysis_id)
        return "EVALUATING"

    def request_evaluation(self, analysis_id: str) -> dict | None:
        req = urllib.request.Request(f"{self.s.api_internal_url}/internal/v1/analyses/{analysis_id}/evaluate", method="POST", data=b"{}",
                                     headers={"X-Vulnix-Service-Token": self.s.internal_token, "Content-Type": "application/json",
                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - URL interna configurada
                body = json.loads(resp.read() or b"{}")
                log.info("análisis %s evaluado: %s", analysis_id, body.get("result"))
                return body
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            log.warning("no se pudo solicitar la evaluación de %s (%s); queda en EVALUATING (php artisan vulnix:evaluate-pending)", analysis_id, exc)
            return None

    # ------------------------------------------------------------------ utilidades
    def _data_path(self, rel: str) -> Path:
        rel = rel.replace("\\", "/")
        if rel.startswith("/") or ".." in rel.split("/") or ":" in rel:
            raise ValueError("ruta de datos inválida")
        return self.s.data_dir / rel

    def _audit(self, cur, action: str, entity_type: str, entity_id: str, event: dict[str, Any]) -> None:
        cur.execute("""INSERT INTO audit.audit_logs (actor_type, action, entity_type, entity_id, event_json)
                       VALUES ('SERVICE', %s, %s, %s, %s)""", (action, entity_type, entity_id, Jsonb({**event, "worker": self.s.worker_id})))
