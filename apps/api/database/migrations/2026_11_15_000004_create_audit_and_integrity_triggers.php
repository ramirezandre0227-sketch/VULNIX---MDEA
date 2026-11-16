<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Auditoría append-only con cadena de hashes + triggers que hacen cumplir las invariantes del manual §2:
 *  - artefactos inmutables, decisiones inmutables, resultados brutos inmutables;
 *  - transiciones válidas de la máquina de estados del análisis.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('audit.audit_logs', function (Blueprint $t) {
            $t->uuid('id')->primary()->default(DB::raw('gen_random_uuid()'));
            // Posición en la cadena: la asigna el trigger bajo bloqueo (orden de commit, no de nextval).
            $t->bigInteger('seq')->default(0);
            $t->uuid('actor_id')->nullable();
            $t->string('actor_type', 16);
            $t->string('action', 64);
            $t->string('entity_type', 64)->nullable();
            $t->string('entity_id', 64)->nullable();
            $t->jsonb('event_json')->default('{}');
            $t->string('ip', 45)->nullable();
            $t->string('user_agent', 255)->nullable();
            $t->char('prev_hash', 64)->nullable();
            $t->char('hash', 64)->nullable();
            $t->timestampTz('created_at')->useCurrent();
            $t->foreign('actor_id')->references('id')->on('identity.users');
            $t->index('actor_id');
            $t->index('action');
            $t->index(['entity_type', 'entity_id']);
            $t->index('created_at');
        });
        DB::statement('ALTER TABLE audit.audit_logs ADD CONSTRAINT audit_seq_unique UNIQUE (seq)');
        DB::statement("ALTER TABLE audit.audit_logs ADD CONSTRAINT audit_actor_type_chk
            CHECK (actor_type IN ('USER','SERVICE','SYSTEM','ANONYMOUS'))");

        DB::unprepared(<<<'SQL'
-- Hash canónico de una fila de auditoría (usado por el trigger y por la verificación).
CREATE OR REPLACE FUNCTION audit.row_hash(p_prev text, p_seq bigint, p_actor uuid, p_actor_type text,
    p_action text, p_entity_type text, p_entity_id text, p_event jsonb, p_created timestamptz)
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(sha256(convert_to(
      coalesce(p_prev, '') || '|' || p_seq::text || '|' || coalesce(p_actor::text, '') || '|' ||
      p_actor_type || '|' || p_action || '|' || coalesce(p_entity_type, '') || '|' ||
      coalesce(p_entity_id, '') || '|' || coalesce(p_event::text, '{}') || '|' ||
      to_char(p_created AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), 'UTF8')), 'hex')
$$;

CREATE OR REPLACE FUNCTION audit.chain_hash() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, audit AS $$
DECLARE v_prev text; v_seq bigint;
BEGIN
  -- El bloqueo se mantiene hasta el commit: las inserciones concurrentes se encadenan en orden.
  PERFORM pg_advisory_xact_lock(7300155);
  SELECT hash, seq INTO v_prev, v_seq FROM audit.audit_logs ORDER BY seq DESC LIMIT 1;
  NEW.seq := coalesce(v_seq, 0) + 1;
  NEW.created_at := clock_timestamp();
  NEW.prev_hash := v_prev;
  NEW.hash := audit.row_hash(v_prev, NEW.seq, NEW.actor_id, NEW.actor_type, NEW.action,
                             NEW.entity_type, NEW.entity_id, NEW.event_json, NEW.created_at);
  RETURN NEW;
END $$;

CREATE TRIGGER audit_logs_chain BEFORE INSERT ON audit.audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit.chain_hash();

CREATE OR REPLACE FUNCTION audit.forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'VULNIX_IMMUTABLE: % on %.% is not allowed', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = 'P0001';
END $$;

CREATE TRIGGER audit_logs_immutable BEFORE UPDATE OR DELETE ON audit.audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit.forbid_mutation();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit.audit_logs
  FOR EACH STATEMENT EXECUTE FUNCTION audit.forbid_mutation();

-- Decisiones firmadas: inmutables.
CREATE TRIGGER decisions_immutable BEFORE UPDATE OR DELETE ON evaluation.decisions
  FOR EACH ROW EXECUTE FUNCTION audit.forbid_mutation();

-- Evidencias: inmutables.
CREATE TRIGGER evidences_immutable BEFORE UPDATE OR DELETE ON evaluation.evidences
  FOR EACH ROW EXECUTE FUNCTION audit.forbid_mutation();

-- Versiones de proyecto: artefacto inmutable (no se borra ni se cambia su identidad).
CREATE OR REPLACE FUNCTION catalog.protect_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'VULNIX_IMMUTABLE: project versions cannot be deleted' USING ERRCODE = 'P0001';
  END IF;
  IF NEW.sha256 IS DISTINCT FROM OLD.sha256 OR NEW.uri IS DISTINCT FROM OLD.uri
     OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes OR NEW.project_id IS DISTINCT FROM OLD.project_id
     OR NEW.version IS DISTINCT FROM OLD.version OR NEW.manifest_json IS DISTINCT FROM OLD.manifest_json THEN
    RAISE EXCEPTION 'VULNIX_IMMUTABLE: artifact identity cannot change' USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER project_versions_immutable BEFORE UPDATE OR DELETE ON catalog.project_versions
  FOR EACH ROW EXECUTE FUNCTION catalog.protect_version();

-- Políticas: el contenido versionado es inmutable; solo cambia el ciclo de vida (estado/aprobación).
CREATE OR REPLACE FUNCTION catalog.protect_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'VULNIX_IMMUTABLE: policies cannot be deleted' USING ERRCODE = 'P0001';
  END IF;
  IF NEW.code IS DISTINCT FROM OLD.code OR NEW.version IS DISTINCT FROM OLD.version
     OR NEW.rules_json IS DISTINCT FROM OLD.rules_json OR NEW.sha256 IS DISTINCT FROM OLD.sha256
     OR NEW.source_yaml IS DISTINCT FROM OLD.source_yaml THEN
    RAISE EXCEPTION 'VULNIX_IMMUTABLE: policy content is versioned and immutable' USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER policies_immutable BEFORE UPDATE OR DELETE ON catalog.policies
  FOR EACH ROW EXECUTE FUNCTION catalog.protect_policy();

-- Hallazgos (resultados brutos normalizados): solo puede asignarse la clave de correlación.
CREATE OR REPLACE FUNCTION evaluation.protect_finding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'VULNIX_IMMUTABLE: findings cannot be deleted' USING ERRCODE = 'P0001';
  END IF;
  IF (to_jsonb(NEW) - 'correlation_key') IS DISTINCT FROM (to_jsonb(OLD) - 'correlation_key') THEN
    RAISE EXCEPTION 'VULNIX_IMMUTABLE: raw findings cannot be modified' USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER findings_immutable BEFORE UPDATE OR DELETE ON evaluation.findings
  FOR EACH ROW EXECUTE FUNCTION evaluation.protect_finding();

-- Máquina de estados del análisis (manual §2).
CREATE OR REPLACE FUNCTION evaluation.check_analysis_transition() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE allowed text[];
BEGIN
  IF NEW.status = OLD.status THEN RETURN NEW; END IF;
  allowed := CASE OLD.status
    WHEN 'CREATED'     THEN ARRAY['VALIDATING','FAILED','CANCELLED']
    WHEN 'VALIDATING'  THEN ARRAY['QUEUED','FAILED','INCONCLUSIVE','CANCELLED']
    WHEN 'QUEUED'      THEN ARRAY['RUNNING','FAILED','CANCELLED','TIMED_OUT']
    WHEN 'RUNNING'     THEN ARRAY['NORMALIZING','FAILED','CANCELLED','TIMED_OUT']
    WHEN 'NORMALIZING' THEN ARRAY['EVALUATING','FAILED']
    WHEN 'EVALUATING'  THEN ARRAY['COMPLETED','INCONCLUSIVE','FAILED']
    ELSE ARRAY[]::text[]
  END;
  IF NOT (NEW.status = ANY(allowed)) THEN
    RAISE EXCEPTION 'VULNIX_INVALID_TRANSITION: % -> %', OLD.status, NEW.status USING ERRCODE = 'P0001';
  END IF;
  IF NEW.artifact_sha256 IS DISTINCT FROM OLD.artifact_sha256 OR NEW.version_id IS DISTINCT FROM OLD.version_id
     OR NEW.policy_id IS DISTINCT FROM OLD.policy_id THEN
    RAISE EXCEPTION 'VULNIX_IMMUTABLE: analysis identity cannot change' USING ERRCODE = 'P0001';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER analyses_transition BEFORE UPDATE ON evaluation.analyses
  FOR EACH ROW EXECUTE FUNCTION evaluation.check_analysis_transition();

-- Jobs: un estado terminal no puede volver a ejecución (los reintentos crean una fila nueva).
CREATE OR REPLACE FUNCTION evaluation.check_job_transition() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status IN ('SUCCEEDED','FAILED','TIMED_OUT','CANCELLED','SKIPPED') AND NEW.status IS DISTINCT FROM OLD.status THEN
    RAISE EXCEPTION 'VULNIX_INVALID_TRANSITION: job % is terminal (%)', OLD.id, OLD.status USING ERRCODE = 'P0001';
  END IF;
  IF OLD.status = 'QUEUED' AND NEW.status NOT IN ('QUEUED','RUNNING','CANCELLED','SKIPPED','FAILED') THEN
    RAISE EXCEPTION 'VULNIX_INVALID_TRANSITION: job QUEUED -> %', NEW.status USING ERRCODE = 'P0001';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $$;
CREATE TRIGGER scan_jobs_transition BEFORE UPDATE ON evaluation.scan_jobs
  FOR EACH ROW EXECUTE FUNCTION evaluation.check_job_transition();
SQL);
    }

    public function down(): void
    {
        DB::unprepared(<<<'SQL'
DROP TRIGGER IF EXISTS scan_jobs_transition ON evaluation.scan_jobs;
DROP FUNCTION IF EXISTS evaluation.check_job_transition();
DROP TRIGGER IF EXISTS analyses_transition ON evaluation.analyses;
DROP FUNCTION IF EXISTS evaluation.check_analysis_transition();
DROP TRIGGER IF EXISTS findings_immutable ON evaluation.findings;
DROP FUNCTION IF EXISTS evaluation.protect_finding();
DROP TRIGGER IF EXISTS policies_immutable ON catalog.policies;
DROP FUNCTION IF EXISTS catalog.protect_policy();
DROP TRIGGER IF EXISTS project_versions_immutable ON catalog.project_versions;
DROP FUNCTION IF EXISTS catalog.protect_version();
DROP TRIGGER IF EXISTS evidences_immutable ON evaluation.evidences;
DROP TRIGGER IF EXISTS decisions_immutable ON evaluation.decisions;
DROP TABLE IF EXISTS audit.audit_logs;
DROP FUNCTION IF EXISTS audit.forbid_mutation();
DROP FUNCTION IF EXISTS audit.chain_hash();
DROP FUNCTION IF EXISTS audit.row_hash(text, bigint, uuid, text, text, text, text, jsonb, timestamptz);
SQL);
    }
};
