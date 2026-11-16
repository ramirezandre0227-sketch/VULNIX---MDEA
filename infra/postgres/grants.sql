-- VULNIX: permisos mínimos por servicio. Ejecutar como vulnix_owner DESPUÉS de las migraciones.
-- Es idempotente: revoca todo y vuelve a conceder.
\set ON_ERROR_STOP on

REVOKE ALL ON ALL TABLES IN SCHEMA public, identity, catalog, evaluation, audit FROM vulnix_api, vulnix_orchestrator;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public, identity, catalog, evaluation, audit FROM vulnix_api, vulnix_orchestrator;

-- ---------------------------------------------------------------- vulnix_api (Laravel)
GRANT USAGE ON SCHEMA public, identity, catalog, evaluation, audit TO vulnix_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vulnix_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vulnix_api;
GRANT SELECT, INSERT, UPDATE ON identity.users TO vulnix_api;
GRANT SELECT, INSERT, UPDATE ON catalog.projects TO vulnix_api;
GRANT SELECT, INSERT ON catalog.project_versions TO vulnix_api;
GRANT SELECT ON catalog.analyzers, catalog.intel_feeds TO vulnix_api;
GRANT SELECT, INSERT, UPDATE ON catalog.policies TO vulnix_api;
GRANT SELECT, INSERT, UPDATE ON evaluation.analyses TO vulnix_api;
GRANT SELECT, INSERT, UPDATE ON evaluation.scan_jobs TO vulnix_api;
GRANT SELECT ON evaluation.findings, evaluation.evidences, evaluation.recommendations TO vulnix_api;
GRANT SELECT, INSERT ON evaluation.decisions, evaluation.reports TO vulnix_api;
GRANT SELECT, INSERT, UPDATE ON evaluation.exceptions TO vulnix_api;
GRANT SELECT, INSERT ON audit.audit_logs TO vulnix_api;

-- ---------------------------------------------------------------- vulnix_orchestrator (Python)
-- Sin acceso a identity, decisiones, excepciones ni políticas en escritura: un worker no puede autorizar.
GRANT USAGE ON SCHEMA catalog, evaluation, audit TO vulnix_orchestrator;
GRANT SELECT ON catalog.projects, catalog.project_versions, catalog.policies,
                catalog.intel_feeds, catalog.advisories TO vulnix_orchestrator;
GRANT SELECT, INSERT, UPDATE ON catalog.analyzers TO vulnix_orchestrator;
GRANT SELECT ON evaluation.analyses TO vulnix_orchestrator;
GRANT UPDATE (status, status_reason, started_at, finished_at, updated_at) ON evaluation.analyses TO vulnix_orchestrator;
GRANT SELECT, INSERT, UPDATE ON evaluation.scan_jobs TO vulnix_orchestrator;
GRANT SELECT, INSERT ON evaluation.findings TO vulnix_orchestrator;
GRANT UPDATE (correlation_key) ON evaluation.findings TO vulnix_orchestrator;
GRANT SELECT, INSERT ON evaluation.evidences, evaluation.recommendations TO vulnix_orchestrator;
GRANT INSERT ON audit.audit_logs TO vulnix_orchestrator;
