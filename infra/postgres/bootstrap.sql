-- VULNIX: creación de roles y bases de datos (ejecutar como superusuario postgres).
-- Uso: psql -U postgres -v owner_pw=... -v api_pw=... -v orch_pw=... -f bootstrap.sql
-- Roles (manual §5: separar permisos por servicio):
--   vulnix_owner        dueño del esquema, solo para migraciones y operaciones administrativas.
--   vulnix_api          runtime de Laravel (DML limitado; sin UPDATE/DELETE en auditoría ni decisiones).
--   vulnix_orchestrator runtime del orquestador/workers (sin acceso a identidad, decisiones ni excepciones).
\set ON_ERROR_STOP on

SELECT format('CREATE ROLE vulnix_owner LOGIN PASSWORD %L', :'owner_pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vulnix_owner') \gexec
SELECT format('CREATE ROLE vulnix_api LOGIN PASSWORD %L', :'api_pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vulnix_api') \gexec
SELECT format('CREATE ROLE vulnix_orchestrator LOGIN PASSWORD %L', :'orch_pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vulnix_orchestrator') \gexec

ALTER ROLE vulnix_owner PASSWORD :'owner_pw';
ALTER ROLE vulnix_api PASSWORD :'api_pw';
ALTER ROLE vulnix_orchestrator PASSWORD :'orch_pw';
ALTER ROLE vulnix_api SET search_path = public;
ALTER ROLE vulnix_orchestrator SET search_path = public;
ALTER ROLE vulnix_orchestrator SET statement_timeout = '120s';

SELECT 'CREATE DATABASE vulnix OWNER vulnix_owner ENCODING ''UTF8'' TEMPLATE template0'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'vulnix') \gexec
SELECT 'CREATE DATABASE vulnix_test OWNER vulnix_owner ENCODING ''UTF8'' TEMPLATE template0'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'vulnix_test') \gexec

REVOKE ALL ON DATABASE vulnix FROM PUBLIC;
GRANT CONNECT ON DATABASE vulnix TO vulnix_api, vulnix_orchestrator;
REVOKE ALL ON DATABASE vulnix_test FROM PUBLIC;
GRANT CONNECT ON DATABASE vulnix_test TO vulnix_api, vulnix_orchestrator;

\c vulnix
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO vulnix_owner;
\c vulnix_test
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO vulnix_owner;
