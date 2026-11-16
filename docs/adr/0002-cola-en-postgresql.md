# ADR-0002 · Cola de trabajos en PostgreSQL (Redis opcional)

**Estado:** aceptado (revisable en fase 2) · **Fecha:** 2026-11-15

## Contexto
El manual propone Redis como "cola temporal". En el entorno piloto (Windows) no hay Redis nativo, y la
fuente de verdad de los jobs ya es PostgreSQL (estados, intentos, evidencias).

## Decisión
La cola es la propia tabla `evaluation.scan_jobs`:
- Reclamo atómico con `SELECT … FOR UPDATE SKIP LOCKED` y **lease** con caducidad (`lease_expires_at`).
- Resultado escrito en **una transacción** condicionada a `status='RUNNING' AND locked_by=<worker>`:
  un job cancelado o con lease perdido descarta su resultado (idempotencia).
- Reintentos = **fila nueva** (`attempt + 1`) con `UNIQUE(analysis_id, analyzer_name, attempt)`; el histórico es auditable.
- `reap()` recupera leases vencidos (worker caído) y aplica el timeout global del análisis.

## Consecuencias
- Un reinicio de Redis no puede perder trabajos (no existe esa dependencia).
- Para alto volumen se puede añadir Redis como **señal de despertar** (LPUSH/BRPOP) sin cambiar la semántica.
  Pendiente: implementar y probar el adaptador Redis (riesgo listado en `docs/ESTADO.md`).
