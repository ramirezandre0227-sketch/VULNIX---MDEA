# ADR-0001 · Arquitectura de servicios y stack

**Estado:** aceptado · **Fecha:** 2026-11-15

## Contexto
El manual (§2) define frontend web, API Laravel, orquestador, servicio Python de analizadores, workers aislados,
PostgreSQL, almacenamiento de artefactos y Redis, con operación local sin servicios cloud obligatorios.

## Decisión
| Componente | Implementación | Responsabilidad |
|---|---|---|
| `apps/web` | HTML/CSS/JS sin build, servido por la API (mismo origen) | Panel, proyectos, hallazgos, comparación, políticas, excepciones, auditoría |
| `apps/api` | Laravel 12 + Sanctum | Auth/RBAC, ingesta, planificación, **motor de políticas**, **firma**, reportes, auditoría |
| `services/orchestrator` | Python 3.12 | Cola, leases, reintentos, sandbox por job, normalización, correlación |
| `workers/adapters`, `workers/sandbox` | Python | Contrato `AnalyzerAdapter`, runners integrados, aislamiento |
| `services/analyzer-api` | FastAPI (solo 127.0.0.1, token de servicio) | Salud y catálogo de analizadores, reglas, normalización SARIF |
| PostgreSQL 16 | Esquemas `identity`, `catalog`, `evaluation`, `audit` | Fuente de verdad, triggers de integridad |

Roles de BD separados por servicio (`vulnix_owner`, `vulnix_api`, `vulnix_orchestrator`), ver `infra/postgres/grants.sql`.

## Consecuencias
- La separación de roles hace cumplir por la base de datos que **un worker no puede emitir una autorización**
  (el rol del orquestador no tiene acceso a `evaluation.decisions`, `exceptions` ni a la identidad).
- El frontend no necesita build ni CDN (compatible con red aislada y CSP estricta).
