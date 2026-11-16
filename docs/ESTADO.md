# Estado de implementación frente al Manual Maestro (v1.0)

Fecha: 2026-11-15 · Alcance entregado: **fases 0, 1, 2, 3 y 5 del plan (§10) a nivel MVP/P0**, con piezas de P1.
Pendiente: fase 4 (DAST) y la ejecución de builds/pruebas en VM desechable.

## Checklist §14 para habilitar VULNIX como gate

| # | Criterio | Estado | Evidencia |
|---|---|---|---|
| 1 | Pruebas obligatorias con estado, evidencia y versión | ✅ | `scan_jobs` (estado, exit code, `analyzer_id` → versión + `config_hash`), evidencias con SHA-256 re-verificadas al decidir (`PolicyEngine::checkJobEvidence`) |
| 2 | Ninguna ruta de despliegue omite la verificación | ⚠️ Parcial | `infra/deploy/deploy-gate.{ps1,sh}` + `vulnix-verify`. **Depende de integrarlo como único camino en su pipeline** |
| 3 | Artefactos inmutables y SHA-256 comprobado antes de desplegar | ✅ | Almacén direccionado por hash, trigger `project_versions_immutable`, verificación en gate (probado E2E con 1 byte modificado) |
| 4 | Política versionada y aprobada | ✅ | YAML versionado, trigger de inmutabilidad, aprobación por persona distinta (CHECK `policies_sod_chk`) |
| 5 | Workers aislados y aislamiento probado | ⚠️ Parcial | Sandbox efímero + Job Object/rlimits + entorno sin credenciales, probado en `tests/security/test_sandbox.py`. **Falta VM desechable y bloqueo de red para ejecutar código del proyecto** |
| 6 | Críticos/altos confirmados bloquean | ✅ | `PolicyEngineTest`, E2E (`test_known_vulnerable_dependency_is_rejected`) |
| 7 | FAILED/TIMEOUT/SKIPPED nunca son PASS | ✅ | `test_failed_or_skipped_mandatory_control_is_inconclusive` |
| 8 | Revisión humana para excepciones e inciertos | ✅ | REVIEW_REQUIRED por excepciones pendientes y hallazgos crítico/alto de confianza no alta |
| 9 | Auditoría, respaldo y recuperación probados | ✅ | Cadena de hashes en BD + `vulnix:audit:verify`; respaldo cifrado → restauración en BD de ensayo → verificación (ejecutado 2026-11-15) |
| 10 | Conjunto de referencia y métricas documentados | ⚠️ Parcial | `tests/corpus` + `measure.py`. **Corpus pequeño y creado junto con las reglas: no es representativo** (ver abajo) |

## Criterios medibles de aceptación (§1)

| Criterio | Estado |
|---|---|
| 100 % de análisis con hash de entrada, estado final y versiones | ✅ `artifact_sha256` obligatorio, estado final por máquina de estados (trigger), versión por job |
| 0 autorizaciones con prueba obligatoria fallida/omitida/sin evidencia | ✅ Probado (unitarias + E2E) |
| Pruebas automatizadas del bloqueo ante cambio de hash | ✅ `tests/unit/test_core.py`, `ApiFlowTest`, `tests/acceptance` |
| Corpus con positivos/negativos y precisión/cobertura por clase | ⚠️ Medido sobre corpus propio (32 TP, 0 FN, 0 FP; 17 clases); ampliar con corpus independiente (OWASP Benchmark PHP/JS, proyectos internos) |
| Ejecuciones repetibles; respaldo y restauración probados | ✅ Huellas deterministas; restauración ensayada |

## Pruebas automatizadas (última ejecución)
- Laravel (`php artisan test`): **31 pruebas / 135 aserciones** — gate, ingesta adversarial, RBAC, segregación, inmutabilidad, flujo API.
- Python (`pytest`): **55 pruebas** — extracción segura, sandbox, adaptadores en sandbox real, OSV/CVSS, verificador, corpus.
- Aceptación E2E (`VULNIX_E2E=1 pytest tests/acceptance`): **6 pruebas** contra la plataforma en ejecución.

## Riesgos y decisiones pendientes

| Riesgo / pendiente | Prioridad | Mitigación / siguiente paso |
|---|---|---|
| DAST no implementado (`vulnix-dast` no instalado) | P1 | Fase 4: OWASP ZAP en laboratorio aislado con lista blanca `VULNIX_DAST_ALLOWED_TARGETS` |
| Builds, pruebas y cobertura no se ejecutan | P1 | VM desechable (Hyper-V/KVM) con red de laboratorio; hasta entonces el perfil estricto es INCONCLUSIVE |
| Red no bloqueada por proceso en Windows | P1 | Workers de producción en Linux (namespaces/VM) con egress denegado |
| SAST heurístico (falsos negativos interprocedurales) | P1 | Semgrep con reglas locales (`VULNIX_SEMGREP_RULES`), revisión manual, ampliar corpus |
| Corpus no representativo | P1 | Corpus independiente por tecnología; no publicar cifras de precisión fuera de lo medido |
| Inteligencia npm no importada | P0 operativo | `vulnix-intel fetch/import --ecosystem npm` (~220 MB); sin ella, SCA de proyectos npm = INCONCLUSIVE |
| Redis no usado (cola en PostgreSQL) | P2 | Ver ADR-0002 |
| Ingesta desde repositorio interno autorizado | P1 | Hoy: ZIP o fichero. Añadir clonado de repositorios en lista blanca |
| HTTPS/certificados internos y servidor de producción | P0 producción | `php artisan serve` es solo de desarrollo: usar Apache/Nginx + PHP-FPM con TLS interno y `SESSION_SECURE_COOKIE=true` |
| Repositorio dentro de OneDrive | P0 producción | Datos, claves y sandbox ya están en `%USERPROFILE%\.vulnix-local`; los `.env` (contraseñas de BD de desarrollo) siguen en la carpeta sincronizada: mover el repositorio fuera de OneDrive para producción |
| Interfaz web verificada solo por API y sintaxis | P1 | Revisión visual/manual y pruebas de navegador (Playwright) pendientes |
| Recomendaciones con IA local, correlación avanzada | P2 | Fuera del MVP (backlog P2 del manual) |
