# VULNIX · Gate DevSecOps local para proyectos web

VULNIX recibe un proyecto web (ZIP o fichero), detecta sus tecnologías, ejecuta análisis estático (SAST),
composición de software (SCA), búsqueda de secretos y calidad en un **sandbox aislado**, normaliza los hallazgos,
propone correcciones y emite una **decisión firmada (Ed25519) ligada al SHA-256 exacto del artefacto**. El pipeline
de despliegue solo instala si esa autorización es válida para *ese* artefacto.

> VULNIX es un evaluador técnico, no una certificación de ausencia de vulnerabilidades (manual §14).

Implementación según el *Manual Maestro de Desarrollo v1.0*. Estado detallado y riesgos pendientes en
[docs/ESTADO.md](docs/ESTADO.md).

## Arquitectura

```
Usuario ─► apps/web ─► apps/api (Laravel) ─► Ingesta segura ─► SHA-256 + inventario + tecnologías
                              │                                     │
                              │                         evaluation.scan_jobs (cola PostgreSQL, SKIP LOCKED)
                              │                                     │
                              │                    services/orchestrator ─► workers/sandbox (por job)
                              │                                     │      SAST · SCA · Secretos · Calidad
                              │                         normalización + correlación + evidencias
                              ▼                                     │
               Motor de políticas fail-closed ◄── EVALUATING ───────┘
                              │
               Decisión firmada (JWS EdDSA) + reportes JSON/SARIF/HTML/PDF + auditoría encadenada
```

| Ruta | Contenido |
|---|---|
| `apps/web/` | Panel (HTML/CSS/JS sin build, CSP estricta) |
| `apps/api/` | Laravel 12: auth/RBAC, ingesta, planificador, políticas, firma, reportes, auditoría |
| `services/orchestrator/` | Worker: cola, leases, reintentos, sandbox, normalización, inteligencia OSV, respaldos |
| `services/analyzer-api/` | FastAPI interno: salud/catálogo de analizadores, reglas, normalización SARIF |
| `workers/adapters/` | Contrato `AnalyzerAdapter` + analizadores integrados y externos (Semgrep, Gitleaks) |
| `workers/sandbox/` | Extracción segura, Job Objects de Windows / rlimits POSIX |
| `packages/schemas/` | JSON Schema (hallazgo, solicitud, autorización, política) y OpenAPI |
| `policies/` | Políticas versionadas (`web-development`, `web-production-strict`) |
| `apps/api/database/migrations/` | Esquemas `identity`, `catalog`, `evaluation`, `audit` + triggers de integridad |
| `infra/` | SQL de roles/permisos, scripts de instalación y arranque, gate de despliegue |
| `tests/` | unit · security · functional (corpus) · integration · acceptance (E2E) |
| `docs/` | ADR, runbooks, estado/trazabilidad |

## Instalación (Windows, desarrollo)

Requisitos: PHP 8.2+ (XAMPP) con `pdo_pgsql, pgsql, zip, sodium, intl, gd`; PostgreSQL 16; Python 3.12; Node 20+.

```powershell
powershell -ExecutionPolicy Bypass -File infra\scripts\setup-dev.ps1     # idempotente
powershell -File infra\scripts\start-dev.ps1                             # API :8000, analyzer-api :8100, orquestador
```

Abrir http://127.0.0.1:8000. Secretos, claves de firma, artefactos y sandbox se guardan en
`%USERPROFILE%\.vulnix-local\` (fuera de carpetas sincronizadas).

Crear usuarios: `php apps\api\artisan vulnix:user:create <usuario> --role=developer|security_reviewer|approver|admin|auditor`.

Importar inteligencia de vulnerabilidades (obligatorio para SCA; sin ella el resultado es INCONCLUSIVE):
ver [docs/runbooks/operacion.md](docs/runbooks/operacion.md#inteligencia-de-vulnerabilidades-offline-firmada).

## Uso típico

1. **Proyectos → Nuevo proyecto** (criticidad y perfil de evaluación).
2. **Nueva versión**: subir ZIP. Se rechazan ZIP Slip, enlaces, bombas de compresión, nombres reservados.
3. **Analizar**: el orquestador ejecuta los controles; la decisión se emite automáticamente.
4. Revisar hallazgos (corrección propuesta + cómo verificarla), solicitar excepciones con vencimiento
   (las aprueba otra persona), comparar con versiones anteriores.
5. Descargar la **autorización .jws** y desplegar solo a través del gate:

```powershell
infra\deploy\deploy-gate.ps1 -Artifact build\app.zip -Token vulnix-authorization.jws -PublicKey C:\pipeline\vulnix-ed25519.pub
```

Desde CI (token Bearer): `POST /api/v1/auth/login` → `POST /projects/{id}/versions` → `POST /analyses`
(con `Idempotency-Key`) → `GET /analyses/{id}` hasta estado terminal → `GET /analyses/{id}/decision/token`.
Contrato completo en [packages/schemas/openapi.yaml](packages/schemas/openapi.yaml).

## Decisión (manual §7)

| Resultado | Cuándo |
|---|---|
| `INCONCLUSIVE` | artefacto/evidencia alterados, control obligatorio fallido/omitido/sin ejecutar, inteligencia caducada, build/pruebas/cobertura sin verificar |
| `REVIEW_REQUIRED` | excepciones pendientes o hallazgos crítico/alto de confianza no alta |
| `REJECTED` | críticos/altos confirmados por encima del umbral, secretos expuestos, build/pruebas fallidas, cobertura insuficiente |
| `APPROVED` | solo el cumplimiento íntegro de la política |

Perfiles incluidos: `web-development` (SAST, SCA, secretos, verificación sintáctica) y `web-production-strict`
(además DAST, pruebas y cobertura ≥ 80 %: hoy resulta **INCONCLUSIVE** a propósito hasta disponer del laboratorio DAST y
de la VM de ejecución).

## Pruebas

```powershell
cd apps\api; php artisan test                                  # 31 pruebas (BD vulnix_test)
.venv\Scripts\python -m pytest                                  # 55 pruebas
.venv\Scripts\python tests\corpus\measure.py                    # precisión/cobertura por clase
$env:VULNIX_E2E=1; .venv\Scripts\python -m pytest tests\acceptance   # E2E con la plataforma arrancada
```

## Seguridad de la propia plataforma

- Roles de BD por servicio; el orquestador **no puede** leer identidades ni escribir decisiones/excepciones.
- Triggers: auditoría append-only con cadena de hashes, decisiones/evidencias/artefactos/políticas inmutables,
  máquina de estados del análisis.
- Sesión con CSRF (frontend) o token Bearer con caducidad; bloqueo tras 5 fallos; rate limits; CSP sin inline.
- Secretos detectados redactados en origen (nunca se guarda el valor ni su hash).
- Workers sin credenciales, `python -I`, código de solo lectura, límites de memoria/procesos/tiempo/salida.
