# ADR-0003 · Motor de políticas fail-closed y autorización firmada

**Estado:** aceptado · **Fecha:** 2026-11-15

## Decisión
1. **Políticas** en YAML versionado (`policies/`), validadas y normalizadas a JSON canónico cuyo SHA-256 se liga a
   cada decisión. Contenido inmutable (trigger); ciclo de vida DRAFT → ACTIVE (aprobación por persona distinta del
   autor) → RETIRED. `fail_closed: true` es obligatorio: el cargador rechaza políticas fail-open.
2. **Precedencia** (manual §7): INCONCLUSIVE > REVIEW_REQUIRED > REJECTED > APPROVED. Se registran *todas* las
   razones aunque gane una de mayor precedencia. Un job FAILED/TIMED_OUT/SKIPPED/CANCELLED **nunca** es PASS.
   La evidencia de cada control obligatorio se re-hashea al evaluar; el artefacto también.
3. **Hallazgos inciertos**: crítico/alto con confianza no alta → REVIEW_REQUIRED (revisión humana, §14).
4. **Excepciones**: resolución separada (los hallazgos son inmutables), aprobador ≠ solicitante (CHECK en BD),
   vencimiento obligatorio (máx. 90 días). Una excepción aprobada aplica a la misma huella en otras versiones
   del mismo proyecto hasta que vence.
5. **Autorización**: JWS compacto EdDSA (Ed25519, RFC 8037), `typ: vulnix-deploy-authz+jwt`, con
   `artifact_sha256, analysis_id, policy_sha256, result, issued_at, expires_at, issuer`. Sin clave → no hay decisión.
   Verificación fuera de línea con `vulnix-verify` (Python) o `php artisan vulnix:verify-authorization`.

## Consecuencias
- Un cambio de un solo byte en el artefacto invalida la autorización (probado en `tests/unit`, `ApiFlowTest` y E2E).
- Las decisiones son inmutables; reevaluar crea una decisión nueva (historial completo).
