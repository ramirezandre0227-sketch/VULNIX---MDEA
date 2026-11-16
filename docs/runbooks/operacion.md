# Runbook · Operación de VULNIX

## Arranque / parada
- Arranque (desarrollo): `powershell -File infra\scripts\start-dev.ps1` → http://127.0.0.1:8000
- Servicios: API+web `:8000`, analyzer-api `:8100` (interno), orquestador (`python -m vulnix_orchestrator run`).
- Si el orquestador no pudo notificar a la API, los análisis quedan en EVALUATING:
  `php apps\api\artisan vulnix:evaluate-pending`.

## Monitorización (manual §11)
Panel **Sistema** o `GET /api/v1/system/health`: BD, clave de firma, espacio en disco, latido del orquestador
(< 3 min), analyzer-api, cola (QUEUED/RUNNING) y frescura de la inteligencia (alerta si > `max_age_days`).

## Inteligencia de vulnerabilidades (offline firmada)
1. Máquina con salida controlada: `vulnix-intel keygen --out <dir>` (una vez) y
   `vulnix-intel fetch --ecosystem npm --out <dir> --sign-key <dir>\intel-signing.key`.
2. Transferir zip + manifiesto por el canal aprobado.
3. En VULNIX: `vulnix-intel import --ecosystem npm --file npm-all.zip --manifest npm-all.manifest.json --public-key intel-signing.pub --require-signature`.
4. `vulnix-intel status`. Con inteligencia caducada (> 7 días por defecto) las decisiones serán INCONCLUSIVE.
> Tamaños orientativos (nov. 2026): Packagist ≈ 11 MB; npm ≈ 220 MB (≈ 1 GB en BD).

## Respaldo y restauración (RPO/RTO)
- Respaldo cifrado (AES-256-GCM, clave scrypt): `set VULNIX_BACKUP_PASSPHRASE=...` y
  `python -m vulnix_orchestrator.ops backup --out %USERPROFILE%\.vulnix-local\backups`.
- Ensayo de restauración en BD de prueba:
  `python -m vulnix_orchestrator.ops restore --file <.vxb> --dsn <dsn_prueba> --data-dir <dir>` y
  `python -m vulnix_orchestrator.ops verify-restore --dsn <dsn_prueba>` (recuentos + cadena de auditoría).
- La frase de paso se custodia aparte; la **clave privada de firma no viaja en el respaldo** (custodia separada).
- Objetivo inicial propuesto: RPO 24 h (respaldo diario), RTO 2 h. Ajustar con la operación real.

## Rotación de la clave de firma
`php artisan vulnix:keys:generate --force` archiva la clave anterior (`retired-<kid>`). Distribuir la nueva clave
pública (`GET /api/v1/authorization/public-key`) a los pipelines **antes** de rotar; las autorizaciones previas dejan
de verificar con la clave nueva (vencen igualmente según `VULNIX_AUTHORIZATION_TTL_HOURS`).

## Auditoría
`php artisan vulnix:audit:verify` o panel **Auditoría → Verificar integridad**. Una cadena rota es un incidente de seguridad.

## Gate de despliegue
`infra\deploy\deploy-gate.ps1 -Artifact <zip> -Token <jws> -PublicKey <pub>` (o `deploy-gate.sh`). Debe ser el
**único** camino hacia producción (checklist §14).
