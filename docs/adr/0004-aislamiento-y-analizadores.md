# ADR-0004 · Aislamiento de workers y analizadores integrados

**Estado:** aceptado (piloto) · **Fecha:** 2026-11-15

## Decisión
- **Analizadores integrados offline** (sin red, deterministas): `vulnix-sast` (reglas PHP/JS/TS/HTML/CSS con
  rastreo de contaminación intra-fichero), `vulnix-secrets` (redacción en origen), `vulnix-sca` (lockfiles +
  inteligencia OSV local), `vulnix-quality` (`php -l`, `node --check`, `tsc` opcional, métricas).
  Semgrep y Gitleaks son **opcionales** y solo con reglas locales (`VULNIX_SEMGREP_RULES`).
- **Todo** analizador se ejecuta como subproceso en un sandbox efímero por job:
  extracción segura repetida (defensa en profundidad), código de solo lectura, entorno mínimo sin credenciales,
  `python -I` (ignora módulos plantados), límites de tiempo/salida y, en Windows, **Job Object**
  (memoria, nº de procesos, muerte garantizada del árbol); en Linux, rlimits + grupo de procesos.
- **No se ejecuta código del proyecto** (builds, tests, DAST): requiere VM desechable (§8). Por eso la política
  estricta resulta INCONCLUSIVE hasta disponer de ese laboratorio: es el comportamiento fail-closed esperado.

## Limitaciones conocidas
- En Windows no se bloquea la red por proceso sin privilegios: los runners integrados no la usan; las herramientas
  externas deben configurarse sin red. Producción: workers Linux en VM desechable con red de laboratorio aislada.
- El SAST integrado es heurístico (patrones + taint intra-fichero). Complementar con Semgrep y revisión manual.
