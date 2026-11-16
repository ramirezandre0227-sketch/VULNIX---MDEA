<#
.SYNOPSIS
  Gate de despliegue (manual §7 y §14): NINGUNA ruta de despliegue debe omitir esta verificación.
.DESCRIPTION
  Verifica fuera de línea la autorización firmada de VULNIX contra el artefacto EXACTO que se va a instalar:
  firma Ed25519, emisor, vigencia, resultado APPROVED y SHA-256 del artefacto. Ante cualquier error, bloquea
  (fail closed): verificador ausente, ficheros ilegibles o autorización inválida.
  La clave pública debe estar fijada en el pipeline (no descargarla en el momento del despliegue).
.EXAMPLE
  .\deploy-gate.ps1 -Artifact build\app.zip -Token vulnix-authorization.jws -PublicKey C:\pipeline\vulnix-ed25519.pub
#>
param(
  [Parameter(Mandatory)] [string]$Artifact,
  [Parameter(Mandatory)] [string]$Token,
  [Parameter(Mandatory)] [string]$PublicKey,
  [string]$Issuer = "vulnix-local",
  [string]$Verifier = ""
)
$ErrorActionPreference = "Stop"
function Block([string]$why) { Write-Host "DESPLIEGUE BLOQUEADO por VULNIX: $why" -ForegroundColor Red; exit 1 }

if (-not $Verifier) { $Verifier = Join-Path $PSScriptRoot "..\..\.venv\Scripts\vulnix-verify.exe" }
if (-not (Test-Path $Verifier)) { Block "verificador no encontrado ($Verifier)" }
foreach ($f in $Artifact, $Token, $PublicKey) { if (-not (Test-Path $f -PathType Leaf)) { Block "fichero no encontrado: $f" } }

try {
  & $Verifier --token $Token --artifact $Artifact --public-key $PublicKey --issuer $Issuer
  $code = $LASTEXITCODE
} catch {
  Block "error al ejecutar el verificador: $($_.Exception.Message)"
}
if ($code -ne 0) { Block "autorización inválida para este artefacto (código $code)" }

Write-Host "Autorización válida: se puede instalar exactamente este artefacto." -ForegroundColor Green
# >>> Aquí continúa el procedimiento de instalación (copiar $Artifact al destino, etc.) <<<
exit 0
