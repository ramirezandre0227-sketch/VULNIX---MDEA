<#
.SYNOPSIS
  Arranca los tres servicios de VULNIX en ventanas separadas (desarrollo local).
  - API + frontend (Laravel)   http://127.0.0.1:8000
  - analyzer-api (FastAPI)     http://127.0.0.1:8100  (interno, requiere token de servicio)
  - orquestador/worker         cola PostgreSQL, sandbox por job
#>
param([string]$PhpBin = "C:\xampp\php\php.exe")
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$Py = Join-Path $Root ".venv\Scripts\python.exe"

Start-Process -FilePath $PhpBin -ArgumentList "artisan", "serve", "--host=127.0.0.1", "--port=8000" -WorkingDirectory (Join-Path $Root "apps\api") -WindowStyle Minimized
Start-Process -FilePath $Py -ArgumentList "-m", "vulnix_analyzer_api" -WorkingDirectory $Root -WindowStyle Minimized
Start-Process -FilePath $Py -ArgumentList "-m", "vulnix_orchestrator", "run" -WorkingDirectory $Root -WindowStyle Minimized

Write-Host "Servicios iniciados. Abra http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "Respaldo de evaluación pendiente (si el orquestador no pudo notificar):  php apps\api\artisan vulnix:evaluate-pending"
