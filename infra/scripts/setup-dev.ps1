<#
.SYNOPSIS
  Instalación local reproducible de VULNIX en Windows (idempotente).
.DESCRIPTION
  Requisitos: PHP 8.2+ (extensiones pdo_pgsql, pgsql, zip, sodium, intl, gd), PostgreSQL 16, Python 3.12, Node 20+, Git.
  Datos sensibles (secretos, claves de firma, artefactos, sandbox) se guardan FUERA de carpetas sincronizadas,
  en $env:USERPROFILE\.vulnix-local (manual §8: no montar secretos del host; nada en servicios cloud).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File infra\scripts\setup-dev.ps1
#>
[CmdletBinding()]
param(
  [string]$PgBin = "C:\Program Files\PostgreSQL\16\bin",
  [string]$PhpBin = "C:\xampp\php\php.exe",
  [string]$PythonBin = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
  [string]$AdminUser = "admin"
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$Local = Join-Path $env:USERPROFILE ".vulnix-local"
$Api = Join-Path $Root "apps\api"
New-Item -ItemType Directory -Force $Local, "$Local\data", "$Local\keys", "$Local\sandbox", "$Local\bin", "$Local\backups" | Out-Null

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function New-Secret { $b = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); ($b | ForEach-Object { $_.ToString("x2") }) -join "" }

Step "Comprobando requisitos"
foreach ($t in @($PhpBin, "$PgBin\psql.exe", $PythonBin)) { if (-not (Test-Path $t)) { throw "No encontrado: $t" } }
$mods = & $PhpBin -m
foreach ($e in "pdo_pgsql", "zip", "sodium") { if ($mods -notcontains $e) { throw "Extensión PHP '$e' no habilitada en php.ini" } }

Step "Secretos locales ($Local\dev-secrets.env)"
$secFile = Join-Path $Local "dev-secrets.env"
if (-not (Test-Path $secFile)) {
  @("VULNIX_PG_OWNER_PASSWORD=$(New-Secret)", "VULNIX_PG_API_PASSWORD=$(New-Secret)", "VULNIX_PG_ORCH_PASSWORD=$(New-Secret)", "VULNIX_INTERNAL_TOKEN=$(New-Secret)$(New-Secret)") |
    Set-Content -Encoding ascii $secFile
}
$sec = @{}; Get-Content $secFile | ForEach-Object { $k, $v = $_ -split "=", 2; $sec[$k] = $v }

Step "PostgreSQL: roles y bases de datos"
$suFile = Join-Path $Local "pg_superuser_password.txt"
$env:PGPASSWORD = if (Test-Path $suFile) { (Get-Content $suFile -Raw).Trim() } else { Read-Host "Contraseña del superusuario postgres" }
& "$PgBin\psql.exe" -q -U postgres -h 127.0.0.1 -v "owner_pw=$($sec.VULNIX_PG_OWNER_PASSWORD)" -v "api_pw=$($sec.VULNIX_PG_API_PASSWORD)" `
  -v "orch_pw=$($sec.VULNIX_PG_ORCH_PASSWORD)" -f "$Root\infra\postgres\bootstrap.sql"
if ($LASTEXITCODE) { throw "bootstrap.sql falló" }

Step "Composer y dependencias PHP"
$composer = Join-Path $Local "bin\composer.phar"
if (-not (Test-Path $composer)) {
  $expected = (Invoke-WebRequest -UseBasicParsing https://composer.github.io/installer.sig).Content.Trim()
  & $PhpBin -r "copy('https://getcomposer.org/installer', '$Local/bin/composer-setup.php');"
  $actual = & $PhpBin -r "echo hash_file('sha384', '$Local/bin/composer-setup.php');"
  if ($expected -ne $actual) { throw "Firma del instalador de Composer inválida" }
  & $PhpBin "$Local\bin\composer-setup.php" --quiet --install-dir="$Local\bin"; Remove-Item "$Local\bin\composer-setup.php"
}
Push-Location $Api
& $PhpBin $composer install --no-interaction --prefer-dist
Pop-Location

Step "Configuración de la API (apps\api\.env)"
$envFile = Join-Path $Api ".env"
if (-not (Test-Path $envFile)) { Copy-Item "$Api\.env.example" $envFile }
$content = Get-Content $envFile -Raw
$set = @{
  "DB_PASSWORD" = $sec.VULNIX_PG_API_PASSWORD; "DB_OWNER_PASSWORD" = $sec.VULNIX_PG_OWNER_PASSWORD
  "VULNIX_INTERNAL_TOKEN" = $sec.VULNIX_INTERNAL_TOKEN; "VULNIX_DATA_DIR" = ("$Local\data" -replace "\\", "/")
  "VULNIX_KEYS_DIR" = ("$Local\keys" -replace "\\", "/")
}
foreach ($k in $set.Keys) { $content = [regex]::Replace($content, "(?m)^$k=.*$", "$k=$($set[$k])") }
Set-Content -Encoding utf8 $envFile $content.TrimEnd()
Push-Location $Api
if ((Select-String -Path $envFile -Pattern "^APP_KEY=base64:" -Quiet) -eq $false) { & $PhpBin artisan key:generate --force }

Step "Migraciones (rol dueño) y permisos mínimos por servicio"
& $PhpBin artisan migrate --database=pgsql_owner --force
$env:PGPASSWORD = $sec.VULNIX_PG_OWNER_PASSWORD
& "$PgBin\psql.exe" -q -U vulnix_owner -h 127.0.0.1 -d vulnix -f "$Root\infra\postgres\grants.sql"
if ($LASTEXITCODE) { throw "grants.sql falló" }

Step "Clave de firma Ed25519 y políticas"
& $PhpBin artisan vulnix:keys:generate
& $PhpBin artisan vulnix:policies:sync --activate
& $PhpBin artisan vulnix:user:create $AdminUser --role=admin --name="Administración" 2>$null
Pop-Location

Step "Motor Python (.venv)"
if (-not (Test-Path "$Root\.venv")) { & $PythonBin -m venv "$Root\.venv" }
& "$Root\.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
& "$Root\.venv\Scripts\python.exe" -m pip install --quiet -e "$Root[dev]"
$rootEnv = @(
  "# Generado por setup-dev.ps1. NO versionar.",
  "VULNIX_DB_DSN=postgresql://vulnix_orchestrator:$($sec.VULNIX_PG_ORCH_PASSWORD)@127.0.0.1:5432/vulnix",
  "VULNIX_ADMIN_DSN=postgresql://vulnix_owner:$($sec.VULNIX_PG_OWNER_PASSWORD)@127.0.0.1:5432/vulnix",
  "VULNIX_DATA_DIR=$("$Local\data" -replace '\\', '/')",
  "VULNIX_SANDBOX_ROOT=$("$Local\sandbox" -replace '\\', '/')",
  "VULNIX_API_INTERNAL_URL=http://127.0.0.1:8000",
  "VULNIX_INTERNAL_TOKEN=$($sec.VULNIX_INTERNAL_TOKEN)",
  "VULNIX_PHP_BIN=$($PhpBin -replace '\\', '/')",
  "VULNIX_NODE_BIN=node",
  "VULNIX_PG_BIN_DIR=$PgBin"
)
Set-Content -Encoding utf8 "$Root\.env" $rootEnv

Write-Host ""
Write-Host "VULNIX instalado. Siguientes pasos:" -ForegroundColor Green
Write-Host "  1) Importar inteligencia OSV:  .venv\Scripts\vulnix-intel import --ecosystem Packagist --file <zip> [--manifest ... --public-key ...]"
Write-Host "  2) Arrancar servicios:         powershell -File infra\scripts\start-dev.ps1"
Write-Host "  3) Abrir                       http://127.0.0.1:8000"
