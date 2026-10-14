$ErrorActionPreference = "Stop"

$root = $env:WORKSPACE
if ([string]::IsNullOrWhiteSpace($root)) {
    $root = Split-Path -Parent $PSScriptRoot
}

$python = Join-Path $root "backend\venv\Scripts\python.exe"
$entry = Join-Path $root "run.py"
$reports = Join-Path $root "reports"

New-Item -ItemType Directory -Force $reports | Out-Null

if (!(Test-Path $python)) { throw "Backend Python not found: $python" }
if (!(Test-Path $entry)) { throw "Application entry point not found: $entry" }

$listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($listener) { throw "Port 8000 is occupied. No process was stopped." }

$env:HOST = "127.0.0.1"
$env:PORT = "8000"
$env:APP_DEBUG = "false"

$proc = Start-Process -FilePath $python `
    -ArgumentList @("`"$entry`"") `
    -WorkingDirectory $root `
    -RedirectStandardOutput (Join-Path $reports "deployment.log") `
    -RedirectStandardError (Join-Path $reports "deployment-error.log") `
    -PassThru

Set-Content -Path (Join-Path $reports "deployment.pid") -Value $proc.Id

for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) { throw "Application stopped. Check reports\deployment-error.log" }
    try {
        Invoke-RestMethod "http://127.0.0.1:8000/api/health" -TimeoutSec 2 | Out-Null
        Write-Host "VulnWatch is healthy at http://127.0.0.1:8000"
        exit 0
    } catch {}
}

throw "Health check timed out. Check reports\deployment-error.log"
