$ErrorActionPreference = "Stop"

$root = $env:WORKSPACE
if ([string]::IsNullOrWhiteSpace($root)) {
    $root = Split-Path -Parent $PSScriptRoot
}

$python = Join-Path $root "backend\venv\Scripts\python.exe"
$entry = Join-Path $root "run.py"
$reports = Join-Path $root "reports"
$pidFile = Join-Path $reports "deployment.pid"
$logFile = Join-Path $reports "deployment.log"
$errorFile = Join-Path $reports "deployment-error.log"

New-Item -ItemType Directory -Force $reports | Out-Null

if (!(Test-Path $python)) { throw "Backend Python not found: $python" }
if (!(Test-Path $entry)) { throw "Application entry point not found: $entry" }

$listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    try {
        Invoke-RestMethod "http://127.0.0.1:8000/api/health" -TimeoutSec 3 | Out-Null
        Write-Host "VulnWatch is already healthy at http://127.0.0.1:8000"
        return
    } catch {
        throw "Port 8000 is occupied by another or unhealthy process. No process was stopped."
    }
}

$env:HOST = "127.0.0.1"
$env:PORT = "8000"
$env:APP_DEBUG = "false"

$proc = Start-Process -FilePath $python `
    -ArgumentList @("`"$entry`"") `
    -WorkingDirectory $root `
    -RedirectStandardOutput $logFile `
    -RedirectStandardError $errorFile `
    -PassThru

Set-Content -Path $pidFile -Value $proc.Id

$healthy = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    $proc.Refresh()

    if ($proc.HasExited) {
        Get-Content $errorFile -ErrorAction SilentlyContinue
        throw "VulnWatch stopped during startup. Check reports\deployment-error.log"
    }

    try {
        Invoke-RestMethod "http://127.0.0.1:8000/api/health" -TimeoutSec 2 | Out-Null
        $healthy = $true
        break
    } catch {}
}

if (!$healthy) {
    throw "Health check timed out. Check reports\deployment-error.log"
}

Write-Host "VulnWatch deployment succeeded at http://127.0.0.1:8000"