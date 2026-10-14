$ErrorActionPreference = "Stop"

$url = "http://127.0.0.1:8000/api/health"

try {
    $response = Invoke-RestMethod -Uri $url -TimeoutSec 10

    if ($null -eq $response) {
        throw "Health endpoint returned an empty response."
    }

    Write-Host "VulnWatch is healthy at http://127.0.0.1:8000"
    Write-Host "Deployment verification successful."
    exit 0
}
catch {
    Write-Error "VulnWatch is not healthy at $url. $($_.Exception.Message)"
    exit 1
}
