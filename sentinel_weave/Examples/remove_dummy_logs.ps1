$dummyPath = Join-Path $PSScriptRoot "dummy_logs"
if (Test-Path $dummyPath) {
    Remove-Item -Path $dummyPath -Recurse -Force
    Write-Host "Removed: $dummyPath"
} else {
    Write-Host "No dummy log directory found at: $dummyPath"
}
