param(
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

foreach ($cmd in @("node", "npm", "cargo")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Error "Required tool '$cmd' was not found on PATH. See README.md for Windows prerequisite installation."
        exit 1
    }
}

if ($Rebuild -or -not (Test-Path "$root\frontend\dist\index.html")) {
    Write-Host "Building React + Meta Astryx UI frontend..."
    Push-Location "$root\frontend"
    try {
        if (-not (Test-Path "$root\frontend\node_modules")) {
            npm ci
            if ($LASTEXITCODE -ne 0) { npm install }
        }
        npm run build
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
}

$exePath = "$root\backend\target\release\aibrainworx-threat-board.exe"
if ($Rebuild -or -not (Test-Path $exePath)) {
    Write-Host "Building Rust backend (release profile)..."
    Push-Location "$root\backend"
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
}

$activePort = if ($env:PORT) { $env:PORT } else { "8080" }
Write-Host "Starting AiBrainWorX CyberSecurity Threat Analysis Board at http://127.0.0.1:$activePort"
& $exePath
