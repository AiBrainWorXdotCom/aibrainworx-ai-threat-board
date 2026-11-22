param(
    [switch]$Rebuild,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PassThruArgs
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$exePath = "$root\backend\target\release\aibrainworx-threat-board.exe"
if ($Rebuild -or -not (Test-Path $exePath)) {
    foreach ($cmd in @("node", "npm", "cargo")) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            Write-Error "Required tool '$cmd' was not found on PATH to build from source."
            exit 1
        }
    }

    Write-Host "Building React + Meta Astryx UI production bundle..."
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

    Write-Host "Building single-file Rust release binary (embedding frontend assets)..."
    Push-Location "$root\backend"
    try {
        cargo build --release
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } finally {
        Pop-Location
    }
}

$activeBind = if ($env:BIND_ADDR) { $env:BIND_ADDR } else { "127.0.0.1" }
$activePort = if ($env:PORT) { $env:PORT } else { "8080" }
Write-Host "Starting AiBrainWorX CyberSecurity Threat Analysis Board v0.2.0 at http://${activeBind}:${activePort}"
& $exePath @PassThruArgs
