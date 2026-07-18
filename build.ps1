$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ProjectRoot
$BuildTemp = Join-Path $ProjectRoot ".build-temp"
New-Item -ItemType Directory -Force -Path $BuildTemp | Out-Null
$env:TEMP = $BuildTemp
$env:TMP = $BuildTemp
$ExeName = "Flash Share"

if (-not (Test-Path -LiteralPath ".venv\Scripts\python.exe")) {
    py -3.13 -m venv .venv
}

if (-not (Test-Path -LiteralPath ".venv\Scripts\pip.exe")) {
    & ".venv\Scripts\python.exe" -m ensurepip --upgrade --default-pip
}

& ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
& ".venv\Scripts\python.exe" -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name $ExeName `
    --collect-all cryptography `
    --collect-all tkinterdnd2 `
    quickdrop.py

Copy-Item -Force -LiteralPath (Join-Path $ProjectRoot "dist\$ExeName.exe") -Destination (Join-Path $ProjectRoot "$ExeName.exe")

Write-Host ""
Write-Host "Build complete: $ProjectRoot\$ExeName.exe" -ForegroundColor Green
