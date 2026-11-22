# Builds Vigil's setup from target\release\vigil.exe with NSIS (installs NSIS on a runner that lacks
# it) and writes the version it used to <Out>\version.txt.
#
#   installer\build-setup.ps1 -Out dist
param([Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$version = ((cargo metadata --no-deps --format-version 1 --manifest-path (Join-Path $root "Cargo.toml") |
    ConvertFrom-Json).packages | Where-Object name -eq "vigil-app").version
$exe = Join-Path $root "target\release\vigil.exe"
if (-not (Test-Path $exe)) { throw "build vigil.exe first: cargo build --release -p vigil-app" }
New-Item -ItemType Directory -Force $Out | Out-Null
$outDir = (Resolve-Path $Out).Path
$makensis = Join-Path ${env:ProgramFiles(x86)} "NSIS\makensis.exe"
if (-not (Test-Path $makensis)) {
    choco install nsis -y --no-progress
    if ($LASTEXITCODE -ne 0) { throw "NSIS could not be installed" }
}
& $makensis /V2 "/DVERSION=$version" "/DEXE=$exe" "/DOUT=$outDir\Vigil_${version}_x64-setup.exe" (Join-Path $PSScriptRoot "vigil.nsi")
if ($LASTEXITCODE -ne 0) { throw "makensis failed" }
Set-Content -Path (Join-Path $outDir "version.txt") -Value $version -NoNewline
Write-Output "Vigil_${version}_x64-setup.exe"
