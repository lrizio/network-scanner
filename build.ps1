<#
  Builds the standalone Windows package into .\build :

    build\NetworkScanner.exe   single-file app (Python, Flask, scapy, python-nmap embedded; asks for admin)
    build\nmap\                portable Nmap copied from your Nmap install
    build\USER_GUIDE.html      offline user guide

  Usage:  powershell -ExecutionPolicy Bypass -File .\build.ps1
  Optional: -NmapDir "D:\Tools\Nmap"   (default: C:\Program Files (x86)\Nmap)
#>
param(
    [string]$NmapDir = "C:\Program Files (x86)\Nmap",
    [string]$Python = "python"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$out  = Join-Path $PSScriptRoot "build"
$work = Join-Path $PSScriptRoot ".pyinstaller"
$venv = Join-Path $PSScriptRoot ".buildenv"

Write-Host "==> Preparing build environment"
if (-not (Test-Path "$venv\Scripts\python.exe")) { & $Python -m venv $venv }
& "$venv\Scripts\python.exe" -m pip install -q --upgrade pip
& "$venv\Scripts\python.exe" -m pip install -q -r requirements.txt pyinstaller

Write-Host "==> Building NetworkScanner.exe"
Remove-Item $out, $work -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $out | Out-Null
& "$venv\Scripts\python.exe" -m PyInstaller (Join-Path $PSScriptRoot "app.py") `
    --name NetworkScanner --onefile --console --uac-admin --noconfirm --clean `
    --add-data ((Join-Path $PSScriptRoot "templates") + ";templates") `
    --collect-submodules scapy.layers `
    --distpath $out --workpath "$work\work" --specpath $work
if (-not (Test-Path "$out\NetworkScanner.exe")) { throw "PyInstaller did not produce the exe" }

Write-Host "==> Bundling portable Nmap from $NmapDir"
if (Test-Path "$NmapDir\nmap.exe") {
    $dest = Join-Path $out "nmap"
    New-Item -ItemType Directory $dest | Out-Null
    # Runtime files only: skip Zenmap GUI, ncat, nping, installers and uninstaller.
    Get-ChildItem $NmapDir -File | Where-Object {
        $_.Name -in @("nmap.exe","nse_main.lua","nmap.xsl","ca-bundle.crt","LICENSE","3rd-party-licenses.txt") -or
        $_.Name -like "nmap-*" -or $_.Extension -eq ".dll"
    } | Copy-Item -Destination $dest
    foreach ($d in "scripts","nselib","licenses") {
        if (Test-Path "$NmapDir\$d") { Copy-Item "$NmapDir\$d" $dest -Recurse }
    }
} else {
    Write-Warning "nmap.exe not found in '$NmapDir'. The exe will rely on a system-installed Nmap. Re-run with -NmapDir."
}

Copy-Item "templates\guide.html" (Join-Path $out "USER_GUIDE.html")
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue

$mb = [math]::Round((Get-ChildItem $out -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "==> Done: $out ($mb MB)"
