#Requires -Version 5.1
<#
.SYNOPSIS
  Authenticode-sign IoTGatewayMonitor.exe in CI when PFX secrets are set.

.DESCRIPTION
  Expects:
    WINDOWS_CODE_SIGN_PFX_BASE64  — base64 of the .pfx / .p12 file
    WINDOWS_CODE_SIGN_PFX_PASSWORD — PFX password
  Optional:
    WINDOWS_CODE_SIGN_TIMESTAMP_URL — default DigiCert RFC3161 TSA
    IOTGW_DIST — directory containing IoTGatewayMonitor.exe

  If the PFX secret is empty, exits 0 and leaves the EXE unsigned (local/dev CI).
#>
$ErrorActionPreference = "Stop"

$pfxB64 = [string]$env:WINDOWS_CODE_SIGN_PFX_BASE64
$pfxPass = [string]$env:WINDOWS_CODE_SIGN_PFX_PASSWORD
$tsa = if ($env:WINDOWS_CODE_SIGN_TIMESTAMP_URL) {
    $env:WINDOWS_CODE_SIGN_TIMESTAMP_URL
} else {
    "http://timestamp.digicert.com"
}
$dist = if ($env:IOTGW_DIST) { $env:IOTGW_DIST } else {
    Join-Path $PSScriptRoot "..\dist" | Resolve-Path -ErrorAction SilentlyContinue
}
if (-not $dist) {
    $dist = Join-Path (Split-Path $PSScriptRoot -Parent) "dist"
}
$exe = Join-Path $dist "IoTGatewayMonitor.exe"

if ([string]::IsNullOrWhiteSpace($pfxB64)) {
    Write-Host "WINDOWS_CODE_SIGN_PFX_BASE64 not set — publishing unsigned EXE."
    exit 0
}
if ([string]::IsNullOrWhiteSpace($pfxPass)) {
    throw "WINDOWS_CODE_SIGN_PFX_PASSWORD is required when PFX base64 is set"
}
if (-not (Test-Path -LiteralPath $exe)) {
    throw "EXE not found: $exe"
}

$signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" `
    -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    throw "signtool.exe (x64) not found under Windows Kits — install Windows SDK on the runner"
}
Write-Host "Using $signtool"

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("iotgw-sign-" + [guid]::NewGuid().ToString("n"))
New-Item -ItemType Directory -Path $work | Out-Null
$pfxPath = Join-Path $work "codesign.pfx"
try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($pfxB64.Trim()))

    # Sign in place (release publishes this same path).
    & $signtool sign `
        /fd SHA256 `
        /td SHA256 `
        /tr $tsa `
        /f $pfxPath `
        /p $pfxPass `
        /d "IoT Gateway Monitor" `
        $exe
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed with exit $LASTEXITCODE"
    }

    & $signtool verify /pa /v $exe
    if ($LASTEXITCODE -ne 0) {
        throw "signtool verify failed with exit $LASTEXITCODE"
    }
    Write-Host "Authenticode signature OK: $exe"

    # Refresh checksums next to the signed binary.
    $sums = Join-Path $dist "SHA256SUMS-windows.txt"
    $hash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $sums -Value ("{0} *IoTGatewayMonitor.exe" -f $hash) -Encoding ascii
    Write-Host "Wrote $sums"
}
finally {
    if (Test-Path -LiteralPath $work) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
