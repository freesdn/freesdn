# SPDX-License-Identifier: AGPL-3.0-only
# Record a real-device cassette for one adapter (Windows / PowerShell).
#
#   .\record-cassette.ps1 -Adapter pfsense -DeviceHost 10.0.0.1 -User admin -Pass 's3cret'
#   .\record-cassette.ps1 -Adapter mikrotik -DeviceHost 10.0.0.2 -User admin -Pass 'x' -Port 443
#   # grandstream also needs the phone MAC:
#   .\record-cassette.ps1 -Adapter grandstream -DeviceHost 192.168.0.21 -User admin -Pass 'x' -Mac 00:0b:82:..
#
# Recordings land in $env:FREESDN_CASSETTE_DIR (default: a 'freesdn-cassettes'
# folder in your home dir), kept OFF-REPO.
# Run from the backend dir with the project venv active (python -m pytest).
param(
  [Parameter(Mandatory = $true)][string]$Adapter,
  [Parameter(Mandatory = $true)][string]$DeviceHost,
  [Parameter(Mandatory = $true)][string]$User,
  [Parameter(Mandatory = $true)][string]$Pass,
  [int]$Port,
  [string]$Mac,
  [string]$UseSsl
)

if (-not $env:FREESDN_CASSETTE_DIR) { $env:FREESDN_CASSETTE_DIR = Join-Path $HOME 'freesdn-cassettes' }
$env:FREESDN_RECORD_FIXTURES = '1'
$env:FREESDN_RECORD_HOST = $DeviceHost
$env:FREESDN_RECORD_USERNAME = $User
$env:FREESDN_RECORD_PASSWORD = $Pass
if ($Port) { $env:FREESDN_RECORD_PORT = "$Port" } else { Remove-Item Env:FREESDN_RECORD_PORT -ErrorAction SilentlyContinue }
if ($Mac) { $env:FREESDN_RECORD_MAC = $Mac } else { Remove-Item Env:FREESDN_RECORD_MAC -ErrorAction SilentlyContinue }
if ($UseSsl) { $env:FREESDN_RECORD_USE_SSL = $UseSsl } else { Remove-Item Env:FREESDN_RECORD_USE_SSL -ErrorAction SilentlyContinue }

Write-Host "Recording '$Adapter' from $DeviceHost -> $env:FREESDN_CASSETTE_DIR (off-repo)" -ForegroundColor Cyan
python -m pytest "tests/adapters/test_${Adapter}_cassette.py" -v
$code = $LASTEXITCODE

# Don't leave real creds in the session environment.
foreach ($v in 'FREESDN_RECORD_FIXTURES', 'FREESDN_RECORD_HOST', 'FREESDN_RECORD_USERNAME', 'FREESDN_RECORD_PASSWORD', 'FREESDN_RECORD_PORT', 'FREESDN_RECORD_MAC', 'FREESDN_RECORD_USE_SSL') {
  Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}
exit $code
