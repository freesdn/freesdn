<#
.SYNOPSIS
  FreeSDN Self-Healing Start (Windows)
.DESCRIPTION
  Convenience wrapper for the self-healing orchestrator.
  Detects port conflicts, auto-resolves, starts stack, monitors health.
.EXAMPLE
  .\scripts\start.ps1              # Start with self-healing
  .\scripts\start.ps1 -Check       # Health check only
  .\scripts\start.ps1 -Stop        # Stop stack
  .\scripts\start.ps1 -Restart     # Full restart
  .\scripts\start.ps1 -Status      # Show status
  .\scripts\start.ps1 -Monitor     # Continuous monitoring
#>

param(
    [switch]$Check,
    [switch]$Stop,
    [switch]$Restart,
    [switch]$Status,
    [switch]$Monitor
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectDir = Split-Path -Parent $ScriptDir

# Ensure we're in project directory
Set-Location $ProjectDir

# Find Python
$python = $null
foreach ($cmd in @("python3", "python", "py")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $python = $cmd
        break
    }
}

if (-not $python) {
    Write-Host "ERROR: Python not found. Install Python 3.10+ and try again." -ForegroundColor Red
    exit 1
}

# Build args
$args = @("scripts/selfheal.py")
if ($Check)   { $args += "--check" }
if ($Stop)    { $args += "--stop" }
if ($Restart) { $args += "--restart" }
if ($Status)  { $args += "--status" }
if ($Monitor) { $args += "--monitor" }

# Run
& $python @args
exit $LASTEXITCODE
