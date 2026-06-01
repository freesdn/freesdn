# FreeSDN Development Reset Script (Windows PowerShell)
# Resets database to fresh state with demo data
#
# Usage (from anywhere):
#   .\scripts\reset-dev.ps1

# Resolve freesdn/ root (parent of scripts/)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$FreeSDNRoot = Split-Path -Parent $ScriptDir

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "FreeSDN Development Environment Reset" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# Stop any running services
Write-Host "`n[1/5] Stopping services..." -ForegroundColor Yellow
docker compose -f "$FreeSDNRoot/docker-compose.yml" down 2>$null

# Remove volumes for fresh start
Write-Host "`n[2/5] Removing database volumes..." -ForegroundColor Yellow
docker volume rm freesdn_postgres_data 2>$null
docker volume rm freesdn_redis_data 2>$null

# Pull latest images
Write-Host "`n[3/5] Pulling latest images..." -ForegroundColor Yellow
docker pull postgres:18.4-trixie
docker pull valkey/valkey:8.1.3-bookworm

# Start fresh containers
Write-Host "`n[4/5] Starting fresh containers..." -ForegroundColor Yellow
docker compose -f "$FreeSDNRoot/docker-compose.yml" up -d

# Wait for postgres to be ready
Write-Host "`n[5/5] Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
$ready = $false
$attempts = 0
while (-not $ready -and $attempts -lt 30) {
    $result = docker exec freesdn-postgres pg_isready -U freesdn 2>$null
    if ($LASTEXITCODE -eq 0) {
        $ready = $true
    } else {
        Write-Host "  Waiting for PostgreSQL..." -ForegroundColor Gray
        Start-Sleep -Seconds 2
        $attempts++
    }
}

if ($ready) {
    Write-Host "  PostgreSQL is ready!" -ForegroundColor Green
} else {
    Write-Host "  PostgreSQL did not start in time. Check docker logs." -ForegroundColor Red
    exit 1
}

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "Infrastructure ready!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. cd backend" -ForegroundColor Gray
Write-Host "  2. alembic upgrade head" -ForegroundColor Gray
Write-Host "  3. python -m scripts.seed_demo_data" -ForegroundColor Gray
Write-Host "  4. uvicorn app.main:app --reload --port 8000" -ForegroundColor Gray
Write-Host ""
Write-Host "Default login:" -ForegroundColor White
Write-Host "  Email: admin@example.com" -ForegroundColor Yellow
Write-Host "  Password: demo" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Cyan
