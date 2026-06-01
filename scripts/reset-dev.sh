#!/usr/bin/env bash
# FreeSDN Development Reset Script
# Resets database to fresh state with demo data
#
# Usage (from freesdn/ root):
#   ./scripts/reset-dev.sh
#
# Or on Windows PowerShell:
#   .\scripts\reset-dev.ps1

set -e

# Resolve freesdn/ root (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FREESDN_ROOT="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "FreeSDN Development Environment Reset"
echo "============================================"

# Stop any running services
echo -e "\n[1/5] Stopping services..."
docker compose -f "$FREESDN_ROOT/docker-compose.yml" down 2>/dev/null || true

# Remove volumes for fresh start
echo -e "\n[2/5] Removing database volumes..."
docker volume rm freesdn_postgres_data 2>/dev/null || true
docker volume rm freesdn_redis_data 2>/dev/null || true

# Pull latest images
echo -e "\n[3/5] Pulling latest images..."
docker pull postgres:18.4-trixie
docker pull valkey/valkey:8.1.3-bookworm

# Start fresh containers
echo -e "\n[4/5] Starting fresh containers..."
docker compose -f "$FREESDN_ROOT/docker-compose.yml" up -d

# Wait for postgres to be ready
echo -e "\n[5/5] Waiting for PostgreSQL to be ready..."
until docker exec freesdn-postgres pg_isready -U freesdn > /dev/null 2>&1; do
    echo "  Waiting for PostgreSQL..."
    sleep 2
done
echo "  PostgreSQL is ready!"

echo -e "\n============================================"
echo "Infrastructure ready!"
echo ""
echo "Next steps:"
echo "  1. cd backend"
echo "  2. alembic upgrade head"
echo "  3. python -m scripts.seed_demo_data"
echo "  4. uvicorn app.main:app --reload --port 8000"
echo ""
echo "Default login:"
echo "  Email: admin@example.com"
echo "  Password: demo"
echo "============================================"
