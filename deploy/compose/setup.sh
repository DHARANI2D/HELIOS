#!/bin/sh
# Writes .env.db and .env.docker for docker-compose.yml with fresh random
# secrets. Run once from the repository root; it won't overwrite existing
# files (delete them first to start over, which also needs a fresh database
# volume: docker compose down -v).
set -eu
cd "$(dirname "$0")/../.."
rand() { openssl rand -base64 "$1" | tr -d '\n'; }
pw() { openssl rand -hex 24; }

if [ -e .env.db ] || [ -e .env.docker ]; then
  echo ".env.db or .env.docker already exists; leaving them alone." >&2
  exit 1
fi
umask 077

POSTGRES_PASSWORD=$(pw)
OWNER=$(pw)
APP=$(pw)
ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '\n/+=' | cut -c1-20)
PORT=${HELIOS_PORT:-3000}

cat > .env.db <<ENV
# Database secrets: the Postgres container and the migrate job only.
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
HELIOS_OWNER_PASSWORD=$OWNER
HELIOS_APP_PASSWORD=$APP
# The migrate job signs in as the schema owner.
DATABASE_URL=postgresql://helios_owner:$OWNER@postgres:5432/helios?schema=public
# The first platform admin, created by the seed.
SEED_ADMIN_EMAIL=admin@helios.local
SEED_ADMIN_PASSWORD=$ADMIN_PASSWORD
ENV

cat > .env.docker <<ENV
# HELIOS web and worker. Signs in to the database as helios_app, which can
# read and write rows but not change the schema or bypass row-level security.
DATABASE_URL=postgresql://helios_app:$APP@postgres:5432/helios?schema=public
AUTH_URL=http://localhost:$PORT
AUTH_SECRET=$(rand 32)
HELIOS_ENCRYPTION_KEY=$(rand 32)

# AI (optional): Claude through Anthropic's API. Providers, including local
# models (Ollama on this Mac: http://host.docker.internal:11434/v1), can be
# set in the app under AI Agents instead. See docs/deployment.md.
ANTHROPIC_API_KEY=
ENV

echo "Wrote .env.db and .env.docker."
echo "First admin: admin@helios.local / $ADMIN_PASSWORD  (change it after signing in)"
