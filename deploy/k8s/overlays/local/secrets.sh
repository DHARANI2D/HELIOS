#!/bin/sh
# Writes secrets.env (HELIOS) and db.env (the in-cluster Postgres) beside
# this script with fresh random values. Both are gitignored; keep them out
# of Git. Won't overwrite existing files.
set -eu
cd "$(dirname "$0")"
[ -e secrets.env ] || [ -e db.env ] && { echo "secrets.env or db.env exists; leaving them alone." >&2; exit 1; }
umask 077
pw() { openssl rand -hex 24; }
OWNER=$(pw); APP=$(pw)
ADMIN=$(openssl rand -base64 18 | tr -d '\n/+=' | cut -c1-20)
cat > db.env <<ENV
POSTGRES_PASSWORD=$(pw)
HELIOS_OWNER_PASSWORD=$OWNER
HELIOS_APP_PASSWORD=$APP
ENV
cat > secrets.env <<ENV
DATABASE_URL=postgresql://helios_app:$APP@postgres:5432/helios?schema=public
OWNER_DATABASE_URL=postgresql://helios_owner:$OWNER@postgres:5432/helios?schema=public
AUTH_SECRET=$(openssl rand -base64 32 | tr -d '\n')
HELIOS_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')
SEED_ADMIN_EMAIL=admin@helios.local
SEED_ADMIN_PASSWORD=$ADMIN
ANTHROPIC_API_KEY=
ENV
echo "Wrote secrets.env and db.env. First admin: admin@helios.local / $ADMIN"
