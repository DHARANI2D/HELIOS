#!/bin/sh
# Runs once, when the Postgres container first creates its data directory:
# makes the owner and app roles (deploy/db/roles.sql).
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_password="$HELIOS_OWNER_PASSWORD" \
  -v app_password="$HELIOS_APP_PASSWORD" \
  -v db="$POSTGRES_DB" \
  -f /helios-db/roles.sql
