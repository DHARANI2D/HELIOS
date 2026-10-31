#!/busybox/sh
# The tools image's entrypoint (Dockerfile): migrations as the schema owner,
# then what the app role may do (grants.sql), then the seed, which adds
# reference data and the first admin and is safe to run again.
# DATABASE_URL must be the owner's (helios_owner).
set -eu
cd /app
node=/nodejs/bin/node
prisma() { "$node" node_modules/prisma/build/index.js "$@"; }

prisma migrate deploy
prisma db execute --file deploy/db/grants.sql --schema prisma/schema.prisma
echo "Grants applied."
if [ "${HELIOS_SEED:-1}" = "1" ]; then
  "$node" node_modules/tsx/dist/cli.mjs prisma/seed.ts
fi
