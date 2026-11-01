#!/usr/bin/env bash
# HELIOS on your Mac, in one command.
#
#   ./helios.sh                  Install what's missing, set everything up,
#                                build, start, and open HELIOS in the browser.
#   ./helios.sh --test-data      ...and load test clients, users and cases.
#   ./helios.sh --with-ollama    ...and a local AI model (Ollama) as HELIOS's
#                                default model, running natively on the Mac.
#
#   ./helios.sh start            Start again (no rebuild).
#   ./helios.sh stop             Stop (keeps every piece of data).
#   ./helios.sh status           What's running, and whether HELIOS answers.
#   ./helios.sh logs [service]   Follow the logs (web and worker by default).
#   ./helios.sh psql             Open the database (as the Postgres superuser).
#   ./helios.sh update           Pull the latest code, rebuild, restart.
#   ./helios.sh reset            Delete everything (data, secrets) and start over.
#   ./helios.sh help             This text.
#
# Safe to run again at any time: what's already done is left alone. Secrets
# are generated on the first run (.env.db, .env.docker, mode 600, never
# committed). Database migrations and reference data are applied on every
# start.
#
# Settings (environment variables, all optional):
#   HELIOS_PORT=3000             Port for HELIOS on this Mac (first run; the
#                                next free one is used if it's taken).
#   HELIOS_OLLAMA_MODEL=...      Model for --with-ollama (default by memory:
#                                qwen2.5:14b with 32 GB or more, else llama3.1:8b).
#   HELIOS_EXTRA_CA=~/ca.pem     Your company proxy's CA certificate, if it
#                                inspects TLS (Zscaler, Netskope...).
#   HELIOS_NODE_IMAGE=...        Build base image (default node:22-bookworm).
#   HELIOS_BUILD_FLAGS="..."     Extra flags for docker build.
#   HELIOS_NO_OPEN=1             Don't open the browser.
#   HELIOS_YES=1                 Don't ask before installing anything.

set -euo pipefail

cd "$(dirname "$0")"
ROOT=$(pwd)
STATE_DIR="$ROOT/.helios"
OS=$(uname -s)

# ---------------------------------------------------------------- output

if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; D=$'\033[2m'; N=$'\033[0m'
else
  B=""; G=""; Y=""; R=""; D=""; N=""
fi
step() { printf '\n%s==>%s %s%s%s\n' "$G" "$N" "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%s    ! %s%s\n' "$Y" "$*" "$N"; }
die() { printf '\n%s✗ %s%s\n' "$R" "$*" "$N" >&2; exit 1; }

confirm() {
  [ "${HELIOS_YES:-}" = "1" ] && return 0
  [ -t 0 ] || return 0
  local answer
  read -r -p "    $1 [Y/n] " answer
  case "$answer" in [nN]*) return 1 ;; *) return 0 ;; esac
}

# ---------------------------------------------------------------- helpers

port_in_use() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

free_port() {
  local p=$1 last=$(($1 + 100))
  while port_in_use "$p"; do
    p=$((p + 1))
    [ "$p" -le "$last" ] || die "No free port between $1 and $last; set HELIOS_PORT to one that is."
  done
  echo "$p"
}

need_setup() { [ -f .env.docker ] && [ -f .env.db ] || die "HELIOS isn't set up on this machine yet: run ./helios.sh"; }

env_value() { # file key
  [ -f "$1" ] || return 0
  grep -E "^$2=" "$1" | tail -n 1 | cut -d= -f2-
}

set_env_value() { # file key value: replaces or appends, keeps mode 600
  local file=$1 key=$2 value=$3 tmp
  tmp=$(mktemp "$file.XXXXXX")
  if grep -qE "^$key=" "$file"; then
    awk -v k="$key" -v v="$value" 'BEGIN { FS = OFS = "=" } $1 == k { print k "=" v; next } { print }' "$file" > "$tmp"
  else
    cat "$file" > "$tmp"
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  chmod 600 "$tmp"
  mv "$tmp" "$file"
}

helios_port() {
  local url
  url=$(env_value .env.docker AUTH_URL)
  url=${url##*:}
  echo "${url%%/*}"
}

compose() { HELIOS_PORT="$(helios_port)" docker compose "$@"; }

web_running() { [ -n "$(compose ps --status running -q web 2>/dev/null)" ]; }

# ---------------------------------------------------------------- Docker

need_homebrew() {
  command -v brew >/dev/null 2>&1 && return 0
  die "Homebrew isn't installed, and it's how this script installs $1.
    Install Homebrew first (https://brew.sh), or install $1 yourself, then run ./helios.sh again."
}

# Docker Desktop and Homebrew put their commands in places a fresh shell may
# not have on PATH yet (right after installing, say).
for dir in /opt/homebrew/bin /usr/local/bin "$HOME/.docker/bin" /Applications/Docker.app/Contents/Resources/bin; do
  case ":$PATH:" in *":$dir:"*) ;; *) [ -d "$dir" ] && PATH="$PATH:$dir" ;; esac
done
export PATH

ensure_docker() {
  step "Docker"
  if ! command -v docker >/dev/null 2>&1; then
    [ "$OS" = "Darwin" ] || die "Docker isn't installed. Install Docker Engine with the compose plugin, then run ./helios.sh again."
    need_homebrew "Docker Desktop"
    confirm "Docker Desktop isn't installed. Install it with Homebrew now?" || die "HELIOS runs in Docker; install Docker Desktop (https://www.docker.com/products/docker-desktop/) and run ./helios.sh again."
    brew install --cask docker
    PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"
  fi

  if ! docker info >/dev/null 2>&1; then
    if [ "$OS" = "Darwin" ]; then
      info "Starting Docker Desktop (the first time, accept its terms in the window that opens)..."
      open -g -a Docker 2>/dev/null || open -a Docker
    else
      die "The Docker daemon isn't running. Start it (sudo systemctl start docker) and run ./helios.sh again."
    fi
    local waited=0
    printf '    '
    until docker info >/dev/null 2>&1; do
      sleep 3
      waited=$((waited + 3))
      printf '.'
      [ "$waited" -ge 300 ] && { echo; die "Docker didn't start within 5 minutes. Open Docker Desktop, wait until it says it's running, then run ./helios.sh again."; }
    done
    echo
  fi

  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is missing. Update Docker Desktop, then run ./helios.sh again."
  info "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) is running."

  local mem
  mem=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
  if [ "${mem:-0}" -lt 5800000000 ] 2>/dev/null; then
    warn "Docker has $((mem / 1024 / 1024 / 1024)) GB of memory; HELIOS needs about 6 GB to build."
    warn "Docker Desktop → Settings → Resources → Memory: 6 GB or more, then Apply & restart."
  fi
  local free_kb
  free_kb=$(df -Pk "$ROOT" | awk 'NR == 2 { print $4 }')
  if [ "${free_kb:-0}" -lt 15000000 ] 2>/dev/null; then
    warn "Less than 15 GB free on this disk; the build may run out of space."
  fi
}

# ---------------------------------------------------------------- secrets

ensure_secrets() {
  step "Settings and secrets"
  if [ -f .env.db ] && [ -f .env.docker ]; then
    info "Using the existing .env.db and .env.docker."
  elif [ -f .env.db ] || [ -f .env.docker ]; then
    die "Only one of .env.db and .env.docker exists. Restore the other, or start over with ./helios.sh reset."
  else
    command -v openssl >/dev/null 2>&1 || die "openssl is missing (macOS includes it; on Linux install it)."
    # Fresh secrets can't open a database made with the old ones.
    if [ -n "$(docker volume ls -q --filter name='^helios_postgres-data$' 2>/dev/null)" ]; then
      die "A HELIOS database from an earlier setup is still here, but its secrets (.env.db, .env.docker) are gone.
    Restore those two files, or delete the old database with ./helios.sh reset."
    fi
    local port
    port=$(free_port "${HELIOS_PORT:-3000}")
    [ "$port" = "${HELIOS_PORT:-3000}" ] || info "Port ${HELIOS_PORT:-3000} is taken; using $port."
    HELIOS_PORT=$port ./deploy/compose/setup.sh > /dev/null
    info "Generated fresh secrets in .env.db and .env.docker (mode 600, not committed)."
  fi

  # The port HELIOS answers on: if something else took it, move to a free one.
  local port
  port=$(helios_port)
  if port_in_use "$port" && ! web_running; then
    local next
    next=$(free_port "$port")
    warn "Port $port is used by another program; HELIOS moves to $next."
    set_env_value .env.docker AUTH_URL "http://localhost:$next"
  fi
}

# ---------------------------------------------------------------- local AI

ensure_ollama() {
  step "Local AI model (Ollama)"
  [ "$OS" = "Darwin" ] || warn "On Linux, consider the ollama container instead: docker compose --profile local-ai up -d"
  if ! command -v ollama >/dev/null 2>&1 && [ ! -d /Applications/Ollama.app ]; then
    need_homebrew "Ollama"
    confirm "Ollama isn't installed. Install it with Homebrew now?" || { warn "Skipping the local model."; return 0; }
    brew install ollama
  fi

  if ! curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    info "Starting Ollama..."
    if [ -d /Applications/Ollama.app ]; then
      open -g -a Ollama
    elif command -v brew >/dev/null 2>&1 && brew list ollama >/dev/null 2>&1; then
      brew services start ollama >/dev/null
    else
      mkdir -p -m 700 "$STATE_DIR"
      nohup ollama serve > "$STATE_DIR/ollama.log" 2>&1 &
    fi
    local waited=0
    until curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; do
      sleep 2
      waited=$((waited + 2))
      [ "$waited" -ge 60 ] && die "Ollama didn't start. Start the Ollama app, then run ./helios.sh --with-ollama again."
    done
  fi

  local model=${HELIOS_OLLAMA_MODEL:-}
  if [ -z "$model" ]; then
    local bytes
    bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    if [ "$bytes" -ge 34000000000 ] 2>/dev/null; then model="qwen2.5:14b"; else model="llama3.1:8b"; fi
  fi
  if ! ollama list 2>/dev/null | awk 'NR > 1 { print $1 }' | grep -qx "$model"; then
    info "Downloading $model (several GB, once)..."
    ollama pull "$model"
  fi
  info "Ollama is serving $model."

  # The seed adds it to HELIOS as a local, platform-wide provider (once).
  set_env_value .env.db SEED_AI_BASE_URL "http://host.docker.internal:11434/v1"
  set_env_value .env.db SEED_AI_MODEL "$model"
  set_env_value .env.db SEED_AI_NAME "Ollama on this Mac"
}

# ---------------------------------------------------------------- build and run

build_images() {
  step "Building HELIOS (5–10 minutes the first time, then much faster)"
  local flags=() id
  id=$(git rev-parse --short HEAD 2>/dev/null || echo local)
  flags+=(--build-arg "NODE_IMAGE=${HELIOS_NODE_IMAGE:-node:22-bookworm}")
  if [ -n "${HELIOS_EXTRA_CA:-}" ]; then
    [ -f "$HELIOS_EXTRA_CA" ] || die "HELIOS_EXTRA_CA points to $HELIOS_EXTRA_CA, which doesn't exist."
    flags+=(--secret "id=extra_ca,src=$HELIOS_EXTRA_CA")
  fi
  # shellcheck disable=SC2206
  [ -n "${HELIOS_BUILD_FLAGS:-}" ] && flags+=(${HELIOS_BUILD_FLAGS})
  export DOCKER_BUILDKIT=1
  info "Web server and worker image..."
  docker build "${flags[@]}" --build-arg "HELIOS_DEPLOYMENT_ID=$id" --target runtime -t helios:local . \
    || die "The build failed (above). Behind a company proxy? Set HELIOS_EXTRA_CA to its CA certificate and try again."
  info "Migration image..."
  docker build "${flags[@]}" --target tools -t helios-tools:local . || die "The build failed (above)."
}

start_stack() {
  step "Starting HELIOS"
  info "Postgres, then migrations and reference data, then the web server and the worker..."
  if ! compose up -d --no-build; then
    echo
    compose logs --tail=60 migrate || true
    die "Starting failed. The migration log is above; ./helios.sh logs migrate shows all of it."
  fi
  local port waited=0
  port=$(helios_port)
  printf '    '
  until curl -fsS "http://localhost:$port/api/health" >/dev/null 2>&1; do
    sleep 3
    waited=$((waited + 3))
    printf '.'
    if [ "$waited" -ge 240 ]; then
      echo
      compose ps
      compose logs --tail=40 web || true
      die "HELIOS didn't answer on port $port within 4 minutes; the log is above."
    fi
  done
  echo
  info "HELIOS answers on http://localhost:$port"
}

load_test_data() {
  step "Test data"
  mkdir -p -m 700 "$STATE_DIR"
  if [ -f "$STATE_DIR/test-data" ]; then
    info "Already loaded (the accounts are in .helios/test-data)."
    return 0
  fi
  info "Loading test clients, users and cases (every page will show a test banner)..."
  compose run --rm -e HELIOS_ALLOW_TEST_SEED=1 --entrypoint /nodejs/bin/node migrate node_modules/tsx/dist/cli.mjs prisma/seed.ts --test > "$STATE_DIR/test-data.tmp" 2>&1 \
    || { cat "$STATE_DIR/test-data.tmp"; rm -f "$STATE_DIR/test-data.tmp"; die "Loading test data failed (above)."; }
  ( umask 077; mv "$STATE_DIR/test-data.tmp" "$STATE_DIR/test-data" )
  chmod 600 "$STATE_DIR/test-data"
  grep -iE "password|@" "$STATE_DIR/test-data" | sed 's/^/    /' | head -30
}

summary() {
  local port email password
  port=$(helios_port)
  email=$(env_value .env.db SEED_ADMIN_EMAIL)
  password=$(env_value .env.db SEED_ADMIN_PASSWORD)
  printf '\n%s✓ HELIOS is running%s\n\n' "$G$B" "$N"
  printf '    Open      %shttp://localhost:%s%s\n' "$B" "$port" "$N"
  printf '    Sign in   %s  /  %s\n' "${email:-admin@helios.local}" "${password:-(see .env.db)}"
  printf '    %sThen change the password and set up two-step sign-in (Account).%s\n' "$D" "$N"
  [ -n "$(env_value .env.db SEED_AI_MODEL)" ] && printf '    AI model  %s via Ollama on this Mac (AI Agents → Providers)\n' "$(env_value .env.db SEED_AI_MODEL)"
  [ -f "$STATE_DIR/test-data" ] && printf '    Test data loaded; its accounts are in .helios/test-data\n'
  printf '\n    %sStop: ./helios.sh stop · Start: ./helios.sh start · Logs: ./helios.sh logs · Help: ./helios.sh help%s\n\n' "$D" "$N"
  if [ "${HELIOS_NO_OPEN:-}" != "1" ] && [ "$OS" = "Darwin" ]; then open "http://localhost:$port" || true; fi
}

# ---------------------------------------------------------------- commands

cmd_up() {
  local test_data=0 ollama=0
  for arg in "$@"; do
    case "$arg" in
      --test-data) test_data=1 ;;
      --with-ollama) ollama=1 ;;
      *) die "Unknown option $arg (see ./helios.sh help)" ;;
    esac
  done
  printf '%sHELIOS%s: setting up on this %s\n' "$B" "$N" "$([ "$OS" = "Darwin" ] && echo Mac || echo machine)"
  [ "$OS" = "Darwin" ] || warn "This script is written for macOS; carrying on with what works elsewhere."
  ensure_docker
  ensure_secrets
  [ "$ollama" = 1 ] && ensure_ollama
  build_images
  start_stack
  [ "$test_data" = 1 ] && load_test_data
  summary
}

cmd_start() {
  need_setup
  ensure_docker
  docker image inspect helios:local >/dev/null 2>&1 || build_images
  start_stack
  summary
}

cmd_stop() {
  need_setup
  docker info >/dev/null 2>&1 || { info "Docker isn't running, so neither is HELIOS."; return 0; }
  step "Stopping HELIOS (your data stays)"
  compose down
}

cmd_status() {
  need_setup
  docker info >/dev/null 2>&1 || die "Docker isn't running."
  compose ps
  local port
  port=$(helios_port)
  if curl -fsS "http://localhost:$port/api/health" >/dev/null 2>&1; then
    printf '\n%s✓ HELIOS answers on http://localhost:%s%s\n' "$G" "$port" "$N"
  else
    printf '\n%s✗ HELIOS doesn'"'"'t answer on port %s%s\n' "$R" "$port" "$N"
  fi
}

cmd_logs() {
  need_setup
  if [ $# -eq 0 ]; then compose logs -f --tail=200 web worker; else compose logs -f --tail=200 "$@"; fi
}

cmd_psql() {
  need_setup
  compose exec postgres psql -U postgres -d helios "$@"
}

cmd_update() {
  step "Getting the latest code"
  if git rev-parse --git-dir >/dev/null 2>&1; then
    [ -z "$(git status --porcelain --untracked-files=no)" ] || die "There are local changes to tracked files; commit or stash them first."
    git pull --ff-only
  else
    warn "Not a git checkout; rebuilding what's here."
  fi
  ensure_docker
  ensure_secrets
  build_images
  start_stack
  summary
}

cmd_reset() {
  printf '%sThis deletes HELIOS on this machine: the database, archived logs, secrets and test data.%s\n' "$R$B" "$N"
  if [ "${HELIOS_YES:-}" != "1" ]; then
    local answer
    read -r -p "    Type reset to go ahead: " answer
    [ "$answer" = "reset" ] || die "Nothing was deleted."
  fi
  if docker info >/dev/null 2>&1; then
    # By the compose project's label, so it works even if the secrets are gone.
    local ids
    ids=$(docker ps -aq --filter label=com.docker.compose.project=helios)
    [ -z "$ids" ] || docker rm -f $ids >/dev/null
    ids=$(docker volume ls -q --filter label=com.docker.compose.project=helios)
    [ -z "$ids" ] || docker volume rm $ids >/dev/null
    docker network ls -q --filter label=com.docker.compose.project=helios | while read -r n; do docker network rm "$n" >/dev/null 2>&1 || true; done
  fi
  rm -f .env.db .env.docker
  rm -rf "$STATE_DIR"
  info "Deleted. Run ./helios.sh to set it up again."
}

cmd_help() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

command=${1:-up}
case "$command" in
  up | install)
    if [ $# -gt 0 ]; then shift; fi
    cmd_up "$@" ;;
  --*) cmd_up "$@" ;;
  start) cmd_start ;;
  stop | down) cmd_stop ;;
  status | ps) cmd_status ;;
  logs) shift; cmd_logs "$@" ;;
  psql | db) shift; cmd_psql "$@" ;;
  update | upgrade) cmd_update ;;
  reset) cmd_reset ;;
  help | -h | --help) cmd_help ;;
  *) die "Unknown command $command (see ./helios.sh help)" ;;
esac
