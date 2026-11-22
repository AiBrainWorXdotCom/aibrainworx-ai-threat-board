#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REBUILD=0
PASS_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --rebuild)
      REBUILD=1
      ;;
    *)
      PASS_ARGS+=("$arg")
      ;;
  esac
done

if [ "$REBUILD" -eq 1 ] || [ ! -x "$SCRIPT_DIR/backend/target/release/aibrainworx-threat-board" ]; then
  for cmd in node npm cargo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: '$cmd' is required to build from source but not installed." >&2
      echo "See README.md for build setup or download a prebuilt release binary." >&2
      exit 1
    fi
  done

  echo "Building React + Meta Astryx UI production bundle..."
  (
    cd "$SCRIPT_DIR/frontend"
    if [ ! -d node_modules ]; then
      npm ci || npm install
    fi
    npm run build
  )

  echo "Building single-file Rust release binary (embedding frontend assets)..."
  (
    cd "$SCRIPT_DIR/backend"
    cargo build --release
  )
fi

ACTIVE_BIND="${BIND_ADDR:-127.0.0.1}"
ACTIVE_PORT="${PORT:-8080}"
echo "Starting AiBrainWorX CyberSecurity Threat Analysis Board v0.2.0 at http://${ACTIVE_BIND}:${ACTIVE_PORT}"
exec "$SCRIPT_DIR/backend/target/release/aibrainworx-threat-board" "${PASS_ARGS[@]}"
