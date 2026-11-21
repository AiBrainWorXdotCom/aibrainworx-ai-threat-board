#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REBUILD=0
for arg in "$@"; do
  case "$arg" in
    --rebuild)
      REBUILD=1
      ;;
    -h|--help)
      echo "Usage: ./start.sh [--rebuild]"
      echo "  --rebuild   Force rebuild of both frontend and Rust backend before starting"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Usage: ./start.sh [--rebuild]" >&2
      exit 1
      ;;
  esac
done

for cmd in node npm cargo; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: '$cmd' is required but not installed or not in PATH." >&2
    echo "See README.md for macOS and Linux prerequisite setup." >&2
    exit 1
  fi
done

if [ "$REBUILD" -eq 1 ] || [ ! -f "$SCRIPT_DIR/frontend/dist/index.html" ]; then
  echo "Building React + Meta Astryx UI frontend..."
  (
    cd "$SCRIPT_DIR/frontend"
    if [ ! -d node_modules ]; then
      npm ci || npm install
    fi
    npm run build
  )
fi

if [ "$REBUILD" -eq 1 ] || [ ! -x "$SCRIPT_DIR/backend/target/release/aibrainworx-threat-board" ]; then
  echo "Building Rust backend (release profile)..."
  (
    cd "$SCRIPT_DIR/backend"
    cargo build --release
  )
fi

ACTIVE_PORT="${PORT:-8080}"
echo "Starting AiBrainWorX CyberSecurity Threat Analysis Board at http://127.0.0.1:${ACTIVE_PORT}"
exec "$SCRIPT_DIR/backend/target/release/aibrainworx-threat-board"
