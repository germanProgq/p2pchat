#!/usr/bin/env bash
# Launch directory container and Tauri desktop app.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required" >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin)
    LIB_EXT="dylib"
    ;;
  Linux)
    LIB_EXT="so"
    ;;
  *)
    echo "unsupported OS for this script" >&2
    exit 1
    ;;
esac

LIB_PATH="$ROOT/build/libp2pchat_ffi.${LIB_EXT}"

cd "$ROOT"

docker compose -f "$ROOT/docker-compose.yml" up -d --build

cmake -S "$ROOT" -B "$ROOT/build"
cmake --build "$ROOT/build"

cd "$ROOT/desktop/tauri/src-tauri"
PATH="$HOME/.cargo/bin:$PATH" P2PCHAT_FFI_PATH="$LIB_PATH" cargo tauri dev
