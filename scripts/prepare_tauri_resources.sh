#!/usr/bin/env bash
# Build desktop web assets and stage the native FFI library for Tauri bundles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
RESOURCE_DIR="$ROOT/desktop/tauri/src-tauri/resources"

if ! command -v cmake >/dev/null 2>&1 && [ -x /opt/homebrew/opt/cmake/bin/cmake ]; then
  export PATH="/opt/homebrew/opt/cmake/bin:$PATH"
fi

case "$(uname -s)" in
  Darwin)
    LIB_NAME="libp2pchat_ffi.dylib"
    ;;
  Linux)
    LIB_NAME="libp2pchat_ffi.so"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    LIB_NAME="p2pchat_ffi.dll"
    ;;
  *)
    echo "unsupported OS for Tauri resource staging" >&2
    exit 1
    ;;
esac

cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"
cmake --build "$ROOT/build" --target p2pchat_ffi --config "$BUILD_TYPE"

mkdir -p "$RESOURCE_DIR"
cp "$ROOT/build/$LIB_NAME" "$RESOURCE_DIR/$LIB_NAME"

npm --prefix "$ROOT/desktop/tauri/ui" run build
