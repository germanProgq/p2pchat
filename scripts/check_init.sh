#!/bin/sh
# Phase 0 spec alignment check for app.txt launch constraint.
set -eu

if [ ! -f "app.txt" ]; then
  echo "app.txt missing" >&2
  exit 1
fi

if ! grep -q "Launch constraint" "app.txt"; then
  echo "Launch constraint line not found in app.txt" >&2
  exit 1
fi

if ! grep -q "paid instances" "app.txt"; then
  echo "Launch constraint content missing paid instances requirement" >&2
  exit 1
fi

exit 0
