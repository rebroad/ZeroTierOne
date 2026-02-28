#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/build/windows-x64}"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
STAGE_DIR="$OUT_DIR/bin"
INSTALLER_PATH="${2:-$OUT_DIR/ZeroTier-One-Cross-x64-Installer.exe}"
NSI="$ROOT_DIR/tools/windows-cross/zerotier-one-cross.nsi"

if ! command -v makensis >/dev/null 2>&1; then
  echo "Missing tool: makensis" >&2
  exit 1
fi

for req in zerotier-one_x64.exe zerotier-cli.bat zerotier-idtool.bat zttap300.inf zttap300.sys zttap300.cat; do
  if [ ! -f "$STAGE_DIR/$req" ]; then
    echo "Missing staged file: $STAGE_DIR/$req" >&2
    echo "Run tools/windows-cross/build-x64.sh first." >&2
    exit 1
  fi
done

mkdir -p "$(dirname "$INSTALLER_PATH")"
makensis \
  -D"STAGE_DIR=$STAGE_DIR" \
  -D"OUTPUT_FILE=$INSTALLER_PATH" \
  "$NSI"

echo "Built installer: $INSTALLER_PATH"
