#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/build/windows-x64}"
INSTALLER_PATH="${2:-$OUT_DIR/ZeroTier-One-x64-Installer.exe}"

"$ROOT_DIR/tools/windows-cross/build-x64.sh" "$OUT_DIR"
"$ROOT_DIR/tools/windows-cross/package-installer.sh" "$OUT_DIR" "$INSTALLER_PATH"
