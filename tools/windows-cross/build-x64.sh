#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/build/windows-x64}"
OBJ_DIR="$OUT_DIR/obj"
SRC_LIST="$ROOT_DIR/tools/windows-cross/sources-x64.txt"

CXX="${CXX:-/usr/bin/x86_64-w64-mingw32-g++}"
CC="${CC:-/usr/bin/x86_64-w64-mingw32-gcc}"

for bin in "$CXX" "$CC"; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Missing compiler: $bin" >&2
    exit 1
  fi
done

mkdir -p "$OBJ_DIR"

COMMON_DEFS=(
  -DZT_EXPORT
  -DFD_SETSIZE=1024
  -DSTATICLIB
  -DWIN32
  -DNOMINMAX
  -DZT_BUILD_PLATFORM=2
  -DZT_BUILD_ARCHITECTURE=2
  -DZT_USE_MINIUPNPC
  -DMINIUPNP_STATICLIB
  -DZT_SOFTWARE_UPDATE_DEFAULT=\"disable\"
)

COMMON_INC=(
  -I"$ROOT_DIR"
  -I"$ROOT_DIR/ext"
  -I"$ROOT_DIR/ext/prometheus-cpp-lite-1.0/core/include"
  -I"$ROOT_DIR/ext/prometheus-cpp-lite-1.0/simpleapi/include"
  -I"$ROOT_DIR/ext/opentelemetry-cpp-api-only/include"
  -I"$ROOT_DIR/rustybits/target"
)

CXXFLAGS=(
  -std=gnu++17
  -O2
  -pipe
  -ffunction-sections
  -fdata-sections
  -Wall
  -Wno-unused-function
  -Wno-unused-parameter
  -Wno-sign-compare
  -include "$ROOT_DIR/node/Metrics.hpp"
  -fpermissive
)

CFLAGS=(
  -std=gnu11
  -O2
  -pipe
  -ffunction-sections
  -fdata-sections
  -Wall
  -Wno-unused-function
  -Wno-unused-parameter
  -Wno-sign-compare
)

OBJS=()
while IFS= read -r src; do
  [ -z "$src" ] && continue
  src_abs="$ROOT_DIR/$src"
  obj="$OBJ_DIR/${src//\//_}.o"

  if [ ! -f "$obj" ] || [ "$src_abs" -nt "$obj" ]; then
    mkdir -p "$(dirname "$obj")"
    case "$src" in
      *.c)
        "$CC" "${CFLAGS[@]}" "${COMMON_DEFS[@]}" "${COMMON_INC[@]}" -c "$src_abs" -o "$obj"
        ;;
      *.cpp)
        "$CXX" "${CXXFLAGS[@]}" "${COMMON_DEFS[@]}" "${COMMON_INC[@]}" -c "$src_abs" -o "$obj"
        ;;
      *)
        echo "Unsupported source extension: $src" >&2
        exit 1
        ;;
    esac
  fi

  OBJS+=("$obj")
done < "$SRC_LIST"

BIN_DIR="$OUT_DIR/bin"
mkdir -p "$BIN_DIR"

"$CXX" -o "$BIN_DIR/zerotier-one_x64.exe" "${OBJS[@]}" \
  -Wl,--gc-sections \
  -static -static-libgcc -static-libstdc++ \
  -lwbemuuid -luuid -loleaut32 -lshlwapi \
  -lwsock32 -lws2_32 -liphlpapi -lrpcrt4 \
  -lbcrypt -luserenv -lcrypt32 -lsecur32 -lncrypt \
  -lsetupapi -ladvapi32 -lshell32 -lole32 -lwinmm

cat > "$BIN_DIR/zerotier-cli.bat" <<'BAT'
@echo off
"%~dp0zerotier-one_x64.exe" -q %*
BAT

cat > "$BIN_DIR/zerotier-idtool.bat" <<'BAT'
@echo off
"%~dp0zerotier-one_x64.exe" -i %*
BAT

cp "$ROOT_DIR/ext/bin/tap-windows-ndis6/x64/zttap300.inf" "$BIN_DIR/"
cp "$ROOT_DIR/ext/bin/tap-windows-ndis6/x64/zttap300.sys" "$BIN_DIR/"
cp "$ROOT_DIR/ext/bin/tap-windows-ndis6/x64/zttap300.cat" "$BIN_DIR/"

echo "Built: $BIN_DIR/zerotier-one_x64.exe"
echo "Staged installer payload in: $BIN_DIR"
