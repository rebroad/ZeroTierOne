#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${1:-pi3}"
REMOTE_STAGE_DIR="${2:-/var/tmp/zerotier-remote-install}"
REMOTE_INSTALL_SCRIPT="install-zerotier-staged.sh"
REMOTE_SUDO="${REMOTE_SUDO:-sudo}"

CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-auto}"
DOCKER_PI_BUILD_IMAGE="${DOCKER_PI_BUILD_IMAGE:-zerotier-build-pi3}"
DOCKER_PI_DOCKERFILE="${DOCKER_PI_DOCKERFILE:-$ROOT_DIR/tools/Dockerfile.pi3-builder}"
DOCKER_PI_BASE_IMAGE="${DOCKER_PI_BASE_IMAGE:-arm32v7/debian:buster}"
DOCKER_BUILD_NETWORK="${DOCKER_BUILD_NETWORK:-host}"
DOCKER_CARGO_HOME="${DOCKER_CARGO_HOME:-/src/.cache/cargo-pi3}"
PI_BUILD_DIR="${PI_BUILD_DIR:-build/pi-armv7}"
PI_BUILD_WORK_DIR="${PI_BUILD_WORK_DIR:-$PI_BUILD_DIR/work}"
PI_BUILD_BIN="$ROOT_DIR/$PI_BUILD_DIR/zerotier-one"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

choose_runtime() {
  if [ "$CONTAINER_RUNTIME" != "auto" ]; then
    echo "$CONTAINER_RUNTIME"
    return 0
  fi
  if command -v docker >/dev/null 2>&1; then
    echo docker
    return 0
  fi
  if command -v podman >/dev/null 2>&1; then
    echo podman
    return 0
  fi
  return 1
}

runtime="$(choose_runtime)" || {
  echo "error: no container runtime found (docker/podman)." >&2
  exit 1
}

ensure_binfmt_if_needed() {
  local rt="$1"
  local base_image="$2"

  if "$rt" run --rm --platform linux/arm/v7 "$base_image" true >/dev/null 2>&1; then
    return 0
  fi

  if [ "$rt" = "docker" ] && command -v sudo >/dev/null 2>&1; then
    echo "Enabling ARM binfmt handlers for docker..."
    sudo docker run --privileged --rm tonistiigi/binfmt --install arm >/dev/null
    "$rt" run --rm --platform linux/arm/v7 "$base_image" true >/dev/null
    return 0
  fi

  echo "error: $rt cannot run linux/arm/v7 image: $base_image" >&2
  echo "hint: install qemu/binfmt support (or use docker with sudo)." >&2
  exit 1
}

if [ ! -f "$DOCKER_PI_DOCKERFILE" ]; then
  echo "error: missing Dockerfile: $DOCKER_PI_DOCKERFILE" >&2
  exit 1
fi

ensure_binfmt_if_needed "$runtime" "$DOCKER_PI_BASE_IMAGE"

echo "Building Pi builder image: $DOCKER_PI_BUILD_IMAGE"
"$runtime" build \
  --platform linux/arm/v7 \
  --network="$DOCKER_BUILD_NETWORK" \
  --build-arg BASE_IMAGE="$DOCKER_PI_BASE_IMAGE" \
  -f "$DOCKER_PI_DOCKERFILE" \
  -t "$DOCKER_PI_BUILD_IMAGE" \
  "$ROOT_DIR"

echo "Building zerotier-one for ARMv7 in container"
"$runtime" run --rm \
  --platform linux/arm/v7 \
  --network="$DOCKER_BUILD_NETWORK" \
  --user "$(id -u):$(id -g)" \
  -v "$ROOT_DIR:/src" \
  -w /src \
  -e CARGO_HOME="$DOCKER_CARGO_HOME" \
  -e CARGO_HTTP_TIMEOUT=120 \
  -e CARGO_NET_RETRY=10 \
  -e CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
  "$DOCKER_PI_BUILD_IMAGE" \
  bash -lc "set -euo pipefail; mkdir -p \"\$CARGO_HOME\"; rm -rf \"$PI_BUILD_WORK_DIR\"; mkdir -p \"$PI_BUILD_WORK_DIR\" \"$PI_BUILD_DIR\"; tar -C /src --exclude='./build' -cf - . | tar -C \"$PI_BUILD_WORK_DIR\" -xf -; cd \"$PI_BUILD_WORK_DIR\"; make one; cp -f zerotier-one \"/src/$PI_BUILD_DIR/zerotier-one\""

if [ ! -x "$PI_BUILD_BIN" ]; then
  echo "error: build did not produce executable: $PI_BUILD_BIN" >&2
  exit 1
fi

bin_desc="$(file -b "$PI_BUILD_BIN" || true)"
if ! echo "$bin_desc" | grep -Eq 'ARM'; then
  echo "error: built binary does not look like ARM: $bin_desc" >&2
  exit 1
fi

local_mmdb=""
local_mmdb_mtime=0
for candidate in \
  /var/lib/geoip/GeoLite2-Country.mmdb \
  /usr/share/GeoIP/GeoLite2-Country.mmdb \
  /var/lib/geoip/GeoLite2-City.mmdb \
  /usr/share/GeoIP/GeoLite2-City.mmdb; do
  if [ -r "$candidate" ]; then
    candidate_mtime="$(stat -c %Y "$candidate" 2>/dev/null || echo 0)"
    if [ "$candidate_mtime" -gt "$local_mmdb_mtime" ]; then
      local_mmdb="$candidate"
      local_mmdb_mtime="$candidate_mtime"
    fi
  fi
done

if ! command -v objdump >/dev/null 2>&1; then
  echo "error: objdump is required for pi-install preflight checks" >&2
  exit 1
fi

required_glibc="$(objdump -T "$PI_BUILD_BIN" 2>/dev/null | sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -V | tail -n1)"

remote_info="$(
  ssh "${SSH_OPTS[@]}" "$HOST" '
    set -e
    echo REMOTE_ARCH="$(uname -m)"
    if command -v ldd >/dev/null 2>&1; then
      ldd --version 2>&1 | head -n1 | sed -n "s/.* \([0-9][0-9.]*\)$/REMOTE_GLIBC=\1/p"
    fi
    usable_geoip=0
    for candidate in \
      /var/lib/geoip/GeoLite2-Country.mmdb \
      /var/lib/geoip/GeoLite2-City.mmdb \
      /usr/share/GeoIP/GeoLite2-Country.mmdb \
      /usr/share/GeoIP/GeoLite2-City.mmdb; do
      if [ -r "$candidate" ]; then
        usable_geoip=1
        break
      fi
    done
    echo REMOTE_HAS_GEOIP="$usable_geoip"
  '
)"
echo "$remote_info"

remote_arch="$(echo "$remote_info" | sed -n 's/^REMOTE_ARCH=//p' | head -n1)"
remote_glibc="$(echo "$remote_info" | sed -n 's/^REMOTE_GLIBC=//p' | head -n1)"
remote_has_geoip="$(echo "$remote_info" | sed -n 's/^REMOTE_HAS_GEOIP=//p' | head -n1)"

if [ -z "$remote_arch" ]; then
  echo "error: unable to determine remote architecture on $HOST" >&2
  exit 1
fi

case "$remote_arch" in
  armv7*|armv6*|armhf|arm) ;;
  *)
    echo "error: remote host architecture is not armv7-compatible: $remote_arch" >&2
    exit 1
    ;;
esac

if [ -n "$required_glibc" ] && [ -n "$remote_glibc" ]; then
  lowest="$(printf '%s\n%s\n' "$required_glibc" "$remote_glibc" | sort -V | head -n1)"
  if [ "$lowest" != "$required_glibc" ]; then
    echo "error: zerotier-one requires glibc >= $required_glibc but remote has $remote_glibc" >&2
    exit 1
  fi
fi

stage_geoip_src=""
if [ "${remote_has_geoip:-0}" = "1" ]; then
  echo "Remote GeoIP DB: usable GeoLite2 database already present"
elif [ -n "$local_mmdb" ]; then
  stage_geoip_src="$local_mmdb"
  echo "Remote GeoIP DB: missing; will stage local $stage_geoip_src"
else
  echo "Remote GeoIP DB: missing and no local GeoLite2 DB available to stage"
fi

echo "Staging files on $HOST:$REMOTE_STAGE_DIR"
ssh "${SSH_OPTS[@]}" "$HOST" "mkdir -p '$REMOTE_STAGE_DIR'"
if [ -n "$stage_geoip_src" ]; then
  scp "${SSH_OPTS[@]}" -q \
    "$PI_BUILD_BIN" \
    "$ROOT_DIR/tools/$REMOTE_INSTALL_SCRIPT" \
    "$stage_geoip_src" \
    "$HOST:$REMOTE_STAGE_DIR/"
else
  scp "${SSH_OPTS[@]}" -q \
    "$PI_BUILD_BIN" \
    "$ROOT_DIR/tools/$REMOTE_INSTALL_SCRIPT" \
    "$HOST:$REMOTE_STAGE_DIR/"
fi

ssh "${SSH_OPTS[@]}" "$HOST" "chmod 0755 '$REMOTE_STAGE_DIR/$REMOTE_INSTALL_SCRIPT' '$REMOTE_STAGE_DIR/zerotier-one'"
install_args="$REMOTE_STAGE_DIR"
if [ -n "$stage_geoip_src" ]; then
  install_args="$install_args $(basename "$stage_geoip_src")"
fi

echo "Running installer via $REMOTE_SUDO on $HOST"
ssh -t "${SSH_OPTS[@]}" "$HOST" "$REMOTE_SUDO '$REMOTE_STAGE_DIR/$REMOTE_INSTALL_SCRIPT' $install_args"

echo "Pi install completed on $HOST"
