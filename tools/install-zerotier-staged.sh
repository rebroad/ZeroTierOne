#!/usr/bin/env bash
set -euo pipefail

STAGE_DIR="${1:-/var/tmp/zerotier-remote-install}"
INSTALL_DIR="${INSTALL_DIR:-/usr/sbin}"
SERVICE_NAME="${SERVICE_NAME:-zerotier-one}"
STATE_DIR="${STATE_DIR:-/var/lib/zerotier-one}"

if [[ "${EUID}" -ne 0 ]]; then
	echo "error: run as root (e.g. sudo $0 ${STAGE_DIR})" >&2
	exit 1
fi

if [[ ! -d "${STAGE_DIR}" ]]; then
	echo "error: stage directory does not exist: ${STAGE_DIR}" >&2
	exit 1
fi

if [[ ! -f "${STAGE_DIR}/zerotier-one" ]]; then
	echo "error: missing staged binary: ${STAGE_DIR}/zerotier-one" >&2
	exit 1
fi

chmod 0755 "${STAGE_DIR}/zerotier-one"

if command -v file >/dev/null 2>&1; then
	remote_arch="$(uname -m)"
	bin_desc="$(file -b "${STAGE_DIR}/zerotier-one" || true)"
	case "${remote_arch}" in
		x86_64) expected="x86-64" ;;
		aarch64|arm64) expected="aarch64|ARM aarch64" ;;
		armv7*|armv6*|armhf|arm) expected="ARM" ;;
		*) expected="" ;;
	esac

	if [[ -n "${expected}" ]] && ! echo "${bin_desc}" | grep -Eq "${expected}"; then
		echo "error: staged binary appears incompatible with host architecture ${remote_arch}" >&2
		echo "       file reports: ${bin_desc}" >&2
		exit 1
	fi
fi

install -d -m 0755 "${INSTALL_DIR}"
install -m 0755 "${STAGE_DIR}/zerotier-one" "${INSTALL_DIR}/zerotier-one"
ln -sfn zerotier-one "${INSTALL_DIR}/zerotier-cli"
ln -sfn zerotier-one "${INSTALL_DIR}/zerotier-idtool"

install -d -m 0755 "${STATE_DIR}"
ln -sfn ../../../usr/sbin/zerotier-one "${STATE_DIR}/zerotier-one"
ln -sfn ../../../usr/sbin/zerotier-one "${STATE_DIR}/zerotier-cli"
ln -sfn ../../../usr/sbin/zerotier-one "${STATE_DIR}/zerotier-idtool"

if command -v systemctl >/dev/null 2>&1; then
	if systemctl list-unit-files --type=service --no-legend | awk '{print $1}' | grep -qx "${SERVICE_NAME}.service"; then
		systemctl daemon-reload || true
		systemctl restart "${SERVICE_NAME}"
		systemctl --no-pager --full status "${SERVICE_NAME}" -n 0 || true
	else
		echo "warning: ${SERVICE_NAME}.service not found; skipped restart" >&2
	fi
else
	echo "warning: systemctl not available; restart service manually" >&2
fi

echo "Installed version: $("${INSTALL_DIR}/zerotier-one" -v 2>/dev/null | head -n1 || true)"
