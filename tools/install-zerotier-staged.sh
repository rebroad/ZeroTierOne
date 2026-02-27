#!/usr/bin/env bash
set -euo pipefail

STAGE_DIR="${1:-/var/tmp/zerotier-remote-install}"
INSTALL_DIR="${INSTALL_DIR:-/usr/sbin}"
SERVICE_NAME="${SERVICE_NAME:-zerotier-one}"
STATE_DIR="${STATE_DIR:-/var/lib/zerotier-one}"
BACKUP_BIN="${BACKUP_BIN:-${INSTALL_DIR}/zerotier-one.prev}"
ROLLBACK_MARKER="${ROLLBACK_MARKER:-${STATE_DIR}/.rollback-on-reboot}"
ROLLBACK_DISABLE_FILE="${ROLLBACK_DISABLE_FILE:-${STATE_DIR}/.rollback-disabled}"
ROLLBACK_SCRIPT="${ROLLBACK_SCRIPT:-/usr/local/sbin/zerotier-rollback-on-boot.sh}"
ROLLBACK_SERVICE="${ROLLBACK_SERVICE:-zerotier-rollback-on-boot.service}"
ROLLBACK_LOG="${ROLLBACK_LOG:-/var/log/zerotier-rollback.log}"

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

have_backup=0
if [[ -x "${INSTALL_DIR}/zerotier-one" ]]; then
	cp -a "${INSTALL_DIR}/zerotier-one" "${BACKUP_BIN}"
	have_backup=1
fi

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
		rollback_armed=0
		if [[ "${have_backup}" -eq 1 ]]; then
			rollback_armed=1
			cat > "${ROLLBACK_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
MARKER="${ROLLBACK_MARKER}"
DISABLE="${ROLLBACK_DISABLE_FILE}"
BACKUP="${BACKUP_BIN}"
INSTALL_DIR="${INSTALL_DIR}"
STATE_DIR="${STATE_DIR}"
SERVICE_NAME="${SERVICE_NAME}"
LOG_FILE="${ROLLBACK_LOG}"

if [[ ! -f "\${MARKER}" ]]; then
	exit 0
fi

if [[ -f "\${DISABLE}" ]]; then
	rm -f "\${MARKER}" "\${DISABLE}"
	exit 0
fi

if [[ -x "\${BACKUP}" ]]; then
	cp -a "\${BACKUP}" "\${INSTALL_DIR}/zerotier-one"
	systemctl restart "\${SERVICE_NAME}" || true
	echo "Rollback applied at \$(date -Is)" >> "\${LOG_FILE}" 2>&1
fi

rm -f "\${MARKER}"
EOF
			chmod 0755 "${ROLLBACK_SCRIPT}"

			cat > "/etc/systemd/system/${ROLLBACK_SERVICE}" <<EOF
[Unit]
Description=Rollback ZeroTier binary on boot if marker is present
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${ROLLBACK_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF

			touch "${ROLLBACK_MARKER}"
			rm -f "${ROLLBACK_DISABLE_FILE}"
			systemctl daemon-reload || true
			systemctl enable "${ROLLBACK_SERVICE}" || true
			echo "Rollback is armed for next reboot."
			echo "If the new version is stable, disable rollback before reboot:"
			echo "  sudo rm -f ${ROLLBACK_MARKER}"
			echo "Optional persistent disable marker:"
			echo "  sudo touch ${ROLLBACK_DISABLE_FILE}"
		fi

		systemctl restart "${SERVICE_NAME}"
		systemctl --no-pager --full status "${SERVICE_NAME}" -n 0 || true

		if [[ "${rollback_armed}" -eq 1 ]]; then
			echo "Rollback-on-reboot remains armed until marker is removed."
		fi
	else
		echo "warning: ${SERVICE_NAME}.service not found; skipped restart" >&2
	fi
else
	echo "warning: systemctl not available; restart service manually" >&2
fi

echo "Installed version: $("${INSTALL_DIR}/zerotier-one" -v 2>/dev/null | head -n1 || true)"

if command -v ldd >/dev/null 2>&1; then
	if ldd "${INSTALL_DIR}/zerotier-one" 2>/dev/null | grep -q "libmaxminddb"; then
		echo "GeoIP runtime linkage: libmaxminddb detected"
	else
		echo "warning: GeoIP runtime linkage missing (libmaxminddb not found by ldd)" >&2
		echo "         install package 'libmaxminddb0' on target to enable country flags in stats" >&2
	fi
fi
