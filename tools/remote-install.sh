#!/usr/bin/env bash
set -euo pipefail

host="${1:?usage: remote-install.sh user@host [binary] [stage-dir]}"
binary="${2:-./zerotier-one}"
stage_dir="${REMOTE_STAGE_DIR:-${3:-/var/tmp/zerotier-remote-install}}"
script_dir="$(cd "$(dirname "$0")" && pwd)"
installer="${script_dir}/install-zerotier-staged.sh"
read -r -a ssh_cmd <<<"${REMOTE_SSH:-ssh}"
read -r -a scp_cmd <<<"${REMOTE_SCP:-scp}"
read -r -a remote_sudo <<<"${REMOTE_SUDO:-sudo}"
geoip_db=""

[[ -x "${binary}" ]] || { echo "error: executable not found: ${binary}" >&2; exit 1; }
[[ "${stage_dir}" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "error: stage directory must be an absolute path without whitespace or shell metacharacters" >&2; exit 2; }
command -v objdump >/dev/null 2>&1 || { echo "error: objdump is required for ABI checks" >&2; exit 1; }
command -v file >/dev/null 2>&1 || { echo "error: file is required for architecture checks" >&2; exit 1; }
required_glibc="$(objdump -T "${binary}" | sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' | sort -V | tail -n1)"
bin_desc="$(file -b "${binary}")"
for candidate in \
	/var/lib/geoip/GeoLite2-Country.mmdb \
	/usr/share/GeoIP/GeoLite2-Country.mmdb \
	/var/lib/geoip/GeoLite2-City.mmdb \
	/usr/share/GeoIP/GeoLite2-City.mmdb; do
	if [[ -r "${candidate}" && ( -z "${geoip_db}" || "${candidate}" -nt "${geoip_db}" ) ]]; then
		geoip_db="${candidate}"
	fi
done
remote_info="$("${ssh_cmd[@]}" -o BatchMode=yes -o ConnectTimeout=10 "${host}" 'set -e; printf "REMOTE_ARCH=%s\n" "$(uname -m)"; ldd --version 2>&1 | head -n1 | sed -n "s/.* \([0-9][0-9.]*\)$/REMOTE_GLIBC=\1/p"; if ldconfig -p 2>/dev/null | grep -q libmaxminddb; then echo REMOTE_HAS_MAXMINDDB=1; else echo REMOTE_HAS_MAXMINDDB=0; fi; for db in /var/lib/geoip/GeoLite2-Country.mmdb /var/lib/geoip/GeoLite2-City.mmdb /usr/share/GeoIP/GeoLite2-Country.mmdb /usr/share/GeoIP/GeoLite2-City.mmdb; do if [ -r "$db" ]; then echo REMOTE_HAS_GEOIP=1; exit 0; fi; done; echo REMOTE_HAS_GEOIP=0')"
printf '%s\n' "${remote_info}"
remote_arch="$(sed -n 's/^REMOTE_ARCH=//p' <<<"${remote_info}" | head -n1)"
remote_glibc="$(sed -n 's/^REMOTE_GLIBC=//p' <<<"${remote_info}" | head -n1)"
remote_has_maxmind="$(sed -n 's/^REMOTE_HAS_MAXMINDDB=//p' <<<"${remote_info}" | head -n1)"
remote_has_geoip="$(sed -n 's/^REMOTE_HAS_GEOIP=//p' <<<"${remote_info}" | head -n1)"
[[ -n "${remote_arch}" ]] || { echo "error: unable to determine remote architecture" >&2; exit 1; }
case "${remote_arch}:${bin_desc}" in
	x86_64:*x86-64*|amd64:*x86-64*|aarch64:*aarch64*|arm64:*aarch64*|armv7*:*ARM*|armv6*:*ARM*|armhf:*ARM*|arm:*ARM*) ;;
	*) echo "error: binary architecture does not match remote ${remote_arch}: ${bin_desc}" >&2; exit 1 ;;
esac
if objdump -p "${binary}" | grep -q 'NEEDED.*libmaxminddb' && [[ "${remote_has_maxmind}" != "1" ]]; then
	echo "error: binary links libmaxminddb but ${host} does not have the runtime library" >&2
	echo "       install the target distribution's libmaxminddb runtime package first" >&2
	exit 1
fi
if [[ -n "${required_glibc}" && -n "${remote_glibc}" ]]; then
	lowest="$(printf '%s\n%s\n' "${required_glibc}" "${remote_glibc}" | sort -V | head -n1)"
	[[ "${lowest}" == "${required_glibc}" ]] || { echo "error: binary requires glibc ${required_glibc}, remote has ${remote_glibc}" >&2; exit 1; }
fi

printf -v remote_stage_q '%q' "${stage_dir}"
"${ssh_cmd[@]}" -o BatchMode=yes -o ConnectTimeout=10 "${host}" "mkdir -p -- ${remote_stage_q}"
if [[ "${remote_has_geoip}" != "1" && -n "${geoip_db}" ]]; then
	"${scp_cmd[@]}" -q "${binary}" "${installer}" "${geoip_db}" "${host}:${stage_dir}/"
	geoip_arg=" $(basename "${geoip_db}")"
else
	"${scp_cmd[@]}" -q "${binary}" "${installer}" "${host}:${stage_dir}/"
	geoip_arg=""
fi
"${ssh_cmd[@]}" -o BatchMode=yes -o ConnectTimeout=10 "${host}" "chmod 0755 ${remote_stage_q}/install-zerotier-staged.sh ${remote_stage_q}/zerotier-one"
printf -v remote_sudo_q '%q ' "${remote_sudo[@]}"
"${ssh_cmd[@]}" -t -o BatchMode=yes -o ConnectTimeout=10 "${host}" "${remote_sudo_q}${remote_stage_q}/install-zerotier-staged.sh ${remote_stage_q}${geoip_arg}"
echo "Remote install completed on ${host}"
