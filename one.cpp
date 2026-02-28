/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "node/ECC.hpp"
#endif

#include "node/Constants.hpp"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __WINDOWS__
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#include <lmcons.h>
#include <newdev.h>
#include <iphlpapi.h>
#include <io.h>
#include <sys/stat.h>
#include <iomanip>
#include <shlobj.h>
#include "osdep/WindowsEthernetTap.hpp"
#include "windows/ZeroTierOne/ServiceInstaller.h"
#include "windows/ZeroTierOne/ServiceBase.h"
#include "windows/ZeroTierOne/ZeroTierOneService.h"
// clang-format on
#else
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#ifdef __LINUX__
#include "osdep/ExtOsdep.hpp"

#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#ifndef ZT_NO_CAPABILITIES
#include <linux/capability.h>
#include <linux/securebits.h>
#endif
#endif
#endif

#include "include/ZeroTierOne.h"
#include "node/Bond.hpp"
#include "node/Buffer.hpp"
#include "node/CertificateOfMembership.hpp"
#include "node/Identity.hpp"
#include "node/NetworkController.hpp"
#include "node/Utils.hpp"
#include "node/World.hpp"
#include "osdep/Http.hpp"
#include "osdep/OSUtils.hpp"
#include "osdep/Thread.hpp"
#include "service/OneService.hpp"
#include "version.h"

#include <algorithm>
#include <atomic>	// TODO needed?
#include <cctype>	// TODO needed?
#include <chrono>	// TODO needed?
#include <cmath>	// TODO needed?
#include <deque>	// TODO needed?
#include <fstream>
#include <iostream>
#include <limits>	// TODO needed?
#include <map>
#include <mutex>   // TODO needed?
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>	// TODO needed?
#include <vector>	// TODO needed?

#if defined(__has_include)
#if __has_include(<maxminddb.h>)
#include <maxminddb.h>
#define ZT_HAVE_MAXMINDDB 1
#elif __has_include(<x86_64-linux-gnu/maxminddb.h>)
#include <x86_64-linux-gnu/maxminddb.h>
#define ZT_HAVE_MAXMINDDB 1
#endif
#endif

using json = nlohmann::json;

#ifdef __APPLE__
#include <CoreServices/CoreServices.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#define ZT_PID_PATH "zerotier-one.pid"

using namespace ZeroTier;

static OneService* volatile zt1Service = (OneService*)0;

#define PROGRAM_NAME	 "ZeroTier One"
#define COPYRIGHT_NOTICE "Copyright (c) ZeroTier, Inc."

#ifdef ZT_NONFREE_CONTROLLER
#define LICENSE_GRANT                                                                                                                                                                                                                          \
	ZT_EOL_S "Licensed under a Source-Available License for Non-Commercial" ZT_EOL_S "Use (nonfree/LICENSE.md). Use of this build for Commercial Use" ZT_EOL_S "requires a paid subscription plan or a commercial license" ZT_EOL_S            \
			 "agreement with ZeroTier, Inc. Visit https://www.zerotier.com for" ZT_EOL_S "more information."
#else
#define LICENSE_GRANT "Licensed under Mozilla Public License v2.0 (LICENSE-MPL.txt)."
#endif

#ifndef ZT_NATIVE_BUILD
#define ZT_NATIVE_BUILD 0
#endif

static inline const char* nativeBuildMode()
{
	return ZT_NATIVE_BUILD ? "native" : "portable";
}

#ifdef __LINUX__
static bool readUnsignedLongLongFromFile(const char* path, unsigned long long& v)
{
	FILE* f = fopen(path, "r");
	if (! f)
		return false;
	unsigned long long tmp = 0ULL;
	const int r = fscanf(f, "%llu", &tmp);
	fclose(f);
	if (r != 1)
		return false;
	v = tmp;
	return true;
}

struct LinuxThermalSample {
	bool freqValid;
	double freqRatio;
	unsigned long long coreThrottleCount;
	unsigned long long packageThrottleCount;
};

static LinuxThermalSample readLinuxThermalSample()
{
	LinuxThermalSample s;
	s.freqValid = false;
	s.freqRatio = std::numeric_limits<double>::quiet_NaN();
	s.coreThrottleCount = 0ULL;
	s.packageThrottleCount = 0ULL;

	unsigned long long freqCurSum = 0ULL;
	unsigned long long freqMaxSum = 0ULL;
	unsigned int freqCount = 0U;

	char path[256];
	for (unsigned int cpu = 0; cpu < 256; ++cpu) {
		unsigned long long v = 0ULL;
		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/cpufreq/scaling_cur_freq", cpu);
		if (readUnsignedLongLongFromFile(path, v)) {
			freqCurSum += v;
			snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/cpufreq/cpuinfo_max_freq", cpu);
			unsigned long long vmax = 0ULL;
			if (readUnsignedLongLongFromFile(path, vmax) && vmax > 0ULL) {
				freqMaxSum += vmax;
				++freqCount;
			}
		}

		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/thermal_throttle/core_throttle_count", cpu);
		if (readUnsignedLongLongFromFile(path, v))
			s.coreThrottleCount += v;
		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/thermal_throttle/package_throttle_count", cpu);
		if (readUnsignedLongLongFromFile(path, v))
			s.packageThrottleCount += v;
	}

	if ((freqCount > 0U) && (freqMaxSum > 0ULL)) {
		s.freqValid = true;
		s.freqRatio = (double)freqCurSum / (double)freqMaxSum;
	}
	return s;
}
#endif

/****************************************************************************/
/* zerotier-cli personality                                                 */
/****************************************************************************/

static void cliPrintHelp(const char* pn, FILE* out)
{
	fprintf(
		out,
		"%s version %d.%d.%d build %d (platform %d arch %d, %s build)" ZT_EOL_S,
		PROGRAM_NAME,
		ZEROTIER_ONE_VERSION_MAJOR,
		ZEROTIER_ONE_VERSION_MINOR,
		ZEROTIER_ONE_VERSION_REVISION,
		ZEROTIER_ONE_VERSION_BUILD,
		ZT_BUILD_PLATFORM,
		ZT_BUILD_ARCHITECTURE,
		nativeBuildMode());
	fprintf(out, COPYRIGHT_NOTICE ZT_EOL_S LICENSE_GRANT ZT_EOL_S);
	fprintf(out, ZT_EOL_S "Usage: %s [-switches] <command/path> [<args>]" ZT_EOL_S "" ZT_EOL_S, pn);
	fprintf(out, "Available switches:" ZT_EOL_S);
	fprintf(out, "  -h                      - Display this help" ZT_EOL_S);
	fprintf(out, "  -v                      - Show version" ZT_EOL_S);
	fprintf(out, "  -j                      - Display full raw JSON output" ZT_EOL_S);
	fprintf(out, "  -D<path>                - ZeroTier home path for parameter auto-detect" ZT_EOL_S);
	fprintf(out, "  -p<port>                - HTTP port (default: auto)" ZT_EOL_S);
	fprintf(out, "  -T<token>               - Authentication token (default: auto)" ZT_EOL_S);
	fprintf(out, ZT_EOL_S "Available commands:" ZT_EOL_S);
	fprintf(out, "  info                    - Display status info" ZT_EOL_S);
	fprintf(out, "  listpeers               - List all peers" ZT_EOL_S);
	fprintf(out, "  peers                   - List all peers (prettier)" ZT_EOL_S);
	fprintf(out, "  listnetworks            - List all networks" ZT_EOL_S);
	fprintf(out, "  join <network ID>          - Join a network" ZT_EOL_S);
	fprintf(out, "  leave <network ID>         - Leave a network" ZT_EOL_S);
	fprintf(out, "  set <network ID> <setting> - Set a network setting" ZT_EOL_S);
	fprintf(out, "  get <network ID> <setting> - Get a network setting" ZT_EOL_S);
	fprintf(out, "  dump                    - Debug settings dump for support" ZT_EOL_S);
	fprintf(out, "  stats                   - Show peer port usage statistics" ZT_EOL_S);
	fprintf(out, "  monitor-add <ip|zt|nwid|network_name|ip:zt> - Enable packet logging for IP, ZT, network, or IP:ZT pair" ZT_EOL_S);
	fprintf(out, "  monitor-remove <ip|zt|nwid|network_name|ip:zt> - Disable packet logging for IP, ZT, network, or IP:ZT pair" ZT_EOL_S);
	fprintf(out, "  monitor-list            - List active monitor targets and their /tmp log files" ZT_EOL_S);
	fprintf(out, "  findzt <ip_address>     - Find ZeroTier address(es) for given in-network IP" ZT_EOL_S);
	fprintf(out, "  findip <zt_address>     - Find IP address for given ZeroTier address" ZT_EOL_S);
	fprintf(out, "  set-api-token <token>   - Set ZeroTier Central API token for enhanced lookups" ZT_EOL_S);
	fprintf(out, ZT_EOL_S "Available settings:" ZT_EOL_S);
	fprintf(out, "  Settings to use with [get/set] may include property names from " ZT_EOL_S);
	fprintf(out, "  the JSON output of \"zerotier-cli -j listnetworks\". Additionally, " ZT_EOL_S);
	fprintf(out, "  (ip, ip4, ip6, ip6plane, and ip6prefix can be used). For instance:" ZT_EOL_S);
	fprintf(out, "  zerotier-cli get <network ID> ip6plane will return the 6PLANE address" ZT_EOL_S);
	fprintf(out, "  assigned to this node." ZT_EOL_S);
}

static std::string cliFixJsonCRs(const std::string& s)
{
	std::string r;
	for (std::string::const_iterator c(s.begin()); c != s.end(); ++c) {
		if (*c == '\n')
			r.append(ZT_EOL_S);
		else
			r.push_back(*c);
	}
	return r;
}

static std::string cliStatsFormatBytesCompact(uint64_t bytes)
{
	char buf[32];
	if (bytes >= (1024ULL * 1024ULL * 1024ULL)) {
		double v = bytes / (1024.0 * 1024.0 * 1024.0);
		snprintf(buf, sizeof(buf), (v >= 10.0) ? "%.0fg" : "%.1fg", v);
	}
	else if (bytes >= (1024ULL * 1024ULL)) {
		double v = bytes / (1024.0 * 1024.0);
		snprintf(buf, sizeof(buf), (v >= 10.0) ? "%.0fm" : "%.1fm", v);
	}
	else if (bytes >= 1024ULL) {
		double v = bytes / 1024.0;
		snprintf(buf, sizeof(buf), (v >= 10.0) ? "%.0fk" : "%.1fk", v);
	}
	else {
		snprintf(buf, sizeof(buf), "%llu", (unsigned long long)bytes);
	}
	return std::string(buf);
}

static std::string cliStatsFormatAge(uint64_t lastSeenMs)
{
	if (lastSeenMs == 0)
		return "never";
	uint64_t now = OSUtils::now();
	if (now <= lastSeenMs)
		return "0s";
	uint64_t secondsAgo = (now - lastSeenMs) / 1000;
	const uint64_t minutesAgo = secondsAgo / 60;
	const uint64_t hoursAgo = secondsAgo / 3600;
	char buf[32];
	if (secondsAgo < 60) {
		snprintf(buf, sizeof(buf), "%lus", (unsigned long)secondsAgo);
	}
	else if (secondsAgo < (20ULL * 60ULL)) {
		snprintf(buf, sizeof(buf), "%lum%lus", (unsigned long)(secondsAgo / 60), (unsigned long)(secondsAgo % 60));
	}
	else if (secondsAgo < 3600) {
		snprintf(buf, sizeof(buf), "%lum", (unsigned long)minutesAgo);
	}
	else if (secondsAgo < (12ULL * 3600ULL)) {
		snprintf(buf, sizeof(buf), "%luh%lum", (unsigned long)hoursAgo, (unsigned long)((secondsAgo % 3600) / 60));
	}
	else if (secondsAgo < 86400) {
		snprintf(buf, sizeof(buf), "%luh", (unsigned long)hoursAgo);
	}
	else {
		snprintf(buf, sizeof(buf), "%lud%luh", (unsigned long)(secondsAgo / 86400), (unsigned long)((secondsAgo % 86400) / 3600));
	}
	return std::string(buf);
}

static void cliStatsPrintDiagnostics(const nlohmann::json& j)
{
	if (! j.contains("diagnostics")) {
		return;
	}
	const auto& diag = j["diagnostics"];
	printf("Lookup Table Diagnostics:" ZT_EOL_S);
	printf("  Lookup Table Entries:  %u (ZT+IP combinations)" ZT_EOL_S, (unsigned int)diag.value("peerStatsTableSize", 0));
	printf("    Unique ZT Addresses: %u" ZT_EOL_S, (unsigned int)diag.value("uniqueZTAddresses", 0));
	printf("    Unique IP Addresses: %u" ZT_EOL_S, (unsigned int)diag.value("uniqueIPAddresses", 0));

	std::string allPeersStr;
	if (diag.contains("allPeersCount")) {
		if (diag["allPeersCount"].is_string()) {
			allPeersStr = diag["allPeersCount"].get<std::string>();
		}
		else {
			allPeersStr = std::to_string((unsigned int)diag["allPeersCount"]);
		}
	}
	else {
		allPeersStr = "unknown";
	}
	printf("  AllPeers (topology):   %s" ZT_EOL_S, allPeersStr.c_str());
	printf("  Port Tracking Entries: %u incoming, %u outgoing" ZT_EOL_S, (unsigned int)diag.value("seenIncomingPeerPortsSize", 0), (unsigned int)diag.value("seenOutgoingPeerPortsSize", 0));
}

static void cliStatsPrintPortConfiguration(const nlohmann::json& j)
{
	if (! j.contains("portConfiguration")) {
		return;
	}
	const auto& portConfig = j["portConfiguration"];
	const uint32_t primaryPort = portConfig["primaryPort"];
	const uint32_t secondaryPort = portConfig["secondaryPort"];
	const uint32_t tertiaryPort = portConfig["tertiaryPort"];
	const bool allowSecondaryPort = portConfig["allowSecondaryPort"];

	std::string secondaryField = "off";
	if (allowSecondaryPort && secondaryPort > 0) {
		secondaryField = std::to_string(secondaryPort);
	}
	else if (allowSecondaryPort) {
		secondaryField = "dyn";
	}

	std::string boundField = "-";
	if (portConfig.contains("actualBoundPorts") && portConfig["actualBoundPorts"].is_array()) {
		const auto& actualPorts = portConfig["actualBoundPorts"];
		std::string bf;
		for (const auto& port : actualPorts) {
			if (! bf.empty()) {
				bf += ",";
			}
			bf += std::to_string((unsigned int)port);
		}
		if (! bf.empty()) {
			boundField = bf;
		}
	}
	printf("Port Config: p=%u s=%s t=%u bound=%s" ZT_EOL_S, primaryPort, secondaryField.c_str(), tertiaryPort, boundField.c_str());
}

static void cliStatsPrintNetworkUsage(const nlohmann::json& j)
{
	if (! j.contains("networkUsage") || ! j["networkUsage"].is_object()) {
		return;
	}
	const auto& nu = j["networkUsage"];
	std::string usageLine;
	if (nu.contains("perNetwork") && nu["perNetwork"].is_array()) {
		for (const auto& row : nu["perNetwork"]) {
			const std::string name = row.value("name", "");
			const std::string nwid = row.value("nwid", "");
			const std::string label = ! name.empty() ? name : nwid;
			const uint64_t in = row.value("incoming", 0ULL);
			const uint64_t out = row.value("outgoing", 0ULL);
			if ((in == 0ULL) && (out == 0ULL)) {
				continue;
			}
			if (! usageLine.empty())
				usageLine += ", ";
			usageLine += label + "=" + cliStatsFormatBytesCompact(in) + ":" + cliStatsFormatBytesCompact(out);
		}
	}
	if (! usageLine.empty()) {
		printf("Net Usage:   %s" ZT_EOL_S ZT_EOL_S, usageLine.c_str());
	}
}

static void cliStatsPrintPeerTable(const nlohmann::json& j)
{
	if (! j.contains("peersByZtAddressAndIP") || ! j["peersByZtAddressAndIP"].is_array()) {
		return;
	}

	struct StatsRow {
		uint64_t pairTotal;
		std::string ipAddress;
		std::string ztaddr;
		std::string peerRole;
		bool isPrivateIp;
		std::string countryFlag;
		std::string rxBytesStr;
		std::string txBytesStr;
		std::string lastSeenStr;
		std::string portUsage;
	};
	std::vector<StatsRow> rows;
	rows.reserve(j["peersByZtAddressAndIP"].size());

	auto isLikelyIpLiteral = [](const std::string& ip) -> bool {
		if (ip.empty())
			return false;
		for (char c : ip) {
			if (! std::isxdigit((unsigned char)c) && c != '.' && c != ':') {
				return false;
			}
		}
		return true;
	};
	auto isPrivateIpLiteral = [](const std::string& ip) -> bool {
		InetAddress a(ip.c_str());
		if (a.isV4()) {
			char b[64];
			a.ipOnly().toIpString(b);
			unsigned int o1 = 0, o2 = 0, o3 = 0, o4 = 0;
			if (sscanf(b, "%u.%u.%u.%u", &o1, &o2, &o3, &o4) == 4) {
				if (o1 == 10)
					return true;
				if ((o1 == 172) && (o2 >= 16) && (o2 <= 31))
					return true;
				if ((o1 == 192) && (o2 == 168))
					return true;
				if (o1 == 127)
					return true;
				if ((o1 == 169) && (o2 == 254))
					return true;
			}
		}
		else if (a.isV6()) {
			char b[64];
			a.ipOnly().toIpString(b);
			const std::string s(b);
			if ((s.size() >= 2) && ((s[0] == 'f') || (s[0] == 'F')) && ((s[1] == 'c') || (s[1] == 'C') || (s[1] == 'd') || (s[1] == 'D')))
				return true;
			if ((s.size() >= 4) && (s[0] == 'f' || s[0] == 'F') && (s[1] == 'e' || s[1] == 'E') && (s[2] == '8') && (s[3] == '0'))
				return true;
			if (s == "::1")
				return true;
		}
		return false;
	};

#ifdef ZT_HAVE_MAXMINDDB
	auto appendUtf8 = [](std::string& out, uint32_t cp) {
		if (cp <= 0x7F) {
			out.push_back((char)cp);
		}
		else if (cp <= 0x7FF) {
			out.push_back((char)(0xC0 | ((cp >> 6) & 0x1F)));
			out.push_back((char)(0x80 | (cp & 0x3F)));
		}
		else if (cp <= 0xFFFF) {
			out.push_back((char)(0xE0 | ((cp >> 12) & 0x0F)));
			out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
			out.push_back((char)(0x80 | (cp & 0x3F)));
		}
		else {
			out.push_back((char)(0xF0 | ((cp >> 18) & 0x07)));
			out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
			out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
			out.push_back((char)(0x80 | (cp & 0x3F)));
		}
	};

	auto isoToFlag = [&appendUtf8](const std::string& iso) -> std::string {
		if (iso.size() != 2)
			return std::string();
		char a = (char)std::toupper((unsigned char)iso[0]);
		char b = (char)std::toupper((unsigned char)iso[1]);
		if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z')
			return std::string();
		std::string out;
		appendUtf8(out, 0x1F1E6 + (uint32_t)(a - 'A'));
		appendUtf8(out, 0x1F1E6 + (uint32_t)(b - 'A'));
		return out;
	};

	struct GeoIpResolver {
		bool initialized = false;
		bool available = false;
		MMDB_s mmdb;

		GeoIpResolver()
		{
			memset(&mmdb, 0, sizeof(mmdb));
		}
		~GeoIpResolver()
		{
			if (available)
				MMDB_close(&mmdb);
		}

		void initOnce()
		{
			if (initialized)
				return;
			initialized = true;
			const char* paths[] = {
				"/var/lib/geoip/GeoLite2-Country.mmdb",
				"/var/lib/geoip/GeoLite2-City.mmdb",
				"/usr/share/GeoIP/GeoLite2-Country.mmdb",
				"/usr/share/GeoIP/GeoLite2-City.mmdb",
#ifdef __WINDOWS__
				"C:\\ProgramData\\ZeroTier\\One\\GeoLite2-Country.mmdb",
				"C:\\ProgramData\\ZeroTier\\One\\GeoLite2-City.mmdb",
#endif
			};
			for (unsigned int i = 0; i < (sizeof(paths) / sizeof(paths[0])); ++i) {
				const int rc = MMDB_open(paths[i], MMDB_MODE_MMAP, &mmdb);
				if (rc == MMDB_SUCCESS) {
					available = true;
					break;
				}
			}
		}

		std::string countryIso(const std::string& ip)
		{
			initOnce();
			if (! available)
				return std::string();
			int gaiError = 0;
			int mmdbError = 0;
			MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip.c_str(), &gaiError, &mmdbError);
			if (gaiError != 0 || mmdbError != MMDB_SUCCESS || ! result.found_entry) {
				return std::string();
			}
			MMDB_entry_data_s data;
			int status = MMDB_get_value(&result.entry, &data, "country", "iso_code", nullptr);
			if (status == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING && data.data_size == 2) {
				return std::string(data.utf8_string, data.data_size);
			}
			status = MMDB_get_value(&result.entry, &data, "registered_country", "iso_code", nullptr);
			if (status == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING && data.data_size == 2) {
				return std::string(data.utf8_string, data.data_size);
			}
			status = MMDB_get_value(&result.entry, &data, "represented_country", "iso_code", nullptr);
			if (status == MMDB_SUCCESS && data.has_data && data.type == MMDB_DATA_TYPE_UTF8_STRING && data.data_size == 2) {
				return std::string(data.utf8_string, data.data_size);
			}
			return std::string();
		}
	};
	GeoIpResolver geo;
#endif
	std::map<std::string, std::string> countryFlagCache;
	auto lookupCountryFlag = [&](const std::string& ip) -> std::string {
		std::map<std::string, std::string>::const_iterator cached = countryFlagCache.find(ip);
		if (cached != countryFlagCache.end()) {
			return cached->second;
		}

		std::string flag;
		if (isLikelyIpLiteral(ip)) {
#ifdef ZT_HAVE_MAXMINDDB
			const std::string iso = geo.countryIso(ip);
			if (! iso.empty()) {
				flag = isoToFlag(iso);
			}
#endif
		}

		countryFlagCache[ip] = flag;
		return flag;
	};

	auto nextCodepoint = [](const std::string& s, std::size_t& i) -> uint32_t {
		unsigned char c = (unsigned char)s[i];
		if (c < 0x80) {
			++i;
			return (uint32_t)c;
		}
		if ((c & 0xE0) == 0xC0 && i + 1 < s.size()) {
			uint32_t cp = ((uint32_t)(c & 0x1F) << 6) | (uint32_t)(s[i + 1] & 0x3F);
			i += 2;
			return cp;
		}
		if ((c & 0xF0) == 0xE0 && i + 2 < s.size()) {
			uint32_t cp = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(s[i + 1] & 0x3F) << 6) | (uint32_t)(s[i + 2] & 0x3F);
			i += 3;
			return cp;
		}
		if ((c & 0xF8) == 0xF0 && i + 3 < s.size()) {
			uint32_t cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[i + 1] & 0x3F) << 12) | ((uint32_t)(s[i + 2] & 0x3F) << 6) | (uint32_t)(s[i + 3] & 0x3F);
			i += 4;
			return cp;
		}
		++i;
		return (uint32_t)c;
	};

	auto displayWidth = [&](const std::string& s) -> int {
		int w = 0;
		static constexpr int ZT_SPIDER_EMOJI_WIDTH = 1;
		std::vector<uint32_t> cps;
		for (std::size_t i = 0; i < s.size();) {
			cps.push_back(nextCodepoint(s, i));
		}
		auto isZeroWidth = [](uint32_t cp) -> bool {
			if ((cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) || (cp >= 0x1DC0 && cp <= 0x1DFF) || (cp >= 0x20D0 && cp <= 0x20FF) || (cp >= 0xFE00 && cp <= 0xFE0F) || cp == 0x200D) {
				return true;
			}
			return false;
		};
		for (std::size_t i = 0; i < cps.size(); ++i) {
			const uint32_t cp = cps[i];
			if (isZeroWidth(cp)) {
				continue;
			}
			if (cp >= 0x1F1E6 && cp <= 0x1F1FF && i + 1 < cps.size() && cps[i + 1] >= 0x1F1E6 && cps[i + 1] <= 0x1F1FF) {
				w += 2;
				++i;
				continue;
			}
			if (cp == 0x1F578) {
				w += ZT_SPIDER_EMOJI_WIDTH;
				continue;
			}
			if (cp < 0x80) {
				w += 1;
			}
			else if (cp >= 0x1100) {
				w += 2;
			}
			else {
				w += 1;
			}
		}
		return w;
	};

	auto padRightDisplay = [&](const std::string& s, int width) -> std::string {
		const int w = displayWidth(s);
		if (w >= width)
			return s;
		return s + std::string((std::size_t)(width - w), ' ');
	};

	uint32_t secondaryPort = 0;
	if (j.contains("portConfiguration")) {
		const auto& portConfig = j["portConfiguration"];
		secondaryPort = portConfig.value("secondaryPort", 0U);
	}

	for (const auto& peerData : j["peersByZtAddressAndIP"]) {
		std::string ztaddr = peerData.value("ztAddress", "");
		if (ztaddr == "0000000000") {
			ztaddr.clear();
		}
		const std::string ipAddressRaw = peerData.value("ipAddress", "-");
		const std::string peerRole = peerData.value("peerRole", "unknown");
		const std::string countryFlag = lookupCountryFlag(ipAddressRaw);

		const uint64_t pairBytesIncoming = peerData.value("pairBytesIncoming", 0ULL);
		const uint64_t pairBytesOutgoing = peerData.value("pairBytesOutgoing", 0ULL);
		const uint64_t displayBytesIncoming = peerData.value("displayBytesIncoming", 0ULL);
		const uint64_t displayBytesOutgoing = peerData.value("displayBytesOutgoing", 0ULL);
		const std::string rxSource = peerData.value("rxSource", "?");
		const std::string txSource = peerData.value("txSource", "?");
		const uint64_t lastSeen = peerData.value("lastSeen", 0ULL);

		const std::string rxBytesStr = cliStatsFormatBytesCompact(pairBytesIncoming) + "/" + cliStatsFormatBytesCompact(displayBytesIncoming) + rxSource;
		const std::string txBytesStr = cliStatsFormatBytesCompact(pairBytesOutgoing) + "/" + cliStatsFormatBytesCompact(displayBytesOutgoing) + txSource;
		const std::string lastSeenStr = cliStatsFormatAge(lastSeen);

		const uint64_t primaryIn = peerData.value("primaryIncoming", 0ULL);
		const uint64_t primaryOut = peerData.value("primaryOutgoing", 0ULL);
		const uint64_t secondaryIn = (secondaryPort > 0) ? peerData.value("secondaryIncoming", 0ULL) : 0ULL;
		const uint64_t secondaryOut = (secondaryPort > 0) ? peerData.value("secondaryOutgoing", 0ULL) : 0ULL;
		const uint64_t tertiaryIn = peerData.value("tertiaryIncoming", 0ULL);
		const uint64_t tertiaryOut = peerData.value("tertiaryOutgoing", 0ULL);
		const uint64_t overlayPacketsIn = peerData.value("overlayPacketsIncoming", 0ULL);
		const uint64_t overlayPacketsOut = peerData.value("overlayPacketsOutgoing", 0ULL);

		std::string portUsage;
		if (peerRole == "overlay") {
			portUsage = cliStatsFormatBytesCompact(overlayPacketsIn) + ":" + cliStatsFormatBytesCompact(overlayPacketsOut);
		}
		else {
			portUsage = cliStatsFormatBytesCompact(primaryIn) + ":" + cliStatsFormatBytesCompact(primaryOut) + ", " + cliStatsFormatBytesCompact(secondaryIn) + ":" + cliStatsFormatBytesCompact(secondaryOut) + ", "
						+ cliStatsFormatBytesCompact(tertiaryIn) + ":" + cliStatsFormatBytesCompact(tertiaryOut);
		}

		StatsRow row;
		row.pairTotal = pairBytesIncoming + pairBytesOutgoing;
		row.ipAddress = ipAddressRaw;
		row.ztaddr = ztaddr;
		row.peerRole = peerRole;
		row.isPrivateIp = isPrivateIpLiteral(ipAddressRaw);
		row.countryFlag = countryFlag;
		row.rxBytesStr = rxBytesStr;
		row.txBytesStr = txBytesStr;
		row.lastSeenStr = lastSeenStr;
		row.portUsage = portUsage;
		rows.push_back(row);
	}

	std::sort(rows.begin(), rows.end(), [](const StatsRow& a, const StatsRow& b) { return a.pairTotal > b.pairTotal; });

	auto roleEmoji = [](const std::string& role) -> const char* {
		if (role == "planet")
			return "🪐";
		if (role == "moon")
			return "🌙";
		return "";
	};

	struct RenderedRow {
		std::string ipCol;
		std::string ztCol;
		std::string rxCol;
		std::string txCol;
		std::string seenCol;
		std::string portUsageCol;
	};
	std::vector<RenderedRow> renderedRows;
	renderedRows.reserve(rows.size());

	int ipColWidth = displayWidth("IP Address");
	int ztColWidth = displayWidth("ZT Address");
	int rxColWidth = displayWidth("RX Bytes");
	int txColWidth = displayWidth("TX Bytes");
	int seenColWidth = displayWidth("Seen");

	for (const auto& row : rows) {
		const char* icon = roleEmoji(row.peerRole);
		std::string ipCol = row.ipAddress;
		if (row.peerRole == "overlay") {
			ipCol = std::string("🕸️  ") + row.ipAddress;
		}
		else if (row.isPrivateIp) {
			ipCol = std::string("🏠 ") + row.ipAddress;
		}
		else if (! row.countryFlag.empty()) {
			ipCol = row.countryFlag + " " + row.ipAddress;
		}
		std::string ztCol = row.ztaddr;
		if (! row.ztaddr.empty() && icon[0] != '\0') {
			ztCol = std::string(icon) + row.ztaddr;
		}

		RenderedRow rr;
		rr.ipCol = ipCol;
		rr.ztCol = ztCol;
		rr.rxCol = row.rxBytesStr;
		rr.txCol = row.txBytesStr;
		rr.seenCol = row.lastSeenStr;
		rr.portUsageCol = row.portUsage;
		renderedRows.push_back(rr);

		ipColWidth = std::max(ipColWidth, displayWidth(rr.ipCol));
		ztColWidth = std::max(ztColWidth, displayWidth(rr.ztCol));
		rxColWidth = std::max(rxColWidth, displayWidth(rr.rxCol));
		txColWidth = std::max(txColWidth, displayWidth(rr.txCol));
		seenColWidth = std::max(seenColWidth, displayWidth(rr.seenCol));
	}

	printf(
		"%s %s %s %s %s %s" ZT_EOL_S,
		padRightDisplay("IP Address", ipColWidth).c_str(),
		padRightDisplay("ZT Address", ztColWidth).c_str(),
		padRightDisplay("RX Bytes", rxColWidth).c_str(),
		padRightDisplay("TX Bytes", txColWidth).c_str(),
		padRightDisplay("Seen", seenColWidth).c_str(),
		"Port Usage");
	printf(
		"%s %s %s %s %s %s" ZT_EOL_S,
		std::string((std::size_t)ipColWidth, '-').c_str(),
		std::string((std::size_t)ztColWidth, '-').c_str(),
		std::string((std::size_t)rxColWidth, '-').c_str(),
		std::string((std::size_t)txColWidth, '-').c_str(),
		std::string((std::size_t)seenColWidth, '-').c_str(),
		"----------");

	for (const auto& rr : renderedRows) {
		printf(
			"%s %s %s %s %s %s" ZT_EOL_S,
			padRightDisplay(rr.ipCol, ipColWidth).c_str(),
			padRightDisplay(rr.ztCol, ztColWidth).c_str(),
			padRightDisplay(rr.rxCol, rxColWidth).c_str(),
			padRightDisplay(rr.txCol, txColWidth).c_str(),
			padRightDisplay(rr.seenCol, seenColWidth).c_str(),
			rr.portUsageCol.c_str());
	}
}

#ifdef __WINDOWS__
static int cli(int argc, _TCHAR* argv[])
#else
static int cli(int argc, char** argv)
#endif
{
	unsigned int port = 0;
	std::string homeDir, command, arg1, arg2, arg3, arg4, authToken;
	std::string ip("127.0.0.1");
	bool json = false;
	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
				case 'q':	// ignore -q used to invoke this personality
					if (argv[i][2]) {
						cliPrintHelp(argv[0], stdout);
						return 1;
					}
					break;

				case 'j':
					if (argv[i][2]) {
						cliPrintHelp(argv[0], stdout);
						return 1;
					}
					json = true;
					break;

				case 'p':
					port = Utils::strToUInt(argv[i] + 2);
					if ((port > 0xffff) || (port == 0)) {
						cliPrintHelp(argv[0], stdout);
						return 1;
					}
					break;

				case 'D':
					if (argv[i][2]) {
						homeDir = argv[i] + 2;
					}
					else {
						cliPrintHelp(argv[0], stdout);
						return 1;
					}
					break;

				case 'H':
					if (argv[i][2]) {
						ip = argv[i] + 2;
					}
					else {
						cliPrintHelp(argv[0], stdout);
						return 1;
					}
					break;

				case 'T':
					if (argv[i][2]) {
						authToken = argv[i] + 2;
					}
					else {
						cliPrintHelp(argv[0], stdout);
						return 1;
					}
					break;

				case 'v':
					if (argv[i][2]) {
						cliPrintHelp(argv[0], stdout);
						return 1;
					}
					printf("%d.%d.%d (%s build)" ZT_EOL_S, ZEROTIER_ONE_VERSION_MAJOR, ZEROTIER_ONE_VERSION_MINOR, ZEROTIER_ONE_VERSION_REVISION, nativeBuildMode());
					return 0;

				case 'h':
				case '?':
				default:
					cliPrintHelp(argv[0], stdout);
					return 0;
			}
		}
		else {
			if (arg1.length())
				arg2 = argv[i];
			else if (command.length())
				arg1 = argv[i];
			else
				command = argv[i];
		}
	}
	if (! homeDir.length())
		homeDir = OneService::platformDefaultHomePath();

	// TODO: cleanup this logic
	if ((! port) || (! authToken.length())) {
		if (! homeDir.length()) {
			fprintf(stderr, "%s: missing port or authentication token and no home directory specified to auto-detect" ZT_EOL_S, argv[0]);
			return 2;
		}

		if (! port) {
			std::string portStr;
			OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "zerotier-one.port").c_str(), portStr);
			port = Utils::strToUInt(portStr.c_str());
			if ((port == 0) || (port > 0xffff)) {
				fprintf(stderr, "%s: missing port and zerotier-one.port not found in %s" ZT_EOL_S, argv[0], homeDir.c_str());
				return 2;
			}
		}

		if (! authToken.length()) {
			OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "authtoken.secret").c_str(), authToken);
#ifdef __UNIX_LIKE__
			if (! authToken.length()) {
				const char* hd = getenv("HOME");
				if (hd) {
					char p[4096];
#ifdef __APPLE__
					OSUtils::ztsnprintf(p, sizeof(p), "%s/Library/Application Support/ZeroTier/One/authtoken.secret", hd);
#else
					OSUtils::ztsnprintf(p, sizeof(p), "%s/.zeroTierOneAuthToken", hd);
#endif
					OSUtils::readFile(p, authToken);
				}
			}
#endif
			if (! authToken.length()) {
				fprintf(stderr, "%s: authtoken.secret not found or readable in %s (try again as root)" ZT_EOL_S, argv[0], homeDir.c_str());
				return 2;
			}
		}
	}

	InetAddress addr;
	{
		char addrtmp[256];
		OSUtils::ztsnprintf(addrtmp, sizeof(addrtmp), "%s/%u", ip.c_str(), port);
		addr = InetAddress(addrtmp);
	}

	std::map<std::string, std::string> requestHeaders;
	std::map<std::string, std::string> responseHeaders;
	std::string responseBody;

	requestHeaders["X-ZT1-Auth"] = authToken;

	if ((command.length() > 0) && (command[0] == '/')) {
		unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, command.c_str(), requestHeaders, responseHeaders, responseBody);
		if (scode == 200) {
			printf("%s", cliFixJsonCRs(responseBody).c_str());
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if ((command == "info") || (command == "status")) {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/status", requestHeaders, responseHeaders, responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
			}
			else {
				if (j.is_object()) {
					printf("200 info %s %s %s" ZT_EOL_S, OSUtils::jsonString(j["address"], "-").c_str(), OSUtils::jsonString(j["version"], "-").c_str(), ((j["tcpFallbackActive"]) ? "TUNNELED" : ((j["online"]) ? "ONLINE" : "OFFLINE")));
				}
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "listpeers") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/peer", requestHeaders, responseHeaders, responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
			}
			else {
				printf("200 listpeers <ztaddr> <path> <latency> <version> <role>" ZT_EOL_S);
				if (j.is_array()) {
					for (unsigned long k = 0; k < j.size(); ++k) {
						nlohmann::json& p = j[k];
						std::string bestPath;
						nlohmann::json& paths = p["paths"];
						if (paths.is_array()) {
							for (unsigned long i = 0; i < paths.size(); ++i) {
								nlohmann::json& path = paths[i];
								if (path["preferred"]) {
									char tmp[256];
									std::string addr = path["address"];
									const int64_t now = OSUtils::now();
									int64_t lastSendDiff = (uint64_t)path["lastSend"] ? now - (uint64_t)path["lastSend"] : -1;
									int64_t lastReceiveDiff = (uint64_t)path["lastReceive"] ? now - (uint64_t)path["lastReceive"] : -1;
									OSUtils::ztsnprintf(tmp, sizeof(tmp), "%s;%lld;%lld", addr.c_str(), lastSendDiff, lastReceiveDiff);
									bestPath = tmp;
									break;
								}
							}
						}
						if (bestPath.length() == 0)
							bestPath = "-";
						char ver[128];
						int64_t vmaj = p["versionMajor"];
						int64_t vmin = p["versionMinor"];
						int64_t vrev = p["versionRev"];
						if (vmaj >= 0) {
							OSUtils::ztsnprintf(ver, sizeof(ver), "%lld.%lld.%lld", vmaj, vmin, vrev);
						}
						else {
							ver[0] = '-';
							ver[1] = (char)0;
						}
						printf("200 listpeers %s %s %d %s %s" ZT_EOL_S, OSUtils::jsonString(p["address"], "-").c_str(), bestPath.c_str(), (int)OSUtils::jsonInt(p["latency"], 0), ver, OSUtils::jsonString(p["role"], "-").c_str());
					}
				}
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "peers") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/peer", requestHeaders, responseHeaders, responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
			}
			else {
				bool anyTunneled = false;
				printf("200 peers\n<ztaddr>   <ver>  <role> <lat> <link>   <lastTX> <lastRX> <path>" ZT_EOL_S);
				if (j.is_array()) {
					for (unsigned long k = 0; k < j.size(); ++k) {
						nlohmann::json& p = j[k];
						std::string bestPath;
						nlohmann::json& paths = p["paths"];
						if (p["tunneled"]) {
							anyTunneled = true;
						}
						if (paths.is_array()) {
							for (unsigned long i = 0; i < paths.size(); ++i) {
								nlohmann::json& path = paths[i];
								if (path["preferred"]) {
									char tmp[256];
									std::string addr = path["address"];
									const int64_t now = OSUtils::now();
									int64_t lastSendDiff = (uint64_t)path["lastSend"] ? now - (uint64_t)path["lastSend"] : -1;
									int64_t lastReceiveDiff = (uint64_t)path["lastReceive"] ? now - (uint64_t)path["lastReceive"] : -1;
									OSUtils::ztsnprintf(tmp, sizeof(tmp), "%-8lld %-8lld %s", lastSendDiff, lastReceiveDiff, addr.c_str());
									if (p["tunneled"]) {
										bestPath = std::string("RELAY ") + tmp;
									}
									else {
										bestPath = std::string("DIRECT   ") + tmp;
									}
									break;
								}
							}
						}
						if (bestPath.length() == 0) {
							bestPath = "RELAY";
						}
						char ver[128];
						int64_t vmaj = p["versionMajor"];
						int64_t vmin = p["versionMinor"];
						int64_t vrev = p["versionRev"];
						if (vmaj >= 0) {
							OSUtils::ztsnprintf(ver, sizeof(ver), "%lld.%lld.%lld", vmaj, vmin, vrev);
						}
						else {
							ver[0] = '-';
							ver[1] = (char)0;
						}
						printf("%s %-6s %-6s %5d %s" ZT_EOL_S, OSUtils::jsonString(p["address"], "-").c_str(), ver, OSUtils::jsonString(p["role"], "-").c_str(), (int)OSUtils::jsonInt(p["latency"], 0), bestPath.c_str());
					}
				}
				if (anyTunneled) {
					printf("NOTE: Currently tunneling through a TCP relay. Ensure that UDP is not blocked.\n");
				}
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "bond") {
		/* zerotier-cli bond <cmd> */
		if (arg1.empty()) {
			printf("(bond) command is missing required arguments" ZT_EOL_S);
			return 2;
		}
		/* zerotier-cli bond list */
		if (arg1 == "list") {
			const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/peer", requestHeaders, responseHeaders, responseBody);
			if (scode == 0) {
				printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
				return 1;
			}
			nlohmann::json j;
			try {
				j = OSUtils::jsonParse(responseBody);
			}
			catch (std::exception& exc) {
				printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
				return 1;
			}
			catch (...) {
				printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
				return 1;
			}
			if (scode == 200) {
				if (json) {
					printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
				}
				else {
					bool bFoundBond = false;
					printf("    <peer>                        <bondtype>     <links>" ZT_EOL_S);
					if (j.is_array()) {
						for (unsigned long k = 0; k < j.size(); ++k) {
							nlohmann::json& p = j[k];
							bool isBonded = p["isBonded"];
							if (isBonded) {
								int8_t bondingPolicyCode = p["bondingPolicyCode"];
								int8_t numAliveLinks = p["numAliveLinks"];
								int8_t numTotalLinks = p["numTotalLinks"];
								bFoundBond = true;
								std::string policyStr = "none";
								if (bondingPolicyCode >= ZT_BOND_POLICY_NONE && bondingPolicyCode <= ZT_BOND_POLICY_BALANCE_AWARE) {
									policyStr = Bond::getPolicyStrByCode(bondingPolicyCode);
								}
								printf("%10s  %32s         %d/%d" ZT_EOL_S, OSUtils::jsonString(p["address"], "-").c_str(), policyStr.c_str(), numAliveLinks, numTotalLinks);
							}
						}
					}
					if (! bFoundBond) {
						printf("      NONE\t\t\t\tNONE\t    NONE       NONE" ZT_EOL_S);
					}
				}
				return 0;
			}
			else {
				printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
				return 1;
			}
		}
		else if (arg1 == "setmtu") { /* zerotier-cli bond setmtu <mtu> <iface> <ip> */
			requestHeaders["Content-Type"] = "application/json";
			requestHeaders["Content-Length"] = "2";
			if (argc == 8) {
				arg2 = argv[5];
				arg3 = argv[6];
				arg4 = argv[7];
			}
			unsigned int scode = Http::POST(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/bond/") + arg1 + "/" + arg2 + "/" + arg3 + "/" + arg4).c_str(), requestHeaders, "{}", 2, responseHeaders, responseBody);
			if (scode == 200) {
				printf("200 setmtu OK" ZT_EOL_S);
				return 0;
			}
			else {
				printf("%d Failed to set MTU: %s" ZT_EOL_S, scode, responseBody.c_str());
				return 1;
			}
			return 0;
		}
		else if (arg1.length() == 10) {
			if (arg2 == "rotate") { /* zerotier-cli bond <peerId> rotate */
				requestHeaders["Content-Type"] = "application/json";
				requestHeaders["Content-Length"] = "2";
				unsigned int scode = Http::POST(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/bond/") + arg2 + "/" + arg1).c_str(), requestHeaders, "{}", 2, responseHeaders, responseBody);
				if (scode == 200) {
					if (json) {
						printf("%s", cliFixJsonCRs(responseBody).c_str());
					}
					else {
						printf("200 rotate OK" ZT_EOL_S);
					}
					return 0;
				}
				else {
					printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
					return 1;
				}
				return 0;
			}
			if (arg2 == "show") {
				// fprintf(stderr, "zerotier-cli bond <peerId> show\n");
				const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/bond/") + arg2 + "/" + arg1).c_str(), requestHeaders, responseHeaders, responseBody);
				if (scode == 0) {
					printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
					return 1;
				}
				nlohmann::json j;
				try {
					j = OSUtils::jsonParse(responseBody);
				}
				catch (std::exception& exc) {
					printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
					return 1;
				}
				catch (...) {
					printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
					return 1;
				}
				if (scode == 200) {
					if (json) {
						printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
					}
					else {
						int numAliveLinks = OSUtils::jsonInt(j["numAliveLinks"], 0);
						int numTotalLinks = OSUtils::jsonInt(j["numTotalLinks"], 0);
						printf("Peer                   : %s\n", arg1.c_str());
						printf("Bond                   : %s\n", OSUtils::jsonString(j["bondingPolicyStr"], "-").c_str());
						printf("Link Select Method     : %d\n", (int)OSUtils::jsonInt(j["linkSelectMethod"], 0));
						printf("Links                  : %d/%d\n", numAliveLinks, numTotalLinks);
						printf("Failover Interval (ms) : %d\n", (int)OSUtils::jsonInt(j["failoverInterval"], 0));
						printf("Up Delay (ms)          : %d\n", (int)OSUtils::jsonInt(j["upDelay"], 0));
						printf("Down Delay (ms)        : %d\n", (int)OSUtils::jsonInt(j["downDelay"], 0));
						printf("Packets Per Link       : %d\n", (int)OSUtils::jsonInt(j["packetsPerLink"], 0));
						nlohmann::json& p = j["paths"];
						if (p.is_array()) {
							printf(
								"\nidx"
								"                  interface"
								"                                  "
								"path               socket             local port\n");
							for (int i = 0; i < 120; i++) {
								printf("-");
							}
							printf("\n");
							for (nlohmann::json::size_type i = 0; i < p.size(); ++i) {
								printf(
									"%2d: %26s %51s %.16llx %12d\n",
									(int)i,
									OSUtils::jsonString(p[i]["ifname"], "-").c_str(),
									OSUtils::jsonString(p[i]["address"], "-").c_str(),
									(unsigned long long)OSUtils::jsonInt(p[i]["localSocket"], 0),
									(uint16_t)OSUtils::jsonInt(p[i]["localPort"], 0));
							}
							printf(
								"\nidx     lat      pdv    "
								"capacity    qual      "
								"rx_age      tx_age  eligible  bonded   flows\n");
							for (int i = 0; i < 120; i++) {
								printf("-");
							}
							printf("\n");
							for (nlohmann::json::size_type i = 0; i < p.size(); ++i) {
								printf(
									"%2d: %8.2f %8.2f %10d %7.4f %11d %11d %9d %7d %7d\n",
									(int)i,
									OSUtils::jsonDouble(p[i]["latencyMean"], 0),
									OSUtils::jsonDouble(p[i]["latencyVariance"], 0),
									(int)OSUtils::jsonInt(p[i]["givenLinkSpeed"], 0),
									OSUtils::jsonDouble(p[i]["relativeQuality"], 0),
									(int)OSUtils::jsonInt(p[i]["lastInAge"], 0),
									(int)OSUtils::jsonInt(p[i]["lastOutAge"], 0),
									(int)OSUtils::jsonInt(p[i]["eligible"], 0),
									(int)OSUtils::jsonInt(p[i]["bonded"], 0),
									(int)OSUtils::jsonInt(p[i]["assignedFlowCount"], 0));
							}
						}
					}
					return 0;
				}
				else {
					printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
					return 1;
				}
				return 2;
			}
		}

		/* zerotier-cli bond command was malformed in some way */
		printf("(bond) command is missing required arguments" ZT_EOL_S);
		return 2;
	}
	else if (command == "listbonds") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/peer", requestHeaders, responseHeaders, responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
			}
			else {
				bool bFoundBond = false;
				printf("    <peer>                        <bondtype>     <links>" ZT_EOL_S);
				if (j.is_array()) {
					for (unsigned long k = 0; k < j.size(); ++k) {
						nlohmann::json& p = j[k];
						bool isBonded = p["isBonded"];
						if (isBonded) {
							int8_t bondingPolicyCode = p["bondingPolicyCode"];
							int8_t numAliveLinks = p["numAliveLinks"];
							int8_t numTotalLinks = p["numTotalLinks"];
							bFoundBond = true;
							std::string policyStr = "none";
							if (bondingPolicyCode >= ZT_BOND_POLICY_NONE && bondingPolicyCode <= ZT_BOND_POLICY_BALANCE_AWARE) {
								policyStr = Bond::getPolicyStrByCode(bondingPolicyCode);
							}
							printf("%10s  %32s         %d/%d" ZT_EOL_S, OSUtils::jsonString(p["address"], "-").c_str(), policyStr.c_str(), numAliveLinks, numTotalLinks);
						}
					}
				}
				if (! bFoundBond) {
					printf("      NONE\t\t\t\tNONE\t    NONE       NONE" ZT_EOL_S);
				}
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "listnetworks") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/network", requestHeaders, responseHeaders, responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
			}
			else {
				printf("200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <ZT assigned ips>" ZT_EOL_S);
				if (j.is_array()) {
					for (unsigned long i = 0; i < j.size(); ++i) {
						nlohmann::json& n = j[i];
						if (n.is_object()) {
							std::string aa;
							nlohmann::json& assignedAddresses = n["assignedAddresses"];
							if (assignedAddresses.is_array()) {
								for (unsigned long j = 0; j < assignedAddresses.size(); ++j) {
									nlohmann::json& addr = assignedAddresses[j];
									if (addr.is_string()) {
										if (aa.length() > 0)
											aa.push_back(',');
										aa.append(addr.get<std::string>());
									}
								}
							}
							if (aa.length() == 0)
								aa = "-";
							const std::string status = OSUtils::jsonString(n["status"], "-");
							printf(
								"200 listnetworks %s %s %s %s %s %s %s" ZT_EOL_S,
								OSUtils::jsonString(n["nwid"], "-").c_str(),
								OSUtils::jsonString(n["name"], "-").c_str(),
								OSUtils::jsonString(n["mac"], "-").c_str(),
								status.c_str(),
								OSUtils::jsonString(n["type"], "-").c_str(),
								OSUtils::jsonString(n["portDeviceName"], "-").c_str(),
								aa.c_str());
							if (OSUtils::jsonBool(n["ssoEnabled"], false)) {
								uint64_t authenticationExpiryTime = n["authenticationExpiryTime"];
								if (status == "AUTHENTICATION_REQUIRED") {
									printf("    AUTH EXPIRED, URL: %s" ZT_EOL_S, OSUtils::jsonString(n["authenticationURL"], "(null)").c_str());
								}
								else if (status == "OK") {
									int64_t expiresIn = ((int64_t)authenticationExpiryTime - OSUtils::now()) / 1000LL;
									if (expiresIn >= 0) {
										printf("    AUTH OK, expires in: %lld seconds" ZT_EOL_S, (long long)expiresIn);
									}
								}
							}
						}
					}
				}
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "join") {
		if (arg1.length() != 16) {
			printf("invalid network id" ZT_EOL_S);
			return 2;
		}
		requestHeaders["Content-Type"] = "application/json";
		requestHeaders["Content-Length"] = "2";
		unsigned int scode = Http::POST(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/network/") + arg1).c_str(), requestHeaders, "{}", 2, responseHeaders, responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s", cliFixJsonCRs(responseBody).c_str());
			}
			else {
				printf("200 join OK" ZT_EOL_S);
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "leave") {
		if (arg1.length() != 16) {
			printf("invalid network id" ZT_EOL_S);
			return 2;
		}
		unsigned int scode = Http::DEL(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/network/") + arg1).c_str(), requestHeaders, responseHeaders, responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s", cliFixJsonCRs(responseBody).c_str());
			}
			else {
				printf("200 leave OK" ZT_EOL_S);
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "listmoons") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/moon", requestHeaders, responseHeaders, responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}

		if (scode == 200) {
			printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "orbit") {
		const uint64_t worldId = Utils::hexStrToU64(arg1.c_str());
		const uint64_t seed = Utils::hexStrToU64(arg2.c_str());
		if ((worldId) && (seed)) {
			char jsons[1024];
			OSUtils::ztsnprintf(jsons, sizeof(jsons), "{\"seed\":\"%s\"}", arg2.c_str());
			char cl[128];
			OSUtils::ztsnprintf(cl, sizeof(cl), "%u", (unsigned int)strlen(jsons));
			requestHeaders["Content-Type"] = "application/json";
			requestHeaders["Content-Length"] = cl;
			unsigned int scode = Http::POST(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/moon/") + arg1).c_str(), requestHeaders, jsons, (unsigned long)strlen(jsons), responseHeaders, responseBody);
			if (scode == 200) {
				printf("200 orbit OK" ZT_EOL_S);
				return 0;
			}
			else {
				printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
				return 1;
			}
		}
	}
	else if (command == "deorbit") {
		unsigned int scode = Http::DEL(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/moon/") + arg1).c_str(), requestHeaders, responseHeaders, responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s", cliFixJsonCRs(responseBody).c_str());
			}
			else {
				printf("200 deorbit OK" ZT_EOL_S);
			}
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "set") {
		if (arg1.length() != 16) {
			fprintf(stderr, "invalid format: must be a 16-digit (network) ID\n");
			return 2;
		}
		if (! arg2.length()) {
			fprintf(stderr, "invalid format: include a property name to set\n");
			return 2;
		}
		std::size_t eqidx = arg2.find('=');
		if (eqidx != std::string::npos) {
			if ((arg2.substr(0, eqidx) == "allowManaged") || (arg2.substr(0, eqidx) == "allowGlobal") || (arg2.substr(0, eqidx) == "allowDefault") || (arg2.substr(0, eqidx) == "allowDNS")) {
				char jsons[1024];
				OSUtils::ztsnprintf(jsons, sizeof(jsons), "{\"%s\":%s}", arg2.substr(0, eqidx).c_str(), (((arg2.substr(eqidx, 2) == "=t") || (arg2.substr(eqidx, 2) == "=1")) ? "true" : "false"));
				char cl[128];
				OSUtils::ztsnprintf(cl, sizeof(cl), "%u", (unsigned int)strlen(jsons));
				requestHeaders["Content-Type"] = "application/json";
				requestHeaders["Content-Length"] = cl;
				unsigned int scode = Http::POST(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (std::string("/network/") + arg1).c_str(), requestHeaders, jsons, (unsigned long)strlen(jsons), responseHeaders, responseBody);
				if (scode == 200) {
					printf("%s", cliFixJsonCRs(responseBody).c_str());
					return 0;
				}
				else {
					printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
					return 1;
				}
			}
		}
		else {
			cliPrintHelp(argv[0], stderr);
			return 2;
		}
	}
	else if (command == "get") {
		if (arg1.length() != 16) {
			fprintf(stderr, "invalid format: must be a 16-digit (network) ID\n");
			return 2;
		}
		if (! arg2.length()) {
			fprintf(stderr, "invalid format: include a property name to get\n");
			return 2;
		}
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/network", requestHeaders, responseHeaders, responseBody);
		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}
		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}
		bool bNetworkFound = false;
		if (j.is_array()) {
			for (unsigned long i = 0; i < j.size(); ++i) {
				nlohmann::json& n = j[i];
				if (n.is_object()) {
					if (n["id"] == arg1) {
						bNetworkFound = true;
						std::string aa;
						if (arg2 != "ip" && arg2 != "ip4" && arg2 != "ip6" && arg2 != "ip6plane" && arg2 != "ip6prefix") {
							aa.append(OSUtils::jsonString(n[arg2], "-"));	// Standard network property field
							if (aa == "-") {
								printf("error, unknown property name\n");
								break;
							}
							printf("%s\n", aa.c_str());
							break;
						}
						nlohmann::json& assignedAddresses = n["assignedAddresses"];
						if (assignedAddresses.is_array()) {
							int matchingIdxs[ZT_MAX_ZT_ASSIGNED_ADDRESSES];
							int addressCountOfType = 0;
							for (int k = 0; k < std::min(ZT_MAX_ZT_ASSIGNED_ADDRESSES, (int)assignedAddresses.size()); ++k) {
								nlohmann::json& addr = assignedAddresses[k];
								if ((arg2 == "ip4" && addr.get<std::string>().find('.') != std::string::npos) || ((arg2.find("ip6") == 0) && addr.get<std::string>().find(":") != std::string::npos) || (arg2 == "ip")) {
									matchingIdxs[addressCountOfType++] = k;
								}
							}
							for (int k = 0; k < addressCountOfType; k++) {
								nlohmann::json& addr = assignedAddresses[matchingIdxs[k]];
								if (! addr.is_string()) {
									continue;
								}
								if (arg2.find("ip6p") == 0) {
									if (arg2 == "ip6plane") {
										if (addr.get<std::string>().find("fc") == 0) {
											aa.append(addr.get<std::string>().substr(0, addr.get<std::string>().find('/')));
											if (k < addressCountOfType - 1)
												aa.append("\n");
										}
									}
									if (arg2 == "ip6prefix") {
										if (addr.get<std::string>().find("fc") == 0) {
											aa.append(addr.get<std::string>().substr(0, addr.get<std::string>().find('/')).substr(0, 24));
											if (k < addressCountOfType - 1)
												aa.append("\n");
										}
									}
								}
								else {
									aa.append(addr.get<std::string>().substr(0, addr.get<std::string>().find('/')));
									if (k < addressCountOfType - 1)
										aa.append("\n");
								}
							}
						}
						printf("%s\n", aa.c_str());
					}
				}
			}
		}
		if (! bNetworkFound) {
			fprintf(stderr, "unknown network ID, check that you are a member of the network\n");
		}
		if (scode == 200) {
			return 0;
		}
		else {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	}
	else if (command == "dump") {
		std::stringstream dump;
		dump << "platform: ";
#ifdef __APPLE__
		dump << "macOS" << ZT_EOL_S;
#elif defined(_WIN32)
		dump << "Windows" << ZT_EOL_S;
#elif defined(__LINUX__)
		dump << "Linux" << ZT_EOL_S;
#else
		dump << "other unix based OS" << ZT_EOL_S;
#endif
		dump << "zerotier version: " << ZEROTIER_ONE_VERSION_MAJOR << "." << ZEROTIER_ONE_VERSION_MINOR << "." << ZEROTIER_ONE_VERSION_REVISION << ZT_EOL_S << ZT_EOL_S;

		// grab status
		dump << "status" << ZT_EOL_S << "------" << ZT_EOL_S;
		unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/status", requestHeaders, responseHeaders, responseBody);
		if (scode != 200) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}
		dump << responseBody << ZT_EOL_S;

		responseHeaders.clear();
		responseBody = "";

		// grab network list
		dump << ZT_EOL_S << "networks" << ZT_EOL_S << "--------" << ZT_EOL_S;
		scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/network", requestHeaders, responseHeaders, responseBody);
		if (scode != 200) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}
		dump << responseBody << ZT_EOL_S;

		responseHeaders.clear();
		responseBody = "";

		// list peers
		dump << ZT_EOL_S << "peers" << ZT_EOL_S << "-----" << ZT_EOL_S;
		scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/peer", requestHeaders, responseHeaders, responseBody);
		if (scode != 200) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}
		dump << responseBody << ZT_EOL_S;

		// Bonds don't need to be queried separately since their data originates from "/peer" responses anyway

		responseHeaders.clear();
		responseBody = "";

		dump << ZT_EOL_S << "local.conf" << ZT_EOL_S << "----------" << ZT_EOL_S;
		std::string localConf;
		OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "local.conf").c_str(), localConf);
		if (localConf.empty()) {
			dump << "None Present" << ZT_EOL_S;
		}
		else {
			dump << localConf << ZT_EOL_S;
		}

		dump << ZT_EOL_S << "Network Interfaces" << ZT_EOL_S << "------------------" << ZT_EOL_S << ZT_EOL_S;
#ifdef __APPLE__
		CFArrayRef interfaces = SCNetworkInterfaceCopyAll();
		CFIndex size = CFArrayGetCount(interfaces);
		for (CFIndex i = 0; i < size; ++i) {
			SCNetworkInterfaceRef iface = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaces, i);

			dump << "Interface " << i << ZT_EOL_S << "-----------" << ZT_EOL_S;
			CFStringRef tmp = SCNetworkInterfaceGetBSDName(iface);
			char stringBuffer[512] = {};
			CFStringGetCString(tmp, stringBuffer, sizeof(stringBuffer), kCFStringEncodingUTF8);
			dump << "Name: " << stringBuffer << ZT_EOL_S;
			std::string ifName(stringBuffer);
			int mtuCur, mtuMin, mtuMax;
			SCNetworkInterfaceCopyMTU(iface, &mtuCur, &mtuMin, &mtuMax);
			dump << "MTU: " << mtuCur << ZT_EOL_S;
			tmp = SCNetworkInterfaceGetHardwareAddressString(iface);
			CFStringGetCString(tmp, stringBuffer, sizeof(stringBuffer), kCFStringEncodingUTF8);
			dump << "MAC: " << stringBuffer << ZT_EOL_S;
			tmp = SCNetworkInterfaceGetInterfaceType(iface);
			CFStringGetCString(tmp, stringBuffer, sizeof(stringBuffer), kCFStringEncodingUTF8);
			dump << "Type: " << stringBuffer << ZT_EOL_S;
			dump << "Addresses:" << ZT_EOL_S;

			struct ifaddrs *ifap, *ifa;
			void* addr;
			getifaddrs(&ifap);
			for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
				if (strcmp(ifName.c_str(), ifa->ifa_name) == 0) {
					if (ifa->ifa_addr->sa_family == AF_INET) {
						struct sockaddr_in* ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
						addr = &ipv4->sin_addr;
					}
					else if (ifa->ifa_addr->sa_family == AF_INET6) {
						struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)ifa->ifa_addr;
						addr = &ipv6->sin6_addr;
					}
					else {
						continue;
					}
					inet_ntop(ifa->ifa_addr->sa_family, addr, stringBuffer, sizeof(stringBuffer));
					dump << stringBuffer << ZT_EOL_S;
				}
			}

			dump << ZT_EOL_S;
		}

		FSRef fsref;
		UInt8 path[PATH_MAX];
		if (FSFindFolder(kUserDomain, kDesktopFolderType, kDontCreateFolder, &fsref) == noErr && FSRefMakePath(&fsref, path, sizeof(path)) == noErr) {}
		else if (getenv("SUDO_USER")) {
			snprintf((char*)path, sizeof(path), "/Users/%s/Desktop", getenv("SUDO_USER"));
		}
		else {
			fprintf(stdout, "%s", dump.str().c_str());
			return 0;
		}

		char dumpfile[PATH_MAX];
		snprintf(dumpfile, sizeof(dumpfile), "%s%szerotier_dump.txt", (char*)path, ZT_PATH_SEPARATOR_S);

		fprintf(stdout, "Writing dump to: %s\n", dumpfile);
		int fd = open(dumpfile, O_CREAT | O_WRONLY | O_TRUNC, 0664);
		if (fd == -1) {
			perror("Error creating file");
			return 1;
		}
		const std::string dumpOutput = dump.str();
		const ssize_t written = ::write(fd, dumpOutput.c_str(), dumpOutput.size());
		if (written < 0) {
			perror("Error writing file");
		}
		close(fd);
#elif defined(_WIN32)
		ULONG buffLen = 16384;
		PIP_ADAPTER_ADDRESSES addresses;

		ULONG ret = 0;
		do {
			addresses = (PIP_ADAPTER_ADDRESSES)malloc(buffLen);

			ret = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &buffLen);
			if (ret == ERROR_BUFFER_OVERFLOW) {
				free(addresses);
				addresses = NULL;
			}
			else {
				break;
			}
		} while (ret == ERROR_BUFFER_OVERFLOW);

		int i = 0;
		if (ret == NO_ERROR) {
			PIP_ADAPTER_ADDRESSES curAddr = addresses;
			while (curAddr) {
				dump << "Interface " << i << ZT_EOL_S << "-----------" << ZT_EOL_S;
				dump << "Name: " << curAddr->AdapterName << ZT_EOL_S;
				dump << "MTU: " << curAddr->Mtu << ZT_EOL_S;
				dump << "MAC: ";
				char macBuffer[64] = {};
				snprintf(
					macBuffer,
					sizeof(macBuffer),
					"%02x:%02x:%02x:%02x:%02x:%02x",
					curAddr->PhysicalAddress[0],
					curAddr->PhysicalAddress[1],
					curAddr->PhysicalAddress[2],
					curAddr->PhysicalAddress[3],
					curAddr->PhysicalAddress[4],
					curAddr->PhysicalAddress[5]);
				dump << macBuffer << ZT_EOL_S;
				dump << "Type: " << curAddr->IfType << ZT_EOL_S;
				dump << "Addresses:" << ZT_EOL_S;
				PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
				pUnicast = curAddr->FirstUnicastAddress;
				if (pUnicast) {
					for (int j = 0; pUnicast != NULL; ++j) {
						char buf[128] = {};
						DWORD bufLen = 128;
						LPSOCKADDR a = pUnicast->Address.lpSockaddr;
						WSAAddressToStringA(pUnicast->Address.lpSockaddr, pUnicast->Address.iSockaddrLength, NULL, buf, &bufLen);
						dump << buf << ZT_EOL_S;
						pUnicast = pUnicast->Next;
					}
				}

				curAddr = curAddr->Next;
				++i;
			}
		}
		if (addresses) {
			free(addresses);
			addresses = NULL;
		}

		char path[MAX_PATH + 1] = {};
		if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, path) == S_OK) {
			snprintf(path, sizeof(path), "%s%szerotier_dump.txt", path, ZT_PATH_SEPARATOR_S);
			fprintf(stdout, "Writing dump to: %s\n", path);
			HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (file == INVALID_HANDLE_VALUE) {
				fprintf(stdout, "%s", dump.str().c_str());
				return 0;
			}

			BOOL ok = WriteFile(file, dump.str().c_str(), dump.str().size(), NULL, NULL);
			if (ok == FALSE) {
				fprintf(stderr, "Error writing file\n");
				return 1;
			}
			CloseHandle(file);
		}
		else {
			fprintf(stdout, "%s", dump.str().c_str());
		}
#elif defined(__LINUX__)
		struct ifreq ifr;
		struct ifconf ifc;
		char buf[1024];
		char stringBuffer[128];

		int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

		ifc.ifc_len = sizeof(buf);
		ifc.ifc_buf = buf;
		ioctl(sock, SIOCGIFCONF, &ifc);

		struct ifreq* it = ifc.ifc_req;
		const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
		int count = 0;
		for (; it != end; ++it) {
			strcpy(ifr.ifr_name, it->ifr_name);
			if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
				if (! (ifr.ifr_flags & IFF_LOOPBACK)) {	  // skip loopback
					dump << "Interface " << count++ << ZT_EOL_S << "-----------" << ZT_EOL_S;
					dump << "Name: " << ifr.ifr_name << ZT_EOL_S;
					if (ioctl(sock, SIOCGIFMTU, &ifr) == 0) {
						dump << "MTU: " << ifr.ifr_mtu << ZT_EOL_S;
					}
					if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
						unsigned char mac_addr[6];
						memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
						char macStr[18];
						snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
						dump << "MAC: " << macStr << ZT_EOL_S;
					}

					dump << "Addresses: " << ZT_EOL_S;
					struct ifaddrs *ifap, *ifa;
					void* addr;
					getifaddrs(&ifap);
					for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
						if (strcmp(ifr.ifr_name, ifa->ifa_name) == 0 && ifa->ifa_addr != NULL) {
							if (ifa->ifa_addr->sa_family == AF_INET) {
								struct sockaddr_in* ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
								addr = &ipv4->sin_addr;
							}
							else if (ifa->ifa_addr->sa_family == AF_INET6) {
								struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)ifa->ifa_addr;
								addr = &ipv6->sin6_addr;
							}
							else {
								continue;
							}
							inet_ntop(ifa->ifa_addr->sa_family, addr, stringBuffer, sizeof(stringBuffer));
							dump << stringBuffer << ZT_EOL_S;
						}
					}
				}
			}
		}
		close(sock);
		char cwd[16384];
		if (getcwd(cwd, sizeof(cwd)) == nullptr) {
			strcpy(cwd, ".");
		}
		char dumpfile[sizeof(cwd) + 32];
		snprintf(dumpfile, sizeof(dumpfile), "%s%szerotier_dump.txt", cwd, ZT_PATH_SEPARATOR_S);
		fprintf(stdout, "Writing dump to: %s\n", dumpfile);
		int fd = open(dumpfile, O_CREAT | O_WRONLY | O_TRUNC, 0664);
		if (fd == -1) {
			perror("Error creating file");
			return 1;
		}
		const std::string dumpOutput = dump.str();
		const ssize_t written = ::write(fd, dumpOutput.c_str(), dumpOutput.size());
		if (written < 0) {
			perror("Error writing file");
		}
		close(fd);
#else
		fprintf(stderr, "%s", dump.str().c_str());
#endif

		// fprintf(stderr, "%s\n", dump.str().c_str());
	}
	else if (command == "stats") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/stats", requestHeaders, responseHeaders, responseBody);

		if (scode != 200) {
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		}
		catch (std::exception& exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S, scode, command.c_str(), exc.what());
			return 1;
		}
		catch (...) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S, scode, command.c_str());
			return 1;
		}

		if (json) {
			printf("%s" ZT_EOL_S, OSUtils::jsonDump(j).c_str());
			return 0;
		}

		printf("200 stats - Peer Port Usage Statistics" ZT_EOL_S);
		cliStatsPrintDiagnostics(j);
		printf(ZT_EOL_S);
		cliStatsPrintPortConfiguration(j);
		cliStatsPrintNetworkUsage(j);
		cliStatsPrintPeerTable(j);
		return 0;
	}
	else if (command == "findzt" || command == "findztaddr") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli findzt <ip_address>" ZT_EOL_S);
			return 2;
		}

		std::string targetIp = arg1;
		size_t slashPos = targetIp.find('/');
		if (slashPos != std::string::npos) {
			targetIp = targetIp.substr(0, slashPos);
		}

		std::string url = "/overlay/lookup?ip=" + targetIp;
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, url.c_str(), requestHeaders, responseHeaders, responseBody);
		if (scode != 200) {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}

		if (json) {
			printf("%s" ZT_EOL_S, cliFixJsonCRs(responseBody).c_str());
			return 0;
		}

		nlohmann::json result;
		try {
			result = OSUtils::jsonParse(responseBody);
		}
		catch (...) {
			printf("Error parsing response" ZT_EOL_S);
			return 1;
		}
		if (! result.contains("results") || ! result["results"].is_array() || result["results"].empty()) {
			printf("No observed ZeroTier address mapping found for IP %s" ZT_EOL_S, targetIp.c_str());
			return 1;
		}

		for (const auto& row : result["results"]) {
			const std::string ztAddress = OSUtils::jsonString(row["ztAddress"], "");
			const std::string networkId = OSUtils::jsonString(row["networkId"], "");
			if (ztAddress.empty()) {
				continue;
			}
			printf("200 findzt %s %s (network %s, observed)" ZT_EOL_S, targetIp.c_str(), ztAddress.c_str(), networkId.c_str());
		}
		return 0;
	}
	else if (command == "monitor-list") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, "/monitor", requestHeaders, responseHeaders, responseBody);
		if (scode != 200) {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}

		if (json) {
			printf("%s" ZT_EOL_S, cliFixJsonCRs(responseBody).c_str());
			return 0;
		}

		nlohmann::json result = OSUtils::jsonParse(responseBody);
		printf("%-8s %-42s %s" ZT_EOL_S, "Type", "Target", "Log file");
		printf("%-8s %-42s %s" ZT_EOL_S, "--------", "------------------------------------------", "--------");
		if (result.contains("entries") && result["entries"].is_array()) {
			for (const auto& entry : result["entries"]) {
				printf("%-8s %-42s %s" ZT_EOL_S, OSUtils::jsonString(entry["type"], "").c_str(), OSUtils::jsonString(entry["target"], "").c_str(), OSUtils::jsonString(entry["logFile"], "").c_str());
			}
		}
		return 0;
	}
	else if (command == "monitor-add" || command == "monitor-remove") {
		const bool add = (command == "monitor-add");
		if (arg1.empty()) {
			printf("usage: zerotier-cli %s <ip|zt_address|network_id|network_name>" ZT_EOL_S, command.c_str());
			return 2;
		}

		const std::string target = arg1;
		nlohmann::json bodyObj = nlohmann::json::object();
		bodyObj["target"] = target;
		const std::string body = bodyObj.dump();
		const unsigned int scode = Http::POST(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, (add ? "/monitor/add" : "/monitor/remove"), requestHeaders, body.c_str(), (unsigned long)body.size(), responseHeaders, responseBody);

		if (scode != 200) {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}

		printf("%s" ZT_EOL_S, json ? cliFixJsonCRs(responseBody).c_str() : responseBody.c_str());
		return 0;
	}
	else if (command == "findip") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli findip <zt_address>" ZT_EOL_S);
			return 2;
		}

		std::string targetZtAddr = arg1;
		if (targetZtAddr.length() != 10) {
			printf("Invalid ZeroTier address format. Expected 10 hex characters." ZT_EOL_S);
			return 2;
		}
		for (std::string::const_iterator c = targetZtAddr.begin(); c != targetZtAddr.end(); ++c) {
			if (! std::isxdigit(static_cast<unsigned char>(*c))) {
				printf("Invalid ZeroTier address: %s" ZT_EOL_S, targetZtAddr.c_str());
				return 2;
			}
		}
		if (strtoull(targetZtAddr.c_str(), NULL, 16) == 0ULL) {
			printf("Invalid ZeroTier address: %s" ZT_EOL_S, targetZtAddr.c_str());
			return 2;
		}

		std::string url = "/overlay/lookup?zt=" + targetZtAddr;
		const unsigned int scode = Http::GET(1024 * 1024 * 16, 60000, (const struct sockaddr*)&addr, url.c_str(), requestHeaders, responseHeaders, responseBody);
		if (scode != 200) {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}

		if (json) {
			printf("%s" ZT_EOL_S, cliFixJsonCRs(responseBody).c_str());
			return 0;
		}

		nlohmann::json result;
		try {
			result = OSUtils::jsonParse(responseBody);
		}
		catch (...) {
			printf("Error parsing response" ZT_EOL_S);
			return 1;
		}
		if (! result.contains("results") || ! result["results"].is_array() || result["results"].empty()) {
			printf("No observed in-network IP mapping found for ZeroTier address %s" ZT_EOL_S, targetZtAddr.c_str());
			return 1;
		}

		for (const auto& row : result["results"]) {
			const std::string networkId = OSUtils::jsonString(row["networkId"], "");
			if (row.contains("ips") && row["ips"].is_array()) {
				for (const auto& ip : row["ips"]) {
					std::string ipStr = ip.get<std::string>();
					printf("200 findip %s %s (network %s, observed)" ZT_EOL_S, targetZtAddr.c_str(), ipStr.c_str(), networkId.c_str());
				}
			}
		}
		return 0;
	}
	else if (command == "set-api-token") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli set-api-token <token>" ZT_EOL_S);
			printf("" ZT_EOL_S);
			printf("Get your API token from https://my.zerotier.com/account" ZT_EOL_S);
			return 2;
		}

		// Save API token to a secure file
		char tokenPath[1024];
		char configDir[1024];
		char tokenDir[1024];
		snprintf(configDir, sizeof(configDir), "%s/.config", homeDir.c_str());
		snprintf(tokenDir, sizeof(tokenDir), "%s/.config/zerotier", homeDir.c_str());
		snprintf(tokenPath, sizeof(tokenPath), "%s/.config/zerotier/central-api-token", homeDir.c_str());
		(void)OSUtils::mkdir(configDir);
		(void)OSUtils::mkdir(tokenDir);

		if (OSUtils::writeFile(tokenPath, arg1.c_str(), arg1.length())) {
			// Set restrictive permissions (owner read/write only)
#ifdef __WINDOWS__
			_chmod(tokenPath, S_IREAD | S_IWRITE);
#else
			chmod(tokenPath, 0600);
#endif
			printf("200 set-api-token API token saved successfully" ZT_EOL_S);
			printf("Enhanced IP/ZeroTier address lookups are now available" ZT_EOL_S);
			return 0;
		}
		else {
			printf("Error saving API token to %s" ZT_EOL_S, tokenPath);
			return 1;
		}
	}
	else {
		cliPrintHelp(argv[0], stderr);
		return 0;
	}

	return 0;
}

/****************************************************************************/
/* zerotier-idtool personality                                              */
/****************************************************************************/

static void idtoolPrintHelp(FILE* out, const char* pn)
{
	fprintf(out, "%s version %d.%d.%d (%s build)" ZT_EOL_S, PROGRAM_NAME, ZEROTIER_ONE_VERSION_MAJOR, ZEROTIER_ONE_VERSION_MINOR, ZEROTIER_ONE_VERSION_REVISION, nativeBuildMode());
	fprintf(out, COPYRIGHT_NOTICE ZT_EOL_S LICENSE_GRANT ZT_EOL_S);
	fprintf(out, "Usage: %s <command> [<args>]" ZT_EOL_S "" ZT_EOL_S "Commands:" ZT_EOL_S, pn);
	fprintf(out, "  generate [<identity.secret>] [<identity.public>] [<vanity[,vanity...]>] [<threads|auto>] [--prefix-file <file>] [--count <n>] [--estimate] [--timing-file <file>]" ZT_EOL_S);
	fprintf(out, "  validate <identity.secret/public>" ZT_EOL_S);
	fprintf(out, "  getpublic <identity.secret>" ZT_EOL_S);
	fprintf(out, "  sign <identity.secret> <file>" ZT_EOL_S);
	fprintf(out, "  verify <identity.secret/public> <file> <signature>" ZT_EOL_S);
	fprintf(out, "  initmoon <identity.public of first seed>" ZT_EOL_S);
	fprintf(out, "  genmoon <moon json>" ZT_EOL_S);
}

static std::string formatDurationSeconds(double seconds)
{
	if (! (seconds > 0.0) || (! std::isfinite(seconds)))
		return "unknown";
	char tmp[64];
	const unsigned long long total = (unsigned long long)seconds;
	const unsigned long long hours = total / 3600ULL;
	const unsigned long long minutes = (total % 3600ULL) / 60ULL;
	const unsigned long long secs = total % 60ULL;
	if (hours > 0ULL) {
		snprintf(tmp, sizeof(tmp), "%02llu:%02llu:%02llu", (unsigned long long)hours, (unsigned long long)minutes, (unsigned long long)secs);
	}
	else {
		snprintf(tmp, sizeof(tmp), "%02llu:%02llu", (unsigned long long)minutes, (unsigned long long)secs);
	}
	return std::string(tmp);
}

static Identity getIdFromArg(char* arg)
{
	Identity id;
	if ((strlen(arg) > 32) && (arg[10] == ':')) {	// identity is a literal on the command line
		if (id.fromString(arg))
			return id;
	}
	else {	 // identity is to be read from a file
		std::string idser;
		if (OSUtils::readFile(arg, idser)) {
			if (id.fromString(idser.c_str()))
				return id;
		}
	}
	return Identity();
}

static bool parseUnsignedIntArg(const char* s, unsigned int& v)
{
	if ((! s) || (! *s))
		return false;
	unsigned long tmp = 0UL;
	for (const char* p = s; *p; ++p) {
		if ((*p < '0') || (*p > '9'))
			return false;
		tmp = (tmp * 10UL) + (unsigned long)(*p - '0');
		if (tmp > (unsigned long)std::numeric_limits<unsigned int>::max())
			return false;
	}
	v = (unsigned int)tmp;
	return (v > 0U);
}

static std::string trimAsciiWhitespace(const std::string& s)
{
	std::size_t begin = 0;
	while ((begin < s.size()) && ((s[begin] == ' ') || (s[begin] == '\t') || (s[begin] == '\r') || (s[begin] == '\n')))
		++begin;
	std::size_t end = s.size();
	while ((end > begin) && ((s[end - 1] == ' ') || (s[end - 1] == '\t') || (s[end - 1] == '\r') || (s[end - 1] == '\n')))
		--end;
	return s.substr(begin, end - begin);
}

static bool normalizeVanityPrefix(const std::string& raw, std::string& out, std::string& err)
{
	std::string p = trimAsciiWhitespace(raw);
	if (p.empty()) {
		err = "empty vanity prefix";
		return false;
	}
	if (p.size() > ZT_ADDRESS_LENGTH_HEX) {
		err = "vanity prefix '" + p + "' is too long (max 10 hex chars)";
		return false;
	}
	for (std::size_t i = 0; i < p.size(); ++i) {
		const char c = (char)std::tolower((unsigned char)p[i]);
		if (c == '.') {
			p[i] = c;
			continue;
		}
		switch (c) {
			case 'g':
				p[i] = '6';
				continue;
			case 'i':
				p[i] = '1';
				continue;
			case 'o':
				p[i] = '0';
				continue;
			case 's':
				p[i] = '5';
				continue;
			case 't':
				p[i] = '7';
				continue;
			case 'z':
				p[i] = '2';
				continue;
			default:
				break;
		}
		if (((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f'))) {
			p[i] = c;
			continue;
		}
		err = "invalid character in vanity prefix '" + p + "' (allowed: 0-9, a-f, g, i, o, s, t, z, '.')";	 // '.' => any numeric digit
		return false;
	}
	if ((p.size() >= 2) && (p[0] == 'f') && (p[1] == 'f')) {
		err = "vanity prefix '" + p + "' can never match: addresses beginning with ff are reserved";
		return false;
	}
	if ((p.size() == ZT_ADDRESS_LENGTH_HEX) && (p == "0000000000")) {
		err = "vanity prefix '" + p + "' can never match: 0000000000 is the null reserved address";
		return false;
	}
	out = p;
	return true;
}

static bool addVanityPrefixesFromCsv(const std::string& csv, std::set<std::string>& out, std::string& err)
{
	std::size_t start = 0;
	while (start <= csv.size()) {
		std::size_t comma = csv.find(',', start);
		if (comma == std::string::npos)
			comma = csv.size();
		const std::string token = csv.substr(start, comma - start);
		const std::string trimmed = trimAsciiWhitespace(token);
		if (! trimmed.empty()) {
			std::string normalized;
			if (! normalizeVanityPrefix(trimmed, normalized, err))
				return false;
			out.insert(normalized);
		}
		start = comma + 1;
	}
	return true;
}

static bool loadVanityPrefixes(const std::string& csvArg, const std::string& prefixFile, std::vector<std::string>& prefixes, std::string& err)
{
	std::set<std::string> unique;
	unsigned int fileValidCount = 0U;
	unsigned int fileInvalidCount = 0U;
	if (! csvArg.empty()) {
		if (! addVanityPrefixesFromCsv(csvArg, unique, err))
			return false;
	}
	if (! prefixFile.empty()) {
		std::string contents;
		if (! OSUtils::readFile(prefixFile.c_str(), contents)) {
			err = "unable to read prefix file: " + prefixFile;
			return false;
		}
		std::istringstream in(contents);
		std::string line;
		while (std::getline(in, line)) {
			const std::string trimmed = trimAsciiWhitespace(line);
			if (trimmed.empty())
				continue;
			if (trimmed[0] == '#')
				continue;
			std::istringstream lineIn(trimmed);
			std::string token;
			while (lineIn >> token) {
				std::string normalized;
				std::string ignoredErr;
				if (! normalizeVanityPrefix(token, normalized, ignoredErr)) {
					++fileInvalidCount;
					continue;
				}
				++fileValidCount;
				unique.insert(normalized);
			}
		}
		fprintf(stderr, "vanity prefix file: %u valid, %u invalid token(s) (invalid entries ignored)\n", fileValidCount, fileInvalidCount);
	}
	if (unique.empty() && (! csvArg.empty() || ! prefixFile.empty())) {
		err = "no valid vanity prefixes were provided";
		return false;
	}
	prefixes.assign(unique.begin(), unique.end());
	return true;
}

static bool vanityPrefixMatchesAddress(const char* addressHex10, const std::string& prefix)
{
	for (std::size_t i = 0; i < prefix.size(); ++i) {
		const char p = prefix[i];
		const char a = addressHex10[i];
		if (p == '.') {
			if ((a < '0') || (a > '9'))
				return false;
		}
		else if (p != a) {
			return false;
		}
	}
	return true;
}

static bool vanityAddressMatchesAny(const char* addressHex10, const std::vector<std::string>& prefixes, std::string* matchedPrefix)
{
	for (std::size_t i = 0; i < prefixes.size(); ++i) {
		if (vanityPrefixMatchesAddress(addressHex10, prefixes[i])) {
			if (matchedPrefix)
				*matchedPrefix = prefixes[i];
			return true;
		}
	}
	return false;
}

static std::string sanitizePrefixForFilename(const std::string& prefix)
{
	std::string p = prefix;
	for (char& c : p) {
		if (c == '.')
			c = '#';
	}
	return p;
}

static std::string prependPrefixToFilename(const std::string& path, const std::string& prefix)
{
	const std::size_t slash = path.find_last_of("/\\");
	if (slash == std::string::npos)
		return prefix + path;
	return path.substr(0, slash + 1) + prefix + path.substr(slash + 1);
}

static std::string makeUniqueOutputPath(const std::string& path, const std::string& uniqueTag)
{
	if (! OSUtils::fileExists(path.c_str()))
		return path;
	const std::size_t slash = path.find_last_of("/\\");
	const std::size_t dot = path.find_last_of('.');
	const bool dotInBase = (dot != std::string::npos) && ((slash == std::string::npos) || (dot > slash));
	if (dotInBase)
		return path.substr(0, dot) + "-" + uniqueTag + path.substr(dot);
	return path + "-" + uniqueTag;
}

static double vanityPrefixHitProbability(const std::vector<std::string>& prefixes)
{
	double p = 0.0;
	for (const std::string& prefix : prefixes) {
		double term = 1.0;
		for (const char c : prefix)
			term *= (c == '.') ? (10.0 / 16.0) : (1.0 / 16.0);
		p += term;
	}
	if (p > 1.0)
		p = 1.0;
	return p;
}

static std::string formatVanityTimingLogLine(const uint64_t tries, const double elapsedSeconds, const unsigned int threads)
{
	time_t now = time((time_t*)0);
	char ts[64];
	struct tm tmv;
#ifdef _WIN32
	localtime_s(&tmv, &now);
#else
	localtime_r(&now, &tmv);
#endif
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

	std::ostringstream out;
	const uint64_t avgNs = (tries > 0ULL) ? (uint64_t)std::llround((elapsedSeconds * 1000000000.0) / (double)tries) : 0ULL;
	out << ts << " threads=" << threads << " tries=" << tries << " elapsed_s=" << elapsedSeconds << " avg_ns=" << avgNs << " rate_ids_per_sec=" << ((elapsedSeconds > 0.0) ? ((double)tries / elapsedSeconds) : 0.0);
	return out.str();
}

static bool parseTimingLineThreadCount(const std::string& line, unsigned int& threadsOut)
{
	const std::size_t p = line.find("threads=");
	if (p == std::string::npos)
		return false;
	std::size_t i = p + 8;
	if ((i >= line.size()) || (line[i] < '0') || (line[i] > '9'))
		return false;
	unsigned long v = 0UL;
	for (; i < line.size(); ++i) {
		const char c = line[i];
		if ((c < '0') || (c > '9'))
			break;
		v = (v * 10UL) + (unsigned long)(c - '0');
		if (v > (unsigned long)std::numeric_limits<unsigned int>::max())
			return false;
	}
	threadsOut = (unsigned int)v;
	return true;
}

static bool upsertVanityTimingLog(const std::string& filePath, const uint64_t tries, const double elapsedSeconds, const unsigned int threads)
{
	std::vector<std::string> kept;
	std::string existing;
	if (OSUtils::readFile(filePath.c_str(), existing)) {
		std::istringstream in(existing);
		std::string line;
		while (std::getline(in, line)) {
			const std::string trimmed = trimAsciiWhitespace(line);
			if (trimmed.empty())
				continue;
			unsigned int t = 0U;
			if (parseTimingLineThreadCount(trimmed, t) && (t == threads))
				continue;
			kept.push_back(trimmed);
		}
	}
	kept.push_back(formatVanityTimingLogLine(tries, elapsedSeconds, threads));
	std::ostringstream out;
	for (std::size_t i = 0; i < kept.size(); ++i)
		out << kept[i] << "\n";
	return OSUtils::writeFile(filePath.c_str(), out.str());
}

static std::string defaultVanityTimingLogPath()
{
#ifdef __LINUX__
	const char* home = getenv("HOME");
	if (home && home[0]) {
		std::string cacheDir = std::string(home) + "/.cache";
		if (! OSUtils::fileExists(cacheDir.c_str()))
			(void)OSUtils::mkdir(cacheDir);
		std::string ztCacheDir = cacheDir + "/zerotier-idtool";
		if (! OSUtils::fileExists(ztCacheDir.c_str()))
			(void)OSUtils::mkdir(ztCacheDir);
		return ztCacheDir + "/vanity-timing.log";
	}
#endif
	return "idtool-vanity-timing.log";
}

static bool parseTimingLineAvgNs(const std::string& line, uint64_t& avgNsOut)
{
	const std::size_t p = line.find("avg_ns=");
	if (p == std::string::npos)
		return false;
	std::size_t i = p + 7;
	if ((i >= line.size()) || (line[i] < '0') || (line[i] > '9'))
		return false;
	unsigned long long v = 0ULL;
	for (; i < line.size(); ++i) {
		const char c = line[i];
		if ((c < '0') || (c > '9'))
			break;
		v = (v * 10ULL) + (unsigned long long)(c - '0');
	}
	avgNsOut = (uint64_t)v;
	return true;
}

struct TimingProfile {
	unsigned int threads;
	uint64_t avgNs;
};

static std::vector<TimingProfile> loadTimingProfiles(const std::string& filePath)
{
	std::vector<TimingProfile> out;
	std::string existing;
	if (! OSUtils::readFile(filePath.c_str(), existing))
		return out;
	std::map<unsigned int, uint64_t> byThread;
	std::istringstream in(existing);
	std::string line;
	while (std::getline(in, line)) {
		const std::string trimmed = trimAsciiWhitespace(line);
		if (trimmed.empty())
			continue;
		unsigned int t = 0U;
		uint64_t avgNs = 0ULL;
		if ((! parseTimingLineThreadCount(trimmed, t)) || (! parseTimingLineAvgNs(trimmed, avgNs)) || (avgNs == 0ULL))
			continue;
		byThread[t] = avgNs;   // later entry replaces older entry for this thread
	}
	for (std::map<unsigned int, uint64_t>::const_iterator i(byThread.begin()); i != byThread.end(); ++i)
		out.push_back({ i->first, i->second });
	std::sort(out.begin(), out.end(), [](const TimingProfile& a, const TimingProfile& b) {
		if (a.avgNs != b.avgNs)
			return a.avgNs < b.avgNs;
		return a.threads < b.threads;
	});
	return out;
}

#ifdef __WINDOWS__
static int idtool(int argc, _TCHAR* argv[])
#else
static int idtool(int argc, char** argv)
#endif
{
	if (argc < 2) {
		idtoolPrintHelp(stdout, argv[0]);
		return 1;
	}

	if (! strcmp(argv[1], "generate")) {
		unsigned int vanityThreads = 0;
		unsigned int generateCount = 1;
		bool autoThreads = true;
		bool estimateOnly = false;
		std::string timingFileArg(defaultVanityTimingLogPath());
		std::string outSecretArg;
		std::string outPublicArg;
		std::string vanityArg;
		std::string prefixFileArg;
		std::vector<std::string> positional;
		for (int i = 2; i < argc; ++i) {
			if ((! strcmp(argv[i], "--prefix-file")) || (! strcmp(argv[i], "-f"))) {
				if ((i + 1) >= argc) {
					fprintf(stderr, "error: missing value for %s\n", argv[i]);
					return 1;
				}
				prefixFileArg = argv[++i];
				continue;
			}
			if (! strcmp(argv[i], "--count")) {
				if ((i + 1) >= argc) {
					fprintf(stderr, "error: missing value for %s\n", argv[i]);
					return 1;
				}
				if (! parseUnsignedIntArg(argv[i + 1], generateCount)) {
					fprintf(stderr, "error: invalid --count value: %s\n", argv[i + 1]);
					return 1;
				}
				++i;
				continue;
			}
			if (! strcmp(argv[i], "--estimate")) {
				estimateOnly = true;
				continue;
			}
			if (! strcmp(argv[i], "--timing-file")) {
				if ((i + 1) >= argc) {
					fprintf(stderr, "error: missing value for %s\n", argv[i]);
					return 1;
				}
				timingFileArg = argv[++i];
				continue;
			}
			if ((argv[i][0] == '-') && (argv[i][1] == '-')) {
				fprintf(stderr, "error: unrecognized generate option: %s\n", argv[i]);
				return 1;
			}
			positional.push_back(argv[i]);
		}
		if (positional.size() > 4) {
			fprintf(stderr, "error: too many positional generate arguments\n");
			return 1;
		}
		if (positional.size() > 0)
			outSecretArg = positional[0];
		if (positional.size() > 1)
			outPublicArg = positional[1];
		if (positional.size() == 3) {
			unsigned int parsedThreads = 0U;
			if ((! strcmp(positional[2].c_str(), "auto")) || parseUnsignedIntArg(positional[2].c_str(), parsedThreads)) {
				autoThreads = true;
				vanityThreads = 0;
				if (strcmp(positional[2].c_str(), "auto")) {
					autoThreads = false;
					vanityThreads = parsedThreads;
				}
			}
			else {
				vanityArg = positional[2];
			}
		}
		else if (positional.size() > 3) {
			vanityArg = positional[2];
			if (! strcmp(positional[3].c_str(), "auto")) {
				autoThreads = true;
				vanityThreads = 0;
			}
			else {
				unsigned int parsedThreads = 0U;
				if (! parseUnsignedIntArg(positional[3].c_str(), parsedThreads)) {
					fprintf(stderr, "error: invalid thread count: %s\n", positional[3].c_str());
					return 1;
				}
				autoThreads = false;
				vanityThreads = parsedThreads;
			}
		}
		std::vector<std::string> vanityPrefixes;
		std::string prefixLoadErr;
		if (! loadVanityPrefixes(vanityArg, prefixFileArg, vanityPrefixes, prefixLoadErr)) {
			fprintf(stderr, "error: %s\n", prefixLoadErr.c_str());
			return 1;
		}

		struct VanityGenerateResult {
			Identity id;
			std::string matchedPrefix;
			uint64_t tries;
			double elapsedSeconds;
			unsigned int threads;
		};

		bool printedSearchBanner = false;
		auto generateVanityIdentity = [&vanityPrefixes, &autoThreads, &vanityThreads, &timingFileArg, &printedSearchBanner]() -> VanityGenerateResult {
			std::atomic<uint64_t> attempts(0ULL);
			std::atomic<bool> stopFlag(false);
			std::atomic<bool> found(false);
			std::mutex winnerLock;
			Identity winner;
			std::string winnerPrefix;
			const unsigned int hwThreads = std::max(1U, std::thread::hardware_concurrency());
			const double successProbPerTry = vanityPrefixHitProbability(vanityPrefixes);
			const double logFailure = (successProbPerTry > 0.0) ? std::log1p(-successProbPerTry) : 0.0;
			const uint64_t triesFor50pct = (successProbPerTry >= 1.0) ? 1ULL : ((successProbPerTry > 0.0) ? (uint64_t)std::ceil(std::log(0.5) / logFailure) : 0ULL);

			auto launchWorkers = [&attempts, &stopFlag, &found, &winnerLock, &winner, &winnerPrefix, &vanityPrefixes](unsigned int count, std::vector<std::thread>& workers) {
				workers.clear();
				workers.reserve(count);
				for (unsigned int i = 0; i < count; ++i) {
					workers.emplace_back([&attempts, &stopFlag, &found, &winnerLock, &winner, &winnerPrefix, &vanityPrefixes]() {
						Identity local;
						char addrBuf[11];
						while (! stopFlag.load(std::memory_order_relaxed)) {
							local.generate();
							attempts.fetch_add(1ULL, std::memory_order_relaxed);
							local.address().toString(addrBuf);
							std::string matched;
							if (vanityAddressMatchesAny(addrBuf, vanityPrefixes, &matched)) {
								bool expected = false;
								if (found.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
									std::lock_guard<std::mutex> lock(winnerLock);
									winner = local;
									winnerPrefix = matched;
									stopFlag.store(true, std::memory_order_relaxed);
								}
								return;
							}
						}
					});
				}
			};

			const auto start = std::chrono::steady_clock::now();

			if (autoThreads) {
				unsigned int bestT = 1U;
				double bestRate = 0.0;
				const unsigned int maxProbe = std::min(12U, hwThreads);
				double prevRate = -1.0;
				unsigned int dropsInRow = 0U;
				fprintf(stderr, "vanity address: auto-tuning threads (%u..1, 3s each)\n", maxProbe);
				for (unsigned int t = maxProbe; t >= 1; --t) {
					stopFlag.store(false, std::memory_order_relaxed);
					const uint64_t probeStartAttempts = attempts.load(std::memory_order_relaxed);
					std::vector<std::thread> probeWorkers;
					launchWorkers(t, probeWorkers);
					const auto probeStart = std::chrono::steady_clock::now();
					for (int i = 0; i < 30; ++i) {
						if (found.load(std::memory_order_relaxed))
							break;
						std::this_thread::sleep_for(std::chrono::milliseconds(100));
					}
					stopFlag.store(true, std::memory_order_relaxed);
					for (std::thread& th : probeWorkers)
						th.join();
					const double probeElapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - probeStart).count();
					const uint64_t probeAttempts = attempts.load(std::memory_order_relaxed) - probeStartAttempts;
					const double probeRate = (probeElapsed > 0.0) ? ((double)probeAttempts / probeElapsed) : 0.0;
					fprintf(stderr, "vanity address: autotune %u thread(s) => %.2f ids/s\n", t, probeRate);
					if (! upsertVanityTimingLog(timingFileArg, probeAttempts, probeElapsed, t))
						fprintf(stderr, "warning: unable to update vanity timing stats in %s\n", timingFileArg.c_str());
					if (probeRate > bestRate) {
						bestRate = probeRate;
						bestT = t;
					}
					if (found.load(std::memory_order_relaxed)) {
						vanityThreads = t;
						break;
					}
					if (prevRate >= 0.0) {
						if (probeRate < prevRate)
							++dropsInRow;
						else
							dropsInRow = 0U;
						if (dropsInRow >= 2U) {
							fprintf(stderr, "vanity address: autotune stopping early after consecutive throughput drops\n");
							break;
						}
					}
					prevRate = probeRate;
					if (t == 1U)
						break;
				}
				if (! found.load(std::memory_order_relaxed))
					vanityThreads = bestT;
				fprintf(stderr, "vanity address: auto selected %u thread(s)\n", vanityThreads);
				autoThreads = false;
			}
			if (vanityThreads == 0)
				vanityThreads = 1;

			if (! printedSearchBanner) {
				fprintf(stderr, "vanity address: searching for %zu prefix(es) with %u thread(s): ", vanityPrefixes.size(), vanityThreads);
				for (std::size_t i = 0; i < vanityPrefixes.size(); ++i) {
					if (i)
						fprintf(stderr, ",");
					fprintf(stderr, "%s", vanityPrefixes[i].c_str());
				}
				fprintf(stderr, "\n");
				if (triesFor50pct > 0ULL)
					fprintf(stderr, "vanity address: 50%% success chance after ~%llu tries\n", (unsigned long long)triesFor50pct);
				else
					fprintf(stderr, "vanity address: could not estimate 50%% success point (very low/unknown hit probability)\n");
				printedSearchBanner = true;
			}

			unsigned int currentThreads = vanityThreads;
			std::vector<std::thread> workers;
			if (! found.load(std::memory_order_relaxed)) {
				stopFlag.store(false, std::memory_order_relaxed);
				launchWorkers(currentThreads, workers);
			}
			const double statusIntervalSeconds = 5.0;
			auto lastStatus = std::chrono::steady_clock::now();
			uint64_t lastAttempts = attempts.load(std::memory_order_relaxed);
			double bestWindowRate = 0.0;
			struct RateSample {
				std::chrono::steady_clock::time_point ts;
				uint64_t attemptsDelta;
				double elapsedSeconds;
			};
			std::deque<RateSample> rateSamples;
			int lowRateStreak = 0;
#ifdef __LINUX__
			LinuxThermalSample lastThermal = readLinuxThermalSample();
#endif

			while (! found.load(std::memory_order_relaxed)) {
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
				const auto now = std::chrono::steady_clock::now();
				const double statusElapsed = std::chrono::duration<double>(now - lastStatus).count();
				if (statusElapsed < statusIntervalSeconds)
					continue;
				const uint64_t t = attempts.load(std::memory_order_relaxed);
				const uint64_t delta = t - lastAttempts;
				const double rate = (statusElapsed > 0.0) ? ((double)delta / statusElapsed) : 0.0;
				rateSamples.push_back({ now, delta, statusElapsed });
				const auto oldestNeeded = now - std::chrono::seconds(15 * 60);
				while ((! rateSamples.empty()) && (rateSamples.front().ts < oldestNeeded))
					rateSamples.pop_front();
				auto boxcarRate = [&rateSamples, now](double windowSeconds) -> double {
					const auto cutoff = now - std::chrono::duration_cast<std::chrono::steady_clock::duration>(std::chrono::duration<double>(windowSeconds));
					uint64_t sumDelta = 0ULL;
					double sumElapsed = 0.0;
					for (const RateSample& s : rateSamples) {
						if (s.ts >= cutoff) {
							sumDelta += s.attemptsDelta;
							sumElapsed += s.elapsedSeconds;
						}
					}
					return (sumElapsed > 0.0) ? ((double)sumDelta / sumElapsed) : 0.0;
				};
				const double rate1m = boxcarRate(60.0);
				const double rate5m = boxcarRate(300.0);
				const double rate15m = boxcarRate(900.0);
				if (rate > bestWindowRate)
					bestWindowRate = rate;
				const double successProb = (successProbPerTry > 0.0) ? (1.0 - std::exp(logFailure * (double)t)) : 0.0;
				double eta50_1m = 0.0;
				double eta50_5m = 0.0;
				double eta50_15m = 0.0;
				if ((triesFor50pct > 0ULL) && (t < triesFor50pct)) {
					if (rate1m > 0.0)
						eta50_1m = ((double)(triesFor50pct - t) / rate1m);
					if (rate5m > 0.0)
						eta50_5m = ((double)(triesFor50pct - t) / rate5m);
					if (rate15m > 0.0)
						eta50_15m = ((double)(triesFor50pct - t) / rate15m);
				}

#ifdef __LINUX__
				const LinuxThermalSample thermal = readLinuxThermalSample();
				unsigned long long coreThrottleDelta = 0ULL;
				unsigned long long packageThrottleDelta = 0ULL;
				if (lastThermal.coreThrottleCount <= thermal.coreThrottleCount)
					coreThrottleDelta = thermal.coreThrottleCount - lastThermal.coreThrottleCount;
				if (lastThermal.packageThrottleCount <= thermal.packageThrottleCount)
					packageThrottleDelta = thermal.packageThrottleCount - lastThermal.packageThrottleCount;
#endif

				const double runElapsed = std::chrono::duration<double>(now - start).count();
				const bool reached50 = ((triesFor50pct > 0ULL) && (t >= triesFor50pct));
				const std::string eta1 = reached50 ? "--:--" : ((eta50_1m > 0.0) ? formatDurationSeconds(eta50_1m) : "??:??");
				const std::string eta5 = reached50 ? "--:--" : ((eta50_5m > 0.0) ? formatDurationSeconds(eta50_5m) : "??:??");
				const std::string eta15 = reached50 ? "--:--" : ((eta50_15m > 0.0) ? formatDurationSeconds(eta50_15m) : "??:??");
				if (runElapsed < 60.0) {
					fprintf(stderr, "vanity address: %llu tries, %.2f ids/s, success %.2f%%, 50%% ETA(1m) %s", (unsigned long long)t, rate, std::min(100.0, successProb * 100.0), eta1.c_str());
				}
				else if (runElapsed < 300.0) {
					fprintf(stderr, "vanity address: %llu tries, %.2f ids/s, success %.2f%%, 50%% ETA(1m/5m) %s / %s", (unsigned long long)t, rate, std::min(100.0, successProb * 100.0), eta1.c_str(), eta5.c_str());
				}
				else {
					fprintf(stderr, "vanity address: %llu tries, %.2f ids/s, success %.2f%%, 50%% ETA(1m/5m/15m) %s / %s / %s", (unsigned long long)t, rate, std::min(100.0, successProb * 100.0), eta1.c_str(), eta5.c_str(), eta15.c_str());
				}
#ifdef __LINUX__
				if (thermal.freqValid) {
					const double freqPct = thermal.freqRatio * 100.0;
					if (freqPct < 99.5) {
						fprintf(stderr, ", freq %.0f%% of max", freqPct);
					}
				}
				if ((coreThrottleDelta > 0ULL) || (packageThrottleDelta > 0ULL)) {
					fprintf(stderr, ", throttle +%llu core/+%llu pkg", (unsigned long long)coreThrottleDelta, (unsigned long long)packageThrottleDelta);
				}
				lastThermal = thermal;
#endif
				fprintf(stderr, "\n");

				if ((bestWindowRate > 0.0) && (rate < (bestWindowRate * 0.78))) {
					++lowRateStreak;
				}
				else {
					lowRateStreak = 0;
				}

#ifdef __LINUX__
				const bool thermalPressure = ((coreThrottleDelta + packageThrottleDelta) > 0ULL) || (thermal.freqValid && (thermal.freqRatio < 0.80));
#else
				const bool thermalPressure = false;
#endif
				if ((currentThreads > 1U) && (lowRateStreak >= 3) && thermalPressure) {
					const unsigned int newThreads = std::max(1U, currentThreads - 1U);
					fprintf(stderr, "vanity address: throughput degraded under thermal pressure, reducing threads %u -> %u\n", currentThreads, newThreads);
					stopFlag.store(true, std::memory_order_relaxed);
					for (std::thread& th : workers)
						th.join();
					if (! found.load(std::memory_order_relaxed)) {
						stopFlag.store(false, std::memory_order_relaxed);
						currentThreads = newThreads;
						launchWorkers(currentThreads, workers);
						lowRateStreak = 0;
						bestWindowRate = rate;
					}
				}

				lastStatus = now;
				lastAttempts = t;
			}

			for (std::thread& th : workers)
				th.join();

			const uint64_t totalAttempts = attempts.load(std::memory_order_relaxed);
			const double totalElapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
			const double finalRate = (totalElapsed > 0.0) ? ((double)totalAttempts / totalElapsed) : 0.0;
			char foundAddr[11];
			winner.address().toString(foundAddr);
			fprintf(stderr, "vanity address: found %s (prefix %s) after %llu tries in %s (%.2f ids/s)\n", foundAddr, winnerPrefix.c_str(), (unsigned long long)totalAttempts, formatDurationSeconds(totalElapsed).c_str(), finalRate);
			VanityGenerateResult r;
			r.id = winner;
			r.matchedPrefix = winnerPrefix;
			r.tries = totalAttempts;
			r.elapsedSeconds = totalElapsed;
			r.threads = currentThreads;
			return r;
		};

		if (estimateOnly) {
			const double pTry = vanityPrefixes.empty() ? 1.0 : vanityPrefixHitProbability(vanityPrefixes);
			const double logFailure = (pTry > 0.0) ? std::log1p(-pTry) : 0.0;
			const uint64_t tries50 = (pTry >= 1.0) ? 1ULL : ((pTry > 0.0) ? (uint64_t)std::ceil(std::log(0.5) / logFailure) : 0ULL);
			const std::vector<TimingProfile> profiles = loadTimingProfiles(timingFileArg);
			printf("probability_per_try: %.12g" ZT_EOL_S, pTry);
			printf("tries_for_50pct: %llu" ZT_EOL_S, (unsigned long long)tries50);
			if (profiles.empty()) {
				printf("timing_profiles: none (run vanity generation first to collect per-thread timing in %s)" ZT_EOL_S, timingFileArg.c_str());
				printf("estimated_time_for_50pct: unknown" ZT_EOL_S);
				return 0;
			}
			printf("timing_profiles: %zu" ZT_EOL_S, profiles.size());
			for (std::size_t i = 0; i < profiles.size(); ++i) {
				const unsigned int t = profiles[i].threads;
				const double avgNs = (double)profiles[i].avgNs;
				const double estRate = (avgNs > 0.0) ? (1000000000.0 / avgNs) : 0.0;
				printf("threads=%u avg_ns=%llu est_rate_ids_per_sec=%.2f", t, (unsigned long long)profiles[i].avgNs, estRate);
				if ((tries50 > 0ULL) && (estRate > 0.0))
					printf(" est_time_for_50pct=%s", formatDurationSeconds((double)tries50 / estRate).c_str());
				else
					printf(" est_time_for_50pct=unknown");
				printf(ZT_EOL_S);
			}
			return 0;
		}

		for (unsigned int n = 0; n < generateCount; ++n) {
			Identity id;
			if (vanityPrefixes.empty()) {
				id.generate();
			}
			else {
				if (generateCount > 1U)
					fprintf(stderr, "vanity address: generating identity %u/%u\n", n + 1U, generateCount);
				const VanityGenerateResult r = generateVanityIdentity();
				id = r.id;
				if ((r.tries > 0ULL) && (! upsertVanityTimingLog(timingFileArg, r.tries, r.elapsedSeconds, r.threads)))
					fprintf(stderr, "warning: unable to update vanity timing stats in %s\n", timingFileArg.c_str());
			}

			char idtmp[1024];
			std::string idser = id.toString(true, idtmp);
			if (! outSecretArg.empty()) {
				std::string outSecret = outSecretArg;
				std::string outPublic = outPublicArg;
				char addrBuf[11];
				id.address().toString(addrBuf);
				if (generateCount > 1U) {
					const std::string safePrefix = sanitizePrefixForFilename(std::string(addrBuf));
					outSecret = prependPrefixToFilename(outSecret, safePrefix);
					if (! outPublic.empty())
						outPublic = prependPrefixToFilename(outPublic, safePrefix);
				}
				outSecret = makeUniqueOutputPath(outSecret, addrBuf);
				if (! outPublic.empty())
					outPublic = makeUniqueOutputPath(outPublic, addrBuf);
				if (! OSUtils::writeFile(outSecret.c_str(), idser)) {
					fprintf(stderr, "Error writing to %s" ZT_EOL_S, outSecret.c_str());
					return 1;
				}
				else
					printf("%s written" ZT_EOL_S, outSecret.c_str());
				if (! outPublic.empty()) {
					idser = id.toString(false, idtmp);
					if (! OSUtils::writeFile(outPublic.c_str(), idser)) {
						fprintf(stderr, "Error writing to %s" ZT_EOL_S, outPublic.c_str());
						return 1;
					}
					else
						printf("%s written" ZT_EOL_S, outPublic.c_str());
				}
				if (! vanityPrefixes.empty())
					printf("%s" ZT_EOL_S, id.toString(true, idtmp));
			}
			else {
				if (generateCount == 1U)
					printf("%s", idser.c_str());
				else
					printf("%s" ZT_EOL_S, idser.c_str());
			}
		}
	}
	else if (! strcmp(argv[1], "validate")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout, argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (! id) {
			fprintf(stderr, "Identity argument invalid or file unreadable: %s" ZT_EOL_S, argv[2]);
			return 1;
		}

		if (! id.locallyValidate()) {
			fprintf(stderr, "%s FAILED validation." ZT_EOL_S, argv[2]);
			return 1;
		}
		else
			printf("%s is a valid identity" ZT_EOL_S, argv[2]);
	}
	else if (! strcmp(argv[1], "getpublic")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout, argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (! id) {
			fprintf(stderr, "Identity argument invalid or file unreadable: %s" ZT_EOL_S, argv[2]);
			return 1;
		}

		char idtmp[1024];
		printf("%s", id.toString(false, idtmp));
	}
	else if (! strcmp(argv[1], "sign")) {
		if (argc < 4) {
			idtoolPrintHelp(stdout, argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (! id) {
			fprintf(stderr, "Identity argument invalid or file unreadable: %s" ZT_EOL_S, argv[2]);
			return 1;
		}

		if (! id.hasPrivate()) {
			fprintf(stderr, "%s does not contain a private key (must use private to sign)" ZT_EOL_S, argv[2]);
			return 1;
		}

		std::string inf;
		if (! OSUtils::readFile(argv[3], inf)) {
			fprintf(stderr, "%s is not readable" ZT_EOL_S, argv[3]);
			return 1;
		}
		ECC::Signature signature = id.sign(inf.data(), (unsigned int)inf.length());
		char hexbuf[1024];
		printf("%s", Utils::hex(signature.data, ZT_ECC_SIGNATURE_LEN, hexbuf));
	}
	else if (! strcmp(argv[1], "verify")) {
		if (argc < 5) {
			idtoolPrintHelp(stdout, argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (! id) {
			fprintf(stderr, "Identity argument invalid or file unreadable: %s" ZT_EOL_S, argv[2]);
			return 1;
		}

		std::string inf;
		if (! OSUtils::readFile(argv[3], inf)) {
			fprintf(stderr, "%s is not readable" ZT_EOL_S, argv[3]);
			return 1;
		}

		char buf[4096];
		std::string signature(buf, Utils::unhex(argv[4], buf, (unsigned int)sizeof(buf)));
		if ((signature.length() > ZT_ADDRESS_LENGTH) && (id.verify(inf.data(), (unsigned int)inf.length(), signature.data(), (unsigned int)signature.length()))) {
			printf("%s signature valid" ZT_EOL_S, argv[3]);
		}
		else {
			signature.clear();
			if (OSUtils::readFile(argv[4], signature)) {
				signature.assign(buf, Utils::unhex(signature.c_str(), buf, (unsigned int)sizeof(buf)));
				if ((signature.length() > ZT_ADDRESS_LENGTH) && (id.verify(inf.data(), (unsigned int)inf.length(), signature.data(), (unsigned int)signature.length()))) {
					printf("%s signature valid" ZT_EOL_S, argv[3]);
				}
				else {
					fprintf(stderr, "%s signature check FAILED" ZT_EOL_S, argv[3]);
					return 1;
				}
			}
			else {
				fprintf(stderr, "%s signature check FAILED" ZT_EOL_S, argv[3]);
				return 1;
			}
		}
	}
	else if (! strcmp(argv[1], "initmoon")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout, argv[0]);
		}
		else {
			const Identity id = getIdFromArg(argv[2]);
			if (! id) {
				fprintf(stderr, "%s is not a valid identity" ZT_EOL_S, argv[2]);
				return 1;
			}

			ECC::Pair kp(ECC::generate());

			char idtmp[4096];
			nlohmann::json mj;
			mj["objtype"] = "world";
			mj["worldType"] = "moon";
			mj["updatesMustBeSignedBy"] = mj["signingKey"] = Utils::hex(kp.pub.data, ZT_ECC_PUBLIC_KEY_SET_LEN, idtmp);
			mj["signingKey_SECRET"] = Utils::hex(kp.priv.data, ZT_ECC_PRIVATE_KEY_SET_LEN, idtmp);
			mj["id"] = id.address().toString(idtmp);
			nlohmann::json seedj;
			seedj["identity"] = id.toString(false, idtmp);
			seedj["stableEndpoints"] = nlohmann::json::array();
			(mj["roots"] = nlohmann::json::array()).push_back(seedj);
			std::string mjd(OSUtils::jsonDump(mj));

			printf("%s" ZT_EOL_S, mjd.c_str());
		}
	}
	else if (! strcmp(argv[1], "genmoon")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout, argv[0]);
		}
		else {
			std::string buf;
			if (! OSUtils::readFile(argv[2], buf)) {
				fprintf(stderr, "cannot read %s" ZT_EOL_S, argv[2]);
				return 1;
			}
			nlohmann::json mj(OSUtils::jsonParse(buf));

			const uint64_t id = Utils::hexStrToU64(OSUtils::jsonString(mj["id"], "0").c_str());
			if (! id) {
				fprintf(stderr, "ID in %s is invalid" ZT_EOL_S, argv[2]);
				return 1;
			}

			World::Type t;
			if (mj["worldType"] == "moon") {
				t = World::TYPE_MOON;
			}
			else if (mj["worldType"] == "planet") {
				t = World::TYPE_PLANET;
			}
			else {
				fprintf(stderr, "invalid worldType" ZT_EOL_S);
				return 1;
			}

			ECC::Pair signingKey;
			ECC::Public updatesMustBeSignedBy;
			Utils::unhex(OSUtils::jsonString(mj["signingKey"], "").c_str(), signingKey.pub.data, ZT_ECC_PUBLIC_KEY_SET_LEN);
			Utils::unhex(OSUtils::jsonString(mj["signingKey_SECRET"], "").c_str(), signingKey.priv.data, ZT_ECC_PRIVATE_KEY_SET_LEN);
			Utils::unhex(OSUtils::jsonString(mj["updatesMustBeSignedBy"], "").c_str(), updatesMustBeSignedBy.data, ZT_ECC_PUBLIC_KEY_SET_LEN);

			std::vector<World::Root> roots;
			nlohmann::json& rootsj = mj["roots"];
			if (rootsj.is_array()) {
				for (unsigned long i = 0; i < (unsigned long)rootsj.size(); ++i) {
					nlohmann::json& r = rootsj[i];
					if (r.is_object()) {
						roots.push_back(World::Root());
						roots.back().identity = Identity(OSUtils::jsonString(r["identity"], "").c_str());
						nlohmann::json& stableEndpointsj = r["stableEndpoints"];
						if (stableEndpointsj.is_array()) {
							for (unsigned long k = 0; k < (unsigned long)stableEndpointsj.size(); ++k)
								roots.back().stableEndpoints.push_back(InetAddress(OSUtils::jsonString(stableEndpointsj[k], "").c_str()));
							std::sort(roots.back().stableEndpoints.begin(), roots.back().stableEndpoints.end());
						}
					}
				}
			}
			std::sort(roots.begin(), roots.end());

			const int64_t now = OSUtils::now();
			World w(World::make(t, id, now, updatesMustBeSignedBy, roots, signingKey));
			Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> wbuf;
			w.serialize(wbuf);
			char fn[128];
			OSUtils::ztsnprintf(fn, sizeof(fn), "%.16llx.moon", w.id());
			OSUtils::writeFile(fn, wbuf.data(), wbuf.size());
			printf("wrote %s (signed world with timestamp %llu)" ZT_EOL_S, fn, (unsigned long long)now);
		}
	}
	else {
		idtoolPrintHelp(stdout, argv[0]);
		return 1;
	}

	return 0;
}

/****************************************************************************/
/* Unix helper functions and signal handlers                                */
/****************************************************************************/

#ifdef __UNIX_LIKE__
static void _sighandlerHup(int sig)
{
}
static void _sighandlerReallyQuit(int sig)
{
	exit(0);
}
static void _sighandlerQuit(int sig)
{
	alarm(5);	// force exit after 5s
	OneService* s = zt1Service;
	if (s)
		s->terminate();
	else
		exit(0);
}
#endif

// Drop privileges on Linux, if supported by libc etc. and "zerotier-one" user exists on system
#if defined(__LINUX__) && ! defined(ZT_NO_CAPABILITIES)
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT			 47
#define PR_CAP_AMBIENT_IS_SET	 1
#define PR_CAP_AMBIENT_RAISE	 2
#define PR_CAP_AMBIENT_LOWER	 3
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#define ZT_LINUX_USER			"zerotier-one"
#define ZT_HAVE_DROP_PRIVILEGES 1
namespace {

// libc doesn't export capset, it is instead located in libcap
// We ignore libcap and call it manually.
struct cap_header_struct {
	__u32 version;
	int pid;
};
struct cap_data_struct {
	__u32 effective;
	__u32 permitted;
	__u32 inheritable;
};
static inline int _zt_capset(cap_header_struct* hdrp, cap_data_struct* datap)
{
	return syscall(SYS_capset, hdrp, datap);
}

static void _notDropping(const char* procName, const std::string& homeDir)
{
	struct stat buf;
	if (lstat(homeDir.c_str(), &buf) < 0) {
		if (buf.st_uid != 0 || buf.st_gid != 0) {
			fprintf(stderr, "%s: FATAL: failed to drop privileges and can't run as root since privileges were previously dropped (home directory not owned by root)" ZT_EOL_S, procName);
			exit(1);
		}
	}
	fprintf(stderr, "%s: WARNING: failed to drop privileges (kernel may not support required prctl features), running as root" ZT_EOL_S, procName);
}

static int _setCapabilities(int flags)
{
	cap_header_struct capheader = { _LINUX_CAPABILITY_VERSION_1, 0 };
	cap_data_struct capdata;
	capdata.inheritable = capdata.permitted = capdata.effective = flags;
	return _zt_capset(&capheader, &capdata);
}

static void _recursiveChown(const char* path, uid_t uid, gid_t gid)
{
	struct dirent* dptr;
	if (lchown(path, uid, gid) != 0) {}
	DIR* d = opendir(path);
	if (! d)
		return;
	for (;;) {
		errno = 0;
		dptr = readdir(d);
		if (! dptr)
			break;
		if ((strcmp(dptr->d_name, ".") != 0) && (strcmp(dptr->d_name, "..") != 0) && (strlen(dptr->d_name) > 0)) {
			std::string p(path);
			p.push_back(ZT_PATH_SEPARATOR);
			p.append(dptr->d_name);
			_recursiveChown(p.c_str(), uid, gid);	// will just fail and return on regular files
		}
	}
	closedir(d);
}

static void dropPrivileges(const char* procName, const std::string& homeDir)
{
	if (getuid() != 0)
		return;

	// dropPrivileges switches to zerotier-one user while retaining CAP_NET_ADMIN
	// and CAP_NET_RAW capabilities.
	struct passwd* targetUser = getpwnam(ZT_LINUX_USER);
	if (! targetUser)
		return;

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_RAW, 0, 0) < 0) {
		// Kernel has no support for ambient capabilities.
		_notDropping(procName, homeDir);
		return;
	}
	if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NOROOT) < 0) {
		_notDropping(procName, homeDir);
		return;
	}

	// Change ownership of our home directory if everything looks good (does nothing if already chown'd)
	_recursiveChown(homeDir.c_str(), targetUser->pw_uid, targetUser->pw_gid);

	if (_setCapabilities((1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW) | (1 << CAP_SETUID) | (1 << CAP_SETGID) | (1 << CAP_NET_BIND_SERVICE)) < 0) {
		_notDropping(procName, homeDir);
		return;
	}

	int oldDumpable = prctl(PR_GET_DUMPABLE);
	if (prctl(PR_SET_DUMPABLE, 0) < 0) {
		// Disable ptracing. Otherwise there is a small window when previous
		// compromised ZeroTier process could ptrace us, when we still have CAP_SETUID.
		// (this is mitigated anyway on most distros by ptrace_scope=1)
		fprintf(stderr, "%s: FATAL: prctl(PR_SET_DUMPABLE) failed while attempting to relinquish root permissions" ZT_EOL_S, procName);
		exit(1);
	}

	// Relinquish root
	if (setgid(targetUser->pw_gid) < 0) {
		perror("setgid");
		exit(1);
	}
	if (setuid(targetUser->pw_uid) < 0) {
		perror("setuid");
		exit(1);
	}

	if (_setCapabilities((1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW) | (1 << CAP_NET_BIND_SERVICE)) < 0) {
		fprintf(stderr, "%s: FATAL: unable to drop capabilities after relinquishing root" ZT_EOL_S, procName);
		exit(1);
	}

	if (prctl(PR_SET_DUMPABLE, oldDumpable) < 0) {
		fprintf(stderr, "%s: FATAL: prctl(PR_SET_DUMPABLE) failed while attempting to relinquish root permissions" ZT_EOL_S, procName);
		exit(1);
	}

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0) < 0) {
		fprintf(stderr, "%s: FATAL: prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_NET_ADMIN) failed while attempting to relinquish root permissions" ZT_EOL_S, procName);
		exit(1);
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW, 0, 0) < 0) {
		fprintf(stderr, "%s: FATAL: prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_NET_RAW) failed while attempting to relinquish root permissions" ZT_EOL_S, procName);
		exit(1);
	}
}

}	// anonymous namespace
#endif	 // __LINUX__

/****************************************************************************/
/* Windows helper functions and signal handlers                             */
/****************************************************************************/

#ifdef __WINDOWS__
// Console signal handler routine to allow CTRL+C to work, mostly for testing
static BOOL WINAPI _winConsoleCtrlHandler(DWORD dwCtrlType)
{
	switch (dwCtrlType) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			OneService* s = zt1Service;
			if (s)
				s->terminate();
			return TRUE;
	}
	return FALSE;
}

// TODO: revisit this with https://support.microsoft.com/en-us/help/947709/how-to-use-the-netsh-advfirewall-firewall-context-instead-of-the-netsh
static void _winPokeAHole()
{
	char myPath[MAX_PATH];
	DWORD ps = GetModuleFileNameA(NULL, myPath, sizeof(myPath));
	if ((ps > 0) && (ps < (DWORD)sizeof(myPath))) {
		STARTUPINFOA startupInfo;
		PROCESS_INFORMATION processInfo;

		startupInfo.cb = sizeof(startupInfo);
		memset(&startupInfo, 0, sizeof(STARTUPINFOA));
		memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
		if (CreateProcessA(
				NULL,
				(LPSTR)(std::string("C:\\Windows\\System32\\netsh.exe advfirewall firewall delete rule name=\"ZeroTier One\" program=\"") + myPath + "\"").c_str(),
				NULL,
				NULL,
				FALSE,
				CREATE_NO_WINDOW,
				NULL,
				NULL,
				&startupInfo,
				&processInfo)) {
			WaitForSingleObject(processInfo.hProcess, INFINITE);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}

		startupInfo.cb = sizeof(startupInfo);
		memset(&startupInfo, 0, sizeof(STARTUPINFOA));
		memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
		if (CreateProcessA(
				NULL,
				(LPSTR)(std::string("C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"ZeroTier One\" dir=in action=allow program=\"") + myPath + "\" enable=yes").c_str(),
				NULL,
				NULL,
				FALSE,
				CREATE_NO_WINDOW,
				NULL,
				NULL,
				&startupInfo,
				&processInfo)) {
			WaitForSingleObject(processInfo.hProcess, INFINITE);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}

		startupInfo.cb = sizeof(startupInfo);
		memset(&startupInfo, 0, sizeof(STARTUPINFOA));
		memset(&processInfo, 0, sizeof(PROCESS_INFORMATION));
		if (CreateProcessA(
				NULL,
				(LPSTR)(std::string("C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"ZeroTier One\" dir=out action=allow program=\"") + myPath + "\" enable=yes").c_str(),
				NULL,
				NULL,
				FALSE,
				CREATE_NO_WINDOW,
				NULL,
				NULL,
				&startupInfo,
				&processInfo)) {
			WaitForSingleObject(processInfo.hProcess, INFINITE);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}
	}
}

// Returns true if this is running as the local administrator
static BOOL IsCurrentUserLocalAdministrator(void)
{
	BOOL fReturn = FALSE;
	DWORD dwStatus;
	DWORD dwAccessMask;
	DWORD dwAccessDesired;
	DWORD dwACLSize;
	DWORD dwStructureSize = sizeof(PRIVILEGE_SET);
	PACL pACL = NULL;
	PSID psidAdmin = NULL;

	HANDLE hToken = NULL;
	HANDLE hImpersonationToken = NULL;

	PRIVILEGE_SET ps;
	GENERIC_MAPPING GenericMapping;

	PSECURITY_DESCRIPTOR psdAdmin = NULL;
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;

	const DWORD ACCESS_READ = 1;
	const DWORD ACCESS_WRITE = 2;
	do {
		if (! OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, TRUE, &hToken)) {
			if (GetLastError() != ERROR_NO_TOKEN)
				break;
			if (! OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
				break;
		}
		if (! DuplicateToken(hToken, SecurityImpersonation, &hImpersonationToken))
			break;
		if (! AllocateAndInitializeSid(&SystemSidAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &psidAdmin))
			break;
		psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
		if (psdAdmin == NULL)
			break;
		if (! InitializeSecurityDescriptor(psdAdmin, SECURITY_DESCRIPTOR_REVISION))
			break;
		dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psidAdmin) - sizeof(DWORD);
		pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
		if (pACL == NULL)
			break;
		if (! InitializeAcl(pACL, dwACLSize, ACL_REVISION2))
			break;
		dwAccessMask = ACCESS_READ | ACCESS_WRITE;
		if (! AddAccessAllowedAce(pACL, ACL_REVISION2, dwAccessMask, psidAdmin))
			break;
		if (! SetSecurityDescriptorDacl(psdAdmin, TRUE, pACL, FALSE))
			break;

		SetSecurityDescriptorGroup(psdAdmin, psidAdmin, FALSE);
		SetSecurityDescriptorOwner(psdAdmin, psidAdmin, FALSE);

		if (! IsValidSecurityDescriptor(psdAdmin))
			break;
		dwAccessDesired = ACCESS_READ;

		GenericMapping.GenericRead = ACCESS_READ;
		GenericMapping.GenericWrite = ACCESS_WRITE;
		GenericMapping.GenericExecute = 0;
		GenericMapping.GenericAll = ACCESS_READ | ACCESS_WRITE;

		if (! AccessCheck(psdAdmin, hImpersonationToken, dwAccessDesired, &GenericMapping, &ps, &dwStructureSize, &dwStatus, &fReturn)) {
			fReturn = FALSE;
			break;
		}
	} while (0);

	// Clean up.
	if (pACL)
		LocalFree(pACL);
	if (psdAdmin)
		LocalFree(psdAdmin);
	if (psidAdmin)
		FreeSid(psidAdmin);
	if (hImpersonationToken)
		CloseHandle(hImpersonationToken);
	if (hToken)
		CloseHandle(hToken);

	return fReturn;
}
#endif	 // __WINDOWS__

/****************************************************************************/
/* main() and friends                                                       */
/****************************************************************************/

static void printHelp(const char* cn, FILE* out)
{
	fprintf(out, "%s version %d.%d.%d (%s build)" ZT_EOL_S, PROGRAM_NAME, ZEROTIER_ONE_VERSION_MAJOR, ZEROTIER_ONE_VERSION_MINOR, ZEROTIER_ONE_VERSION_REVISION, nativeBuildMode());
	fprintf(out, COPYRIGHT_NOTICE ZT_EOL_S LICENSE_GRANT ZT_EOL_S);
	fprintf(out, ZT_EOL_S "Usage: %s [-switches] [home directory]" ZT_EOL_S "" ZT_EOL_S, cn);
	fprintf(out, "Available switches:" ZT_EOL_S);
	fprintf(out, "  -h                - Display this help" ZT_EOL_S);
	fprintf(out, "  -v                - Show version" ZT_EOL_S);
	fprintf(out, "  -U                - Skip privilege check and do not attempt to drop privileges" ZT_EOL_S);
	fprintf(out, "  -p<port>          - Port for UDP and TCP/HTTP (default: 9993, 0 for random)" ZT_EOL_S);

#ifdef __UNIX_LIKE__
	fprintf(out, "  -d                - Fork and run as daemon (Unix-ish OSes)" ZT_EOL_S);
#endif	 // __UNIX_LIKE__

#ifdef __WINDOWS__
	fprintf(out, "  -C                - Run from command line instead of as service (Windows)" ZT_EOL_S);
	fprintf(out, "  -I                - Install Windows service (Windows)" ZT_EOL_S);
	fprintf(out, "  -R                - Uninstall Windows service (Windows)" ZT_EOL_S);
	fprintf(out, "  -D                - Remove all instances of Windows tap device (Windows)" ZT_EOL_S);
#endif	 // __WINDOWS__

	fprintf(out, "  -i                - Generate and manage identities (zerotier-idtool)" ZT_EOL_S);
	fprintf(out, "  -q                - Query API (zerotier-cli)" ZT_EOL_S);
}

class _OneServiceRunner {
  public:
	_OneServiceRunner(const char* pn, const std::string& hd, unsigned int p) : progname(pn), returnValue(0), port(p), homeDir(hd)
	{
	}
	void threadMain() throw()
	{
		try {
			for (;;) {
				zt1Service = OneService::newInstance(homeDir.c_str(), port);
				switch (zt1Service->run()) {
					case OneService::ONE_STILL_RUNNING:	  // shouldn't happen, run() won't return until done
					case OneService::ONE_NORMAL_TERMINATION:
						break;
					case OneService::ONE_UNRECOVERABLE_ERROR:
						fprintf(stderr, "%s: fatal error: %s" ZT_EOL_S, progname, zt1Service->fatalErrorMessage().c_str());
						returnValue = 1;
						break;
					case OneService::ONE_IDENTITY_COLLISION: {
						delete zt1Service;
						zt1Service = (OneService*)0;
						std::string oldid;
						OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret").c_str(), oldid);
						if (oldid.length()) {
							OSUtils::writeFile((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret.saved_after_collision").c_str(), oldid);
							OSUtils::rm((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret").c_str());
							OSUtils::rm((homeDir + ZT_PATH_SEPARATOR_S + "identity.public").c_str());
						}
					}
						continue;	// restart!
				}
				break;	 // terminate loop -- normally we don't keep restarting
			}

			delete zt1Service;
			zt1Service = (OneService*)0;
		}
		catch (...) {
			fprintf(stderr, "%s: unexpected exception starting main OneService instance" ZT_EOL_S, progname);
			returnValue = 1;
		}
	}
	const char* progname;
	unsigned int returnValue;
	unsigned int port;
	const std::string& homeDir;
};

#ifdef __WINDOWS__
int __cdecl _tmain(int argc, _TCHAR* argv[])
#else
int main(int argc, char** argv)
#endif
{
#if defined(__LINUX__) && ((! defined(__GLIBC__)) || ((__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 18)))
	// This corrects for systems with abnormally small defaults (musl) and also
	// shrinks the stack on systems with large defaults to save a bit of memory.
	pthread_attr_t tattr;
	pthread_attr_init(&tattr);
	pthread_attr_setstacksize(&tattr, 1048576);
	pthread_setattr_default_np(&tattr);
	pthread_attr_destroy(&tattr);
#endif

#ifdef __UNIX_LIKE__
	signal(SIGHUP, &_sighandlerHup);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGIO, SIG_IGN);
	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, SIG_IGN);
	signal(SIGALRM, &_sighandlerReallyQuit);
	signal(SIGINT, &_sighandlerQuit);
	signal(SIGTERM, &_sighandlerQuit);
	signal(SIGQUIT, &_sighandlerQuit);
	signal(SIGINT, &_sighandlerQuit);

#ifdef ZT_EXTOSDEP
	int extosdepFd1 = -1;
	int extosdepFd2 = -1;
	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] != '-' || argv[i][1] != 'x')
			continue;
		if (sscanf(argv[i] + 2, "%d,%d", &extosdepFd1, &extosdepFd2) == 2)
			break;
		fprintf(stderr, "bad extosdepFd\n");
		return 1;
	}
#endif	 // ZT_EXTOSDEP

	/* Ensure that there are no inherited file descriptors open from a previous
	 * incarnation. This is a hack to ensure that GitHub issue #61 or variants
	 * of it do not return, and should not do anything otherwise bad. */
	{
		int mfd = STDIN_FILENO;
		if (STDOUT_FILENO > mfd)
			mfd = STDOUT_FILENO;
		if (STDERR_FILENO > mfd)
			mfd = STDERR_FILENO;
		for (int f = mfd + 1; f < 1024; ++f) {
#ifdef ZT_EXTOSDEP
			if (f == extosdepFd1 || f == extosdepFd2)
				continue;
#endif	 // ZT_EXTOSDEP
			::close(f);
		}
	}

	bool runAsDaemon = false;
#endif	 // __UNIX_LIKE__

#ifdef __WINDOWS__
	{
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
	}

#ifdef ZT_WIN_RUN_IN_CONSOLE
	bool winRunFromCommandLine = true;
#else
	bool winRunFromCommandLine = false;
#endif
#endif	 // __WINDOWS__

	if ((strstr(argv[0], "zerotier-idtool")) || (strstr(argv[0], "ZEROTIER-IDTOOL")))
		return idtool(argc, argv);
	if ((strstr(argv[0], "zerotier-cli")) || (strstr(argv[0], "ZEROTIER-CLI")))
		return cli(argc, argv);

	std::string homeDir;
	unsigned int port = ZT_DEFAULT_PORT;
	bool skipRootCheck = false;

	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] == '-') {
			switch (argv[i][1]) {
				case 'p':	// port -- for both UDP and TCP, packets and control plane
					port = Utils::strToUInt(argv[i] + 2);
					if (port > 0xffff) {
						printHelp(argv[0], stdout);
						return 1;
					}
					break;

#ifdef __UNIX_LIKE__
				case 'd':	// Run in background as daemon
					runAsDaemon = true;
					break;
#endif	 // __UNIX_LIKE__

				case 'U':
					skipRootCheck = true;
					break;

				case 'v':	// Display version
					printf("%d.%d.%d (%s build)" ZT_EOL_S, ZEROTIER_ONE_VERSION_MAJOR, ZEROTIER_ONE_VERSION_MINOR, ZEROTIER_ONE_VERSION_REVISION, nativeBuildMode());
					return 0;

				case 'i':	// Invoke idtool personality
					if (argv[i][2]) {
						printHelp(argv[0], stdout);
						return 0;
					}
					else
						return idtool(argc - 1, argv + 1);

				case 'q':	// Invoke cli personality
					if (argv[i][2]) {
						printHelp(argv[0], stdout);
						return 0;
					}
					else
						return cli(argc, argv);

#ifdef __WINDOWS__
				case 'C':	// Run from command line instead of as Windows service
					winRunFromCommandLine = true;
					break;

				case 'I': {	  // Install this binary as a Windows service
					if (IsCurrentUserLocalAdministrator() != TRUE) {
						fprintf(stderr, "%s: must be run as a local administrator." ZT_EOL_S, argv[0]);
						return 1;
					}
					std::string ret(InstallService(ZT_SERVICE_NAME, ZT_SERVICE_DISPLAY_NAME, ZT_SERVICE_START_TYPE, ZT_SERVICE_DEPENDENCIES, ZT_SERVICE_ACCOUNT, ZT_SERVICE_PASSWORD));
					if (ret.length()) {
						fprintf(stderr, "%s: unable to install service: %s" ZT_EOL_S, argv[0], ret.c_str());
						return 3;
					}
					return 0;
				} break;

				case 'R': {	  // Uninstall this binary as Windows service
					if (IsCurrentUserLocalAdministrator() != TRUE) {
						fprintf(stderr, "%s: must be run as a local administrator." ZT_EOL_S, argv[0]);
						return 1;
					}
					std::string ret(UninstallService(ZT_SERVICE_NAME));
					if (ret.length()) {
						fprintf(stderr, "%s: unable to uninstall service: %s" ZT_EOL_S, argv[0], ret.c_str());
						return 3;
					}
					return 0;
				} break;

				case 'D': {
					std::string err = WindowsEthernetTap::destroyAllPersistentTapDevices();
					if (err.length() > 0) {
						fprintf(stderr, "%s: unable to uninstall one or more persistent tap devices: %s" ZT_EOL_S, argv[0], err.c_str());
						return 3;
					}
					return 0;
				} break;
#endif	 // __WINDOWS__
#ifdef ZT_EXTOSDEP
				case 'x':
					break;
#endif
				case 'h':
				case '?':
				default:
					printHelp(argv[0], stdout);
					return 0;
			}
		}
		else {
			if (homeDir.length()) {
				printHelp(argv[0], stdout);
				return 0;
			}
			else {
				homeDir = argv[i];
			}
		}
	}

	if (! homeDir.length())
		homeDir = OneService::platformDefaultHomePath();
	if (! homeDir.length()) {
		fprintf(stderr, "%s: no home path specified and no platform default available" ZT_EOL_S, argv[0]);
		return 1;
	}
	else {
		std::vector<std::string> hpsp(OSUtils::split(homeDir.c_str(), ZT_PATH_SEPARATOR_S, "", ""));
		std::string ptmp;
		if (homeDir[0] == ZT_PATH_SEPARATOR)
			ptmp.push_back(ZT_PATH_SEPARATOR);
		for (std::vector<std::string>::iterator pi(hpsp.begin()); pi != hpsp.end(); ++pi) {
			if (ptmp.length() > 0)
				ptmp.push_back(ZT_PATH_SEPARATOR);
			ptmp.append(*pi);
			if ((*pi != ".") && (*pi != "..")) {
				if (! OSUtils::mkdir(ptmp))
					throw std::runtime_error("home path does not exist, and could not create. Please verify local system permissions.");
			}
		}
	}

	// Check and fix permissions on critical files at startup
	try {
		char p[4096];
		OSUtils::ztsnprintf(p, sizeof(p), "%s" ZT_PATH_SEPARATOR_S "identity.secret", homeDir.c_str());
		if (OSUtils::fileExists(p)) {
			OSUtils::lockDownFile(p, false);
		}
	}
	catch (...) {
	}

	try {
		char p[4096];
		OSUtils::ztsnprintf(p, sizeof(p), "%s" ZT_PATH_SEPARATOR_S "authtoken.secret", homeDir.c_str());
		if (OSUtils::fileExists(p)) {
			OSUtils::lockDownFile(p, false);
		}
	}
	catch (...) {
	}

	// This can be removed once the new controller code has been around for many versions
	if (OSUtils::fileExists((homeDir + ZT_PATH_SEPARATOR_S + "controller.db").c_str(), true)) {
		fprintf(stderr, "%s: FATAL: an old controller.db exists in %s -- see instructions in controller/README.md for how to migrate!" ZT_EOL_S, argv[0], homeDir.c_str());
		return 1;
	}

#ifdef __UNIX_LIKE__
#ifndef ZT_ONE_NO_ROOT_CHECK
	if ((! skipRootCheck) && (getuid() != 0)) {
		fprintf(stderr, "%s: must be run as root (uid 0)" ZT_EOL_S, argv[0]);
		return 1;
	}
#endif	 // !ZT_ONE_NO_ROOT_CHECK
	if (runAsDaemon) {
		prometheus::simpleapi::saver.stop();

		long p = (long)fork();
		if (p < 0) {
			fprintf(stderr, "%s: could not fork" ZT_EOL_S, argv[0]);
			return 1;
		}
		else if (p > 0)
			_Exit(0);	// forked
						// else p == 0, so we are daemonized

		prometheus::simpleapi::saver.restart();
	}
#endif	 // __UNIX_LIKE__

#ifdef __WINDOWS__
	// Uninstall legacy tap devices. New devices will automatically be installed and configured
	// when tap instances are created.
	WindowsEthernetTap::destroyAllLegacyPersistentTapDevices();

	if (winRunFromCommandLine) {
		// Running in "interactive" mode (mostly for debugging)
		if (IsCurrentUserLocalAdministrator() != TRUE) {
			if (! skipRootCheck) {
				fprintf(stderr, "%s: must be run as a local administrator." ZT_EOL_S, argv[0]);
				return 1;
			}
		}
		else {
			_winPokeAHole();
		}
		SetConsoleCtrlHandler(&_winConsoleCtrlHandler, TRUE);
		// continues on to ordinary command line execution code below...
	}
	else {
		// Running from service manager
		_winPokeAHole();
		ZeroTierOneService zt1WindowsService;
		if (CServiceBase::Run(zt1WindowsService) == TRUE) {
			return 0;
		}
		else {
			fprintf(stderr, "%s: unable to start service (try -h for help)" ZT_EOL_S, argv[0]);
			return 1;
		}
	}
#endif	 // __WINDOWS__

#ifdef __UNIX_LIKE__
#ifdef ZT_HAVE_DROP_PRIVILEGES
	if (! skipRootCheck)
		dropPrivileges(argv[0], homeDir);
#endif

	std::string pidPath(homeDir + ZT_PATH_SEPARATOR_S + ZT_PID_PATH);
	{
		// Write .pid file to home folder
		FILE* pf = fopen(pidPath.c_str(), "w");
		if (pf) {
			fprintf(pf, "%ld", (long)getpid());
			fclose(pf);
		}
	}
#endif	 // __UNIX_LIKE__

#ifdef ZT_EXTOSDEP
	if (extosdepFd1 < 0) {
		fprintf(stderr, "no extosdepFd specified\n");
		OSUtils::rm(pidPath.c_str());
		return 1;
	}
	ExtOsdep::init(extosdepFd1, extosdepFd2);
#endif

	_OneServiceRunner thr(argv[0], homeDir, port);
	thr.threadMain();
	// Thread::join(Thread::start(&thr));

#ifdef __UNIX_LIKE__
	OSUtils::rm(pidPath.c_str());
#endif

	return thr.returnValue;
}
