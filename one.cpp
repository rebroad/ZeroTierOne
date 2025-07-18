/*
 * Copyright (c)2020 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2026-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#include "node/Constants.hpp"

#ifdef __WINDOWS__
#include <winsock2.h>
#include <windows.h>
#include <tchar.h>
#include <wchar.h>
#include <lmcons.h>
#include <newdev.h>
#include <atlbase.h>
#include <iphlpapi.h>
#include <iomanip>
#include <shlobj.h>
#include "osdep/WindowsEthernetTap.hpp"
#include "windows/ZeroTierOne/ServiceInstaller.h"
#include "windows/ZeroTierOne/ServiceBase.h"
#include "windows/ZeroTierOne/ZeroTierOneService.h"
#else
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <dirent.h>
#include <signal.h>
#ifdef __LINUX__
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#ifndef ZT_NO_CAPABILITIES
#include <linux/capability.h>
#include <linux/securebits.h>
#endif
#endif
#endif

#include <string>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <set> // TODO - need by what?

#include "version.h"
#include "include/ZeroTierOne.h"

#include "node/Identity.hpp"
#include "node/CertificateOfMembership.hpp"
#include "node/Utils.hpp"
#include "node/NetworkController.hpp"
#include "node/Buffer.hpp"
#include "node/World.hpp"

#include "osdep/OSUtils.hpp"
#include "osdep/Http.hpp"
#include "osdep/Thread.hpp"

#include "node/Bond.hpp"

#include "service/OneService.hpp"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

#ifdef __APPLE__
#include <SystemConfiguration/SystemConfiguration.h>
#include <CoreServices/CoreServices.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#endif

#define ZT_PID_PATH "zerotier-one.pid"

using namespace ZeroTier;

static OneService *volatile zt1Service = (OneService *)0;

#define PROGRAM_NAME "ZeroTier One"
#define COPYRIGHT_NOTICE "Copyright (c) 2020 ZeroTier, Inc."
#define LICENSE_GRANT "Licensed under the ZeroTier BSL 1.1 (see LICENSE.txt)"

/****************************************************************************/
/* zerotier-cli personality                                                 */
/****************************************************************************/

// This is getting deprecated soon in favor of the stuff in cli/

static void cliPrintHelp(const char *pn,FILE *out)
{
	fprintf(out,
		"%s version %d.%d.%d build %d (platform %d arch %d)" ZT_EOL_S,
		PROGRAM_NAME,
		ZEROTIER_ONE_VERSION_MAJOR, ZEROTIER_ONE_VERSION_MINOR, ZEROTIER_ONE_VERSION_REVISION, ZEROTIER_ONE_VERSION_BUILD,
		ZT_BUILD_PLATFORM, ZT_BUILD_ARCHITECTURE);
	fprintf(out,
		COPYRIGHT_NOTICE ZT_EOL_S
		LICENSE_GRANT ZT_EOL_S);
	fprintf(out,"Usage: %s [-switches] <command/path> [<args>]" ZT_EOL_S"" ZT_EOL_S,pn);
	fprintf(out,"Available switches:" ZT_EOL_S);
	fprintf(out,"  -h                      - Display this help" ZT_EOL_S);
	fprintf(out,"  -v                      - Show version" ZT_EOL_S);
	fprintf(out,"  -j                      - Display full raw JSON output" ZT_EOL_S);
	fprintf(out,"  -D<path>                - ZeroTier home path for parameter auto-detect" ZT_EOL_S);
	fprintf(out,"  -p<port>                - HTTP port (default: auto)" ZT_EOL_S);
	fprintf(out,"  -T<token>               - Authentication token (default: auto)" ZT_EOL_S);
	fprintf(out,ZT_EOL_S"Available commands:" ZT_EOL_S);
	fprintf(out,"  info                    - Display status info" ZT_EOL_S);
	fprintf(out,"  listpeers               - List all peers" ZT_EOL_S);
	fprintf(out,"  peers                   - List all peers (prettier)" ZT_EOL_S);
	fprintf(out,"  listnetworks            - List all networks" ZT_EOL_S);
	fprintf(out,"  join <network ID>          - Join a network" ZT_EOL_S);
	fprintf(out,"  leave <network ID>         - Leave a network" ZT_EOL_S);
	fprintf(out,"  set <network ID> <setting> - Set a network setting" ZT_EOL_S);
	fprintf(out,"  get <network ID> <setting> - Get a network setting" ZT_EOL_S);
	fprintf(out,"  listmoons               - List moons (federated root sets)" ZT_EOL_S);
	fprintf(out,"  orbit <world ID> <seed> - Join a moon via any member root" ZT_EOL_S);
	fprintf(out,"  deorbit <world ID>      - Leave a moon" ZT_EOL_S);
	fprintf(out,"  set-iptables-enabled <true|false|auto|interface-name> - Manage iptables rules" ZT_EOL_S);
	fprintf(out,"  stats                   - Show peer port usage statistics" ZT_EOL_S);
	fprintf(out,"  stats-by-ip             - Show statistics aggregated by IP address only" ZT_EOL_S); // TODO - test
	fprintf(out,"  health                  - Show system health status" ZT_EOL_S); // TODO - test
	fprintf(out,"  metrics                 - Show system metrics" ZT_EOL_S); // TODO - test
	fprintf(out,"  debug-peer <zt_address> - Show debug information for a peer" ZT_EOL_S); // TODO - test
	fprintf(out,"  debug-lookup <ip>       - Debug IP to ZT address lookup" ZT_EOL_S); // TODO - test
	fprintf(out,"  dump                    - Debug settings dump for support" ZT_EOL_S);
	fprintf(out,"  findztaddr <ip_address> - Find ZeroTier address for given IP" ZT_EOL_S);
	fprintf(out,"  findip <zt_address>     - Find IP address for given ZeroTier address" ZT_EOL_S);
	fprintf(out,"  set-api-token <token>   - Set ZeroTier Central API token for enhanced lookups" ZT_EOL_S);
	fprintf(out,ZT_EOL_S"Available settings:" ZT_EOL_S);
	fprintf(out,"  Settings to use with [get/set] may include property names from " ZT_EOL_S);
	fprintf(out,"  the JSON output of \"zerotier-cli -j listnetworks\". Additionally, " ZT_EOL_S);
	fprintf(out,"  (ip, ip4, ip6, ip6plane, and ip6prefix can be used). For instance:" ZT_EOL_S);
	fprintf(out,"  zerotier-cli get <network ID> ip6plane will return the 6PLANE address" ZT_EOL_S);
	fprintf(out,"  assigned to this node." ZT_EOL_S);
}

static std::string cliFixJsonCRs(const std::string &s)
{
	std::string r;
	for(std::string::const_iterator c(s.begin());c!=s.end();++c) {
		if (*c == '\n')
			r.append(ZT_EOL_S);
		else r.push_back(*c);
	}
	return r;
}

#ifdef __WINDOWS__
static int cli(int argc, _TCHAR* argv[])
#else
static int cli(int argc,char **argv)
#endif
{
	unsigned int port = 0;
	std::string homeDir,command,arg1,arg2,arg3,arg4,authToken;
	std::string ip("127.0.0.1");
	bool json = false;
	for(int i=1;i<argc;++i) {
		if (argv[i][0] == '-') {
			switch(argv[i][1]) {

				case 'q': // ignore -q used to invoke this personality
					if (argv[i][2]) {
						cliPrintHelp(argv[0],stdout);
						return 1;
					}
					break;

				case 'j':
					if (argv[i][2]) {
						cliPrintHelp(argv[0],stdout);
						return 1;
					}
					json = true;
					break;

				case 'p':
					port = Utils::strToUInt(argv[i] + 2);
					if ((port > 0xffff)||(port == 0)) {
						cliPrintHelp(argv[0],stdout);
						return 1;
					}
					break;

				case 'D':
					if (argv[i][2]) {
						homeDir = argv[i] + 2;
					} else {
						cliPrintHelp(argv[0],stdout);
						return 1;
					}
					break;

				case 'H':
					if (argv[i][2]) {
						ip = argv[i] + 2;
					} else {
						cliPrintHelp(argv[0],stdout);
						return 1;
					}
					break;

				case 'T':
					if (argv[i][2]) {
						authToken = argv[i] + 2;
					} else {
						cliPrintHelp(argv[0],stdout);
						return 1;
					}
					break;

				case 'v':
					if (argv[i][2]) {
						cliPrintHelp(argv[0],stdout);
						return 1;
					}
					printf("%d.%d.%d" ZT_EOL_S,ZEROTIER_ONE_VERSION_MAJOR,ZEROTIER_ONE_VERSION_MINOR,ZEROTIER_ONE_VERSION_REVISION);
					return 0;

				case 'h':
				case '?':
				default:
					cliPrintHelp(argv[0],stdout);
					return 0;
			}
		} else {
			if (arg1.length())
				arg2 = argv[i];
			else if (command.length())
				arg1 = argv[i];
			else command = argv[i];
		}
	}
	if (!homeDir.length())
		homeDir = OneService::platformDefaultHomePath();

	// TODO: cleanup this logic
	if ((!port)||(!authToken.length())) {
		if (!homeDir.length()) {
			fprintf(stderr,"%s: missing port or authentication token and no home directory specified to auto-detect" ZT_EOL_S,argv[0]);
			return 2;
		}

		if (!port) {
			std::string portStr;
			OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "zerotier-one.port").c_str(),portStr);
			port = Utils::strToUInt(portStr.c_str());
			if ((port == 0)||(port > 0xffff)) {
				fprintf(stderr,"%s: missing port and zerotier-one.port not found in %s" ZT_EOL_S,argv[0],homeDir.c_str());
				return 2;
			}
		}

		if (!authToken.length()) {
			OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "authtoken.secret").c_str(),authToken);
#ifdef __UNIX_LIKE__
			if (!authToken.length()) {
				const char *hd = getenv("HOME");
				if (hd) {
					char p[4096];
#ifdef __APPLE__
					OSUtils::ztsnprintf(p,sizeof(p),"%s/Library/Application Support/ZeroTier/One/authtoken.secret",hd);
#else
					OSUtils::ztsnprintf(p,sizeof(p),"%s/.zeroTierOneAuthToken",hd);
#endif
					OSUtils::readFile(p,authToken);
				}
			}
#endif
			if (!authToken.length()) {
				fprintf(stderr,"%s: authtoken.secret not found or readable in %s (try again as root)" ZT_EOL_S,argv[0],homeDir.c_str());
				return 2;
			}
		}
	}

	InetAddress addr;
	{
		char addrtmp[256];
		OSUtils::ztsnprintf(addrtmp,sizeof(addrtmp),"%s/%u",ip.c_str(),port);
		addr = InetAddress(addrtmp);
	}

	std::map<std::string,std::string> requestHeaders;
	std::map<std::string,std::string> responseHeaders;
	std::string responseBody;

	requestHeaders["X-ZT1-Auth"] = authToken;

	if ((command.length() > 0)&&(command[0] == '/')) {
		unsigned int scode = Http::GET(
			1024 * 1024 * 16,
			60000,
			(const struct sockaddr *)&addr,
			command.c_str(),
			requestHeaders,
			responseHeaders,
			responseBody);
		if (scode == 200) {
			printf("%s", cliFixJsonCRs(responseBody).c_str());
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if ((command == "info")||(command == "status")) {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/status",requestHeaders,responseHeaders,responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
			} else {
				if (j.is_object()) {
					printf("200 info %s %s %s" ZT_EOL_S,
						OSUtils::jsonString(j["address"],"-").c_str(),
						OSUtils::jsonString(j["version"],"-").c_str(),
						((j["tcpFallbackActive"]) ? "TUNNELED" : ((j["online"]) ? "ONLINE" : "OFFLINE")));
				}
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "listpeers") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/peer",requestHeaders,responseHeaders,responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
			} else {
				printf("200 listpeers <ztaddr> <path> <latency> <version> <role>" ZT_EOL_S);
				if (j.is_array()) {
					for(unsigned long k=0;k<j.size();++k) {
						nlohmann::json &p = j[k];
						std::string bestPath;
						nlohmann::json &paths = p["paths"];
						if (paths.is_array()) {
							for(unsigned long i=0;i<paths.size();++i) {
								nlohmann::json &path = paths[i];
								if (path["preferred"]) {
									char tmp[256];
									std::string addr = path["address"];
									const int64_t now = OSUtils::now();
									int64_t lastSendDiff = (uint64_t)path["lastSend"] ? now - (uint64_t)path["lastSend"] : -1;
									int64_t lastReceiveDiff = (uint64_t)path["lastReceive"] ? now - (uint64_t)path["lastReceive"] : -1;
									OSUtils::ztsnprintf(tmp,sizeof(tmp),"%s;%lld;%lld",addr.c_str(),lastSendDiff,lastReceiveDiff);
									bestPath = tmp;
									break;
								}
							}
						}
						if (bestPath.length() == 0) bestPath = "-";
						char ver[128];
						int64_t vmaj = p["versionMajor"];
						int64_t vmin = p["versionMinor"];
						int64_t vrev = p["versionRev"];
						if (vmaj >= 0) {
							OSUtils::ztsnprintf(ver,sizeof(ver),"%lld.%lld.%lld",vmaj,vmin,vrev);
						} else {
							ver[0] = '-';
							ver[1] = (char)0;
						}
						printf("200 listpeers %s %s %d %s %s" ZT_EOL_S,
							OSUtils::jsonString(p["address"],"-").c_str(),
							bestPath.c_str(),
							(int)OSUtils::jsonInt(p["latency"],0),
							ver,
							OSUtils::jsonString(p["role"],"-").c_str());
					}
				}
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "peers") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/peer",requestHeaders,responseHeaders,responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
			} else {
				bool anyTunneled = false;
				printf("200 peers\n<ztaddr>   <ver>  <role> <lat> <link>   <lastTX> <lastRX> <path>" ZT_EOL_S);
				if (j.is_array()) {
					for(unsigned long k=0;k<j.size();++k) {
						nlohmann::json &p = j[k];
						std::string bestPath;
						nlohmann::json &paths = p["paths"];
						if (p["tunneled"]) {
							anyTunneled = true;
						}
						if (paths.is_array()) {
							for(unsigned long i=0;i<paths.size();++i) {
								nlohmann::json &path = paths[i];
								if (path["preferred"]) {
									char tmp[256];
									std::string addr = path["address"];
									const int64_t now = OSUtils::now();
									int64_t lastSendDiff = (uint64_t)path["lastSend"] ? now - (uint64_t)path["lastSend"] : -1;
									int64_t lastReceiveDiff = (uint64_t)path["lastReceive"] ? now - (uint64_t)path["lastReceive"] : -1;
									OSUtils::ztsnprintf(tmp,sizeof(tmp),"%-8lld %-8lld %s",lastSendDiff,lastReceiveDiff,addr.c_str());
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
							OSUtils::ztsnprintf(ver,sizeof(ver),"%lld.%lld.%lld",vmaj,vmin,vrev);
						} else {
							ver[0] = '-';
							ver[1] = (char)0;
						}
						printf("%s %-6s %-6s %5d %s" ZT_EOL_S,
							OSUtils::jsonString(p["address"],"-").c_str(),
							ver,
							OSUtils::jsonString(p["role"],"-").c_str(),
							(int)OSUtils::jsonInt(p["latency"],0),
							bestPath.c_str());
					}
				}
				if (anyTunneled) {
					printf("NOTE: Currently tunneling through a TCP relay. Ensure that UDP is not blocked.\n");
				}
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "bond") {
		/* zerotier-cli bond <cmd> */
		if (arg1.empty()) {
			printf("(bond) command is missing required arguments" ZT_EOL_S);
			return 2;
		}
		/* zerotier-cli bond list */
		if (arg1 == "list") {
			const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/peer",requestHeaders,responseHeaders,responseBody);
			if (scode == 0) {
				printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
				return 1;
			}
			nlohmann::json j;
			try {
				j = OSUtils::jsonParse(responseBody);
			} catch (std::exception &exc) {
				printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
				return 1;
			} catch ( ... ) {
				printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
				return 1;
			}
			if (scode == 200) {
				if (json) {
					printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
				} else {
					bool bFoundBond = false;
					printf("    <peer>                        <bondtype>     <links>" ZT_EOL_S);
					if (j.is_array()) {
						for(unsigned long k=0;k<j.size();++k) {
							nlohmann::json &p = j[k];
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
								printf("%10s  %32s         %d/%d" ZT_EOL_S,
									OSUtils::jsonString(p ["address"],"-").c_str(),
									policyStr.c_str(),
									numAliveLinks,
									numTotalLinks);
							}
						}
					}
					if (!bFoundBond) {
						printf("      NONE\t\t\t\tNONE\t    NONE       NONE" ZT_EOL_S);
					}
				}
				return 0;
			} else {
				printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
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
			unsigned int scode = Http::POST(
				1024 * 1024 * 16,
				60000,
				(const struct sockaddr *)&addr,
				(std::string("/bond/") + arg1 + "/" + arg2 + "/" + arg3 + "/" + arg4).c_str(),
				requestHeaders,
				"{}",
				2,
				responseHeaders,
				responseBody);
			if (scode == 200) {
				printf("200 setmtu OK" ZT_EOL_S);
				return 0;
			} else {
				printf("%d Failed to set MTU: %s" ZT_EOL_S, scode, responseBody.c_str());
				return 1;
			}
			return 0;
		}
		else if (arg1.length() == 10) {
			if (arg2 == "rotate") { /* zerotier-cli bond <peerId> rotate */
				requestHeaders["Content-Type"] = "application/json";
				requestHeaders["Content-Length"] = "2";
				unsigned int scode = Http::POST(
					1024 * 1024 * 16,
					60000,
					(const struct sockaddr *)&addr,
					(std::string("/bond/") + arg2 + "/" + arg1).c_str(),
					requestHeaders,
					"{}",
					2,
					responseHeaders,
					responseBody);
				if (scode == 200) {
					if (json) {
						printf("%s",cliFixJsonCRs(responseBody).c_str());
					} else {
						printf("200 rotate OK" ZT_EOL_S);
					}
					return 0;
				} else {
					printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
					return 1;
				}
				return 0;
			}
			if (arg2 == "show") {
				//fprintf(stderr, "zerotier-cli bond <peerId> show\n");
				const unsigned int scode = Http::GET(
					1024 * 1024 * 16,60000,
					(const struct sockaddr *)&addr,(std::string("/bond/") + arg2 + "/" + arg1).c_str(),
					requestHeaders,
					responseHeaders,
					responseBody);
				if (scode == 0) {
					printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
					return 1;
				}
				nlohmann::json j;
				try {
					j = OSUtils::jsonParse(responseBody);
				} catch (std::exception &exc) {
					printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
					return 1;
				} catch ( ... ) {
					printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
					return 1;
				}
				if (scode == 200) {
					if (json) {
						printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
					} else {
						int numAliveLinks = OSUtils::jsonInt(j["numAliveLinks"],0);
						int numTotalLinks = OSUtils::jsonInt(j["numTotalLinks"],0);
						printf("Peer                   : %s\n", arg1.c_str());
						printf("Bond                   : %s\n", OSUtils::jsonString(j["bondingPolicyStr"],"-").c_str());
						printf("Link Select Method     : %d\n", (int)OSUtils::jsonInt(j["linkSelectMethod"],0));
						printf("Links                  : %d/%d\n", numAliveLinks, numTotalLinks);
						printf("Failover Interval (ms) : %d\n", (int)OSUtils::jsonInt(j["failoverInterval"],0));
						printf("Up Delay (ms)          : %d\n", (int)OSUtils::jsonInt(j["upDelay"],0));
						printf("Down Delay (ms)        : %d\n", (int)OSUtils::jsonInt(j["downDelay"],0));
						printf("Packets Per Link       : %d\n", (int)OSUtils::jsonInt(j["packetsPerLink"],0));
						nlohmann::json &p = j["paths"];
						if (p.is_array()) {
							printf("\nidx"
							"                  interface"
							"                                  "
							"path               socket             local port\n");
							for(int i=0; i<120; i++) { printf("-"); }
							printf("\n");
							for (int i=0; i<p.size(); i++)
							{
								printf("%2d: %26s %51s %.16llx %12d\n",
									i,
									OSUtils::jsonString(p[i]["ifname"],"-").c_str(),
									OSUtils::jsonString(p[i]["address"],"-").c_str(),
									(unsigned long long)OSUtils::jsonInt(p[i]["localSocket"],0),
									(uint16_t)OSUtils::jsonInt(p[i]["localPort"],0)
									);
							}
							printf("\nidx     lat      pdv    "
							"capacity    qual      "
							"rx_age      tx_age  eligible  bonded   flows\n");
							for(int i=0; i<120; i++) { printf("-"); }
							printf("\n");
							for (int i=0; i<p.size(); i++)
							{
								printf("%2d: %8.2f %8.2f %10d %7.4f %11d %11d %9d %7d %7d\n",
									i,
									OSUtils::jsonDouble(p[i]["latencyMean"], 0),
									OSUtils::jsonDouble(p[i]["latencyVariance"], 0),
									(int)OSUtils::jsonInt(p[i]["givenLinkSpeed"], 0),
									OSUtils::jsonDouble(p[i]["relativeQuality"], 0),
									(int)OSUtils::jsonInt(p[i]["lastInAge"], 0),
									(int)OSUtils::jsonInt(p[i]["lastOutAge"], 0),
									(int)OSUtils::jsonInt(p[i]["eligible"],0),
									(int)OSUtils::jsonInt(p[i]["bonded"],0),
									(int)OSUtils::jsonInt(p[i]["assignedFlowCount"],0));
							}
						}
					}
					return 0;
				} else {
					printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
					return 1;
				}
				return 2;
			}
		}

		/* zerotier-cli bond command was malformed in some way */
		printf("(bond) command is missing required arguments" ZT_EOL_S);
		return 2;
	} else if (command == "listbonds") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/peer",requestHeaders,responseHeaders,responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
			} else {
				bool bFoundBond = false;
				printf("    <peer>                        <bondtype>     <links>" ZT_EOL_S);
				if (j.is_array()) {
					for(unsigned long k=0;k<j.size();++k) {
						nlohmann::json &p = j[k];
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
							printf("%10s  %32s         %d/%d" ZT_EOL_S,
								OSUtils::jsonString(p["address"],"-").c_str(),
								policyStr.c_str(),
								numAliveLinks,
								numTotalLinks);
						}
					}
				}
				if (!bFoundBond) {
					printf("      NONE\t\t\t\tNONE\t    NONE       NONE" ZT_EOL_S);
				}
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "listnetworks") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/network",requestHeaders,responseHeaders,responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
			} else {
				printf("200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <ZT assigned ips>" ZT_EOL_S);
				if (j.is_array()) {
					for(unsigned long i=0;i<j.size();++i) {
						nlohmann::json &n = j[i];
						if (n.is_object()) {
							std::string aa;
							nlohmann::json &assignedAddresses = n["assignedAddresses"];
							if (assignedAddresses.is_array()) {
								for(unsigned long j=0;j<assignedAddresses.size();++j) {
									nlohmann::json &addr = assignedAddresses[j];
									if (addr.is_string()) {
										if (aa.length() > 0) aa.push_back(',');
										aa.append(addr.get<std::string>());
									}
								}
							}
							if (aa.length() == 0) aa = "-";
							const std::string status = OSUtils::jsonString(n["status"],"-");
							printf("200 listnetworks %s %s %s %s %s %s %s" ZT_EOL_S,
								OSUtils::jsonString(n["nwid"],"-").c_str(),
								OSUtils::jsonString(n["name"],"-").c_str(),
								OSUtils::jsonString(n["mac"],"-").c_str(),
								status.c_str(),
								OSUtils::jsonString(n["type"],"-").c_str(),
								OSUtils::jsonString(n["portDeviceName"],"-").c_str(),
								aa.c_str());
							if (OSUtils::jsonBool(n["ssoEnabled"], false)) {
								uint64_t authenticationExpiryTime = n["authenticationExpiryTime"];
								if (status == "AUTHENTICATION_REQUIRED") {
									printf("    AUTH EXPIRED, URL: %s" ZT_EOL_S, OSUtils::jsonString(n["authenticationURL"], "(null)").c_str());
								} else if (status == "OK") {
									int64_t expiresIn = ((int64_t)authenticationExpiryTime - OSUtils::now()) / 1000LL;
									if (expiresIn >= 0) {
										printf("    AUTH OK, expires in: %lld seconds" ZT_EOL_S, expiresIn);
									}
								}
							}
						}
					}
				}
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "join") {
		if (arg1.length() != 16) {
			printf("invalid network id" ZT_EOL_S);
			return 2;
		}
		requestHeaders["Content-Type"] = "application/json";
		requestHeaders["Content-Length"] = "2";
		unsigned int scode = Http::POST(
			1024 * 1024 * 16,
			60000,
			(const struct sockaddr *)&addr,
			(std::string("/network/") + arg1).c_str(),
			requestHeaders,
			"{}",
			2,
			responseHeaders,
			responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s",cliFixJsonCRs(responseBody).c_str());
			} else {
				printf("200 join OK" ZT_EOL_S);
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "leave") {
		if (arg1.length() != 16) {
			printf("invalid network id" ZT_EOL_S);
			return 2;
		}
		unsigned int scode = Http::DEL(
			1024 * 1024 * 16,
			60000,
			(const struct sockaddr *)&addr,
			(std::string("/network/") + arg1).c_str(),
			requestHeaders,
			responseHeaders,
			responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s",cliFixJsonCRs(responseBody).c_str());
			} else {
				printf("200 leave OK" ZT_EOL_S);
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "listmoons") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/moon",requestHeaders,responseHeaders,responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}

		if (scode == 200) {
			printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "orbit") {
		const uint64_t worldId = Utils::hexStrToU64(arg1.c_str());
		const uint64_t seed = Utils::hexStrToU64(arg2.c_str());
		if ((worldId)&&(seed)) {
			char jsons[1024];
			OSUtils::ztsnprintf(jsons,sizeof(jsons),"{\"seed\":\"%s\"}",arg2.c_str());
			char cl[128];
			OSUtils::ztsnprintf(cl,sizeof(cl),"%u",(unsigned int)strlen(jsons));
			requestHeaders["Content-Type"] = "application/json";
			requestHeaders["Content-Length"] = cl;
			unsigned int scode = Http::POST(
				1024 * 1024 * 16,
				60000,
				(const struct sockaddr *)&addr,
				(std::string("/moon/") + arg1).c_str(),
				requestHeaders,
				jsons,
				(unsigned long)strlen(jsons),
				responseHeaders,
				responseBody);
			if (scode == 200) {
				printf("200 orbit OK" ZT_EOL_S);
				return 0;
			} else {
				printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
				return 1;
			}
		}
	} else if (command == "deorbit") {
		unsigned int scode = Http::DEL(
			1024 * 1024 * 16,
			60000,
			(const struct sockaddr *)&addr,
			(std::string("/moon/") + arg1).c_str(),
			requestHeaders,
			responseHeaders,
			responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s",cliFixJsonCRs(responseBody).c_str());
			} else {
				printf("200 deorbit OK" ZT_EOL_S);
			}
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "set") {
		if (arg1.length() != 16) {
			fprintf(stderr,"invalid format: must be a 16-digit (network) ID\n");
			return 2;
		}
		if (!arg2.length()) {
			fprintf(stderr,"invalid format: include a property name to set\n");
			return 2;
		}
		std::size_t eqidx = arg2.find('=');
		if (eqidx != std::string::npos) {
			if ((arg2.substr(0,eqidx) == "allowManaged")||(arg2.substr(0,eqidx) == "allowGlobal")||(arg2.substr(0,eqidx) == "allowDefault")||(arg2.substr(0,eqidx) == "allowDNS")) {
				char jsons[1024];
				OSUtils::ztsnprintf(jsons,sizeof(jsons),"{\"%s\":%s}",
					arg2.substr(0,eqidx).c_str(),
					(((arg2.substr(eqidx,2) == "=t")||(arg2.substr(eqidx,2) == "=1")) ? "true" : "false"));
				char cl[128];
				OSUtils::ztsnprintf(cl,sizeof(cl),"%u",(unsigned int)strlen(jsons));
				requestHeaders["Content-Type"] = "application/json";
				requestHeaders["Content-Length"] = cl;
				unsigned int scode = Http::POST(
					1024 * 1024 * 16,
					60000,
					(const struct sockaddr *)&addr,
					(std::string("/network/") + arg1).c_str(),
					requestHeaders,
					jsons,
					(unsigned long)strlen(jsons),
					responseHeaders,
					responseBody);
				if (scode == 200) {
					printf("%s",cliFixJsonCRs(responseBody).c_str());
					return 0;
				} else {
					printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
					return 1;
				}
			}
		} else {
			cliPrintHelp(argv[0],stderr);
			return 2;
		}
	} else if (command == "get") {
		if (arg1.length() != 16) {
			fprintf(stderr,"invalid format: must be a 16-digit (network) ID\n");
			return 2;
		}
		if (!arg2.length()) {
			fprintf(stderr,"invalid format: include a property name to get\n");
			return 2;
		}
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/network",requestHeaders,responseHeaders,responseBody);
		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}
		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}
		bool bNetworkFound = false;
		if (j.is_array()) {
			for(unsigned long i=0;i<j.size();++i) {
				nlohmann::json &n = j[i];
				if (n.is_object()) {
					if (n["id"] == arg1) {
						bNetworkFound = true;
						std::string aa;
						if (arg2 != "ip" && arg2 != "ip4" && arg2 != "ip6" && arg2 != "ip6plane" && arg2 != "ip6prefix") {
							aa.append(OSUtils::jsonString(n[arg2],"-")); // Standard network property field
							if (aa == "-") {
								printf("error, unknown property name\n");
								break;
							}
							printf("%s\n",aa.c_str());
							break;
						}
						nlohmann::json &assignedAddresses = n["assignedAddresses"];
						if (assignedAddresses.is_array()) {
							int matchingIdxs[ZT_MAX_ZT_ASSIGNED_ADDRESSES];
							int addressCountOfType = 0;
							for (int k = 0; k<std::min(ZT_MAX_ZT_ASSIGNED_ADDRESSES, (int)assignedAddresses.size());++k) {
								nlohmann::json &addr = assignedAddresses[k];
								if ((arg2 == "ip4" && addr.get<std::string>().find('.') != std::string::npos)
									|| ((arg2.find("ip6") == 0) && addr.get<std::string>().find(":") != std::string::npos)
									|| (arg2 == "ip")
									) {
									matchingIdxs[addressCountOfType++] = k;
								}
							}
							for (int k=0; k<addressCountOfType; k++) {
								nlohmann::json &addr = assignedAddresses[matchingIdxs[k]];
								if (!addr.is_string()) {
									continue;
								}
								if (arg2.find("ip6p") == 0) {
									if (arg2 == "ip6plane") {
										if (addr.get<std::string>().find("fc") == 0) {
											aa.append(addr.get<std::string>().substr(0,addr.get<std::string>().find('/')));
											if (k < addressCountOfType-1) aa.append("\n");
										}
									}
									if (arg2 == "ip6prefix") {
										if (addr.get<std::string>().find("fc") == 0) {
											aa.append(addr.get<std::string>().substr(0,addr.get<std::string>().find('/')).substr(0,24));
											if (k < addressCountOfType-1) aa.append("\n");
										}
									}
								}
								else {
									aa.append(addr.get<std::string>().substr(0,addr.get<std::string>().find('/')));
									if (k < addressCountOfType-1) aa.append("\n");
								}
							}
						}
						printf("%s\n",aa.c_str());
					}
				}
			}
		}
		if (!bNetworkFound) {
			fprintf(stderr,"unknown network ID, check that you are a member of the network\n");
		}
		if (scode == 200) {
			return 0;
		} else {
			printf("%u %s %s" ZT_EOL_S,scode,command.c_str(),responseBody.c_str());
			return 1;
		}
	} else if (command == "stats") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/stats",requestHeaders,responseHeaders,responseBody);

		if (scode == 0) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}

		nlohmann::json j;
		try {
			j = OSUtils::jsonParse(responseBody);
		} catch (std::exception &exc) {
			printf("%u %s invalid JSON response (%s)" ZT_EOL_S,scode,command.c_str(),exc.what());
			return 1;
		} catch ( ... ) {
			printf("%u %s invalid JSON response (unknown exception)" ZT_EOL_S,scode,command.c_str());
			return 1;
		}

		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,OSUtils::jsonDump(j).c_str());
			} else {
				printf("200 stats - Peer Port Usage Statistics" ZT_EOL_S);

				// Total peer count is now shown in diagnostics section below

				// Show diagnostic information about lookup table sizes
				if (j.contains("diagnostics")) {
					auto& diag = j["diagnostics"];
					printf("Lookup Table Diagnostics:" ZT_EOL_S);
					printf("  Lookup Table Entries:  %u (ZT+IP combinations)" ZT_EOL_S, (unsigned int)diag.value("peerStatsTableSize", 0));
					printf("    Unique ZT Addresses: %u" ZT_EOL_S, (unsigned int)diag.value("uniqueZTAddresses", 0));
					printf("    Unique IP Addresses: %u" ZT_EOL_S, (unsigned int)diag.value("uniqueIPAddresses", 0));
					// Check if allPeersCount is a string or number and format accordingly
					std::string allPeersStr;
					if (diag.contains("allPeersCount")) {
						if (diag["allPeersCount"].is_string()) {
							allPeersStr = diag["allPeersCount"].get<std::string>();
						} else {
							allPeersStr = std::to_string((unsigned int)diag["allPeersCount"]);
						}
					} else {
						allPeersStr = "unknown";
					}
					printf("  AllPeers (topology):   %s" ZT_EOL_S, allPeersStr.c_str());
					printf("  Port Tracking Entries: %u incoming, %u outgoing" ZT_EOL_S,
						(unsigned int)diag.value("seenIncomingPeerPortsSize", 0),
						(unsigned int)diag.value("seenOutgoingPeerPortsSize", 0));
				}
				printf(ZT_EOL_S);

				// Show port configuration
				if (j.contains("portConfiguration")) {
					auto& portConfig = j["portConfiguration"];
					uint32_t primaryPort = portConfig["primaryPort"];
					uint32_t secondaryPort = portConfig["secondaryPort"];
					uint32_t tertiaryPort = portConfig["tertiaryPort"];
					bool allowSecondaryPort = portConfig["allowSecondaryPort"];

					printf("Port Configuration:" ZT_EOL_S);
					printf("  Primary Port:   %u (always active)" ZT_EOL_S, primaryPort);

					if (allowSecondaryPort && secondaryPort > 0) {
						printf("  Secondary Port: %u (enabled)" ZT_EOL_S, secondaryPort);
					} else if (allowSecondaryPort) {
						printf("  Secondary Port: enabled (dynamic port assignment)" ZT_EOL_S);
					} else {
						printf("  Secondary Port: disabled (use 'allowSecondaryPort' setting to enable)" ZT_EOL_S);
					}

					printf("  Tertiary Port:  %u (always active - NAT traversal & failover)" ZT_EOL_S, tertiaryPort);

					// Show actual bound ports only if they differ from configured ports
					if (portConfig.contains("actualBoundPorts") && portConfig["actualBoundPorts"].is_array()) {
						auto actualPorts = portConfig["actualBoundPorts"];
						std::set<unsigned int> expectedPorts = {primaryPort, tertiaryPort};
						if (allowSecondaryPort && secondaryPort > 0) {
							expectedPorts.insert(secondaryPort);
						}

						std::set<unsigned int> actualPortsSet;
						for (auto& port : actualPorts) {
							actualPortsSet.insert((unsigned int)port);
						}

						// Only show if different from expected
						if (actualPortsSet != expectedPorts) {
							printf("  Actually Bound: ");
							bool first = true;
							for (auto& port : actualPorts) {
								if (!first) printf(", ");
								printf("%u", (unsigned int)port);
								first = false;
							}
							printf(ZT_EOL_S);
						}
					}
					printf(ZT_EOL_S);
				}

				printf("%-10s %-15s %-9s %-9s %-8s %-10s %s" ZT_EOL_S,
					"ZT Address", "IP Address", "RX Bytes", "TX Bytes", "Security", "Last Seen", "Port Usage");
				printf("%-10s %-15s %-9s %-9s %-8s %-10s %s" ZT_EOL_S,
					"----------", "---------------", "---------", "---------", "--------", "----------", "----------");

				// Process per-IP peer data from the /stats endpoint (already sorted by server)
				if (j.contains("peersByZtAddressAndIP") && j["peersByZtAddressAndIP"].is_array()) {
					for (auto& peerData : j["peersByZtAddressAndIP"]) {
						std::string ztaddr = peerData.value("ztAddress", "unknown");
						std::string ipAddress = peerData.value("ipAddress", "-");

						// Truncate IPv6 addresses to 15 characters
						if (ipAddress.length() > 15) {
							ipAddress = ipAddress.substr(0, 15);
						}

						// Get display statistics (higher of IP vs ZT address stats) - these are for enforcement
						uint64_t displayBytesIncoming = peerData.value("displayBytesIncoming", 0ULL);
						uint64_t displayBytesOutgoing = peerData.value("displayBytesOutgoing", 0ULL);
						std::string rxSource = peerData.value("rxSource", "?");
						std::string txSource = peerData.value("txSource", "?");

						// Get attack detection metrics
						uint64_t suspiciousPackets = peerData.value("SuspiciousPacketCount", 0ULL);
						uint64_t attackEvents = peerData.value("AttackEventCount", 0ULL);
						double maxDivergenceRatio = peerData.value("MaxDivergenceRatio", 0.0);
						uint64_t lastAttackDetected = peerData.value("LastAttackDetected", 0ULL);

						// Get last seen timestamps (use authenticated packets for accuracy)
						uint64_t lastSeen = peerData.value("lastIncomingSeen", 0ULL);

						// Format statistics for display
						char rxBytesStr[32], txBytesStr[32], securityStr[16], lastSeenStr[16];

						// Format RX bytes with source indicator ("i" = IP stats, "z" = ZT address stats)
						if (displayBytesIncoming > 1024*1024*1024) {
							snprintf(rxBytesStr, sizeof(rxBytesStr), "%.1fG%s",
								displayBytesIncoming / (1024.0*1024.0*1024.0), rxSource.c_str());
						} else if (displayBytesIncoming > 1024*1024) {
							snprintf(rxBytesStr, sizeof(rxBytesStr), "%.1fM%s",
								displayBytesIncoming / (1024.0*1024.0), rxSource.c_str());
						} else if (displayBytesIncoming > 1024) {
							snprintf(rxBytesStr, sizeof(rxBytesStr), "%.1fK%s",
								displayBytesIncoming / 1024.0, rxSource.c_str());
						} else {
							snprintf(rxBytesStr, sizeof(rxBytesStr), "%llu%s",
								(unsigned long long)displayBytesIncoming, rxSource.c_str());
						}

						// Format TX bytes with source indicator ("i" = IP stats, "z" = ZT address stats)
						if (displayBytesOutgoing > 1024*1024*1024) {
							snprintf(txBytesStr, sizeof(txBytesStr), "%.1fG%s",
								displayBytesOutgoing / (1024.0*1024.0*1024.0), txSource.c_str());
						} else if (displayBytesOutgoing > 1024*1024) {
							snprintf(txBytesStr, sizeof(txBytesStr), "%.1fM%s",
								displayBytesOutgoing / (1024.0*1024.0), txSource.c_str());
						} else if (displayBytesOutgoing > 1024) {
							snprintf(txBytesStr, sizeof(txBytesStr), "%.1fK%s",
								displayBytesOutgoing / 1024.0, txSource.c_str());
						} else {
							snprintf(txBytesStr, sizeof(txBytesStr), "%llu%s",
								(unsigned long long)displayBytesOutgoing, txSource.c_str());
						}

						// Format security status based on attack detection
						if (attackEvents > 0) {
							if (maxDivergenceRatio >= 20.0) {
								strcpy(securityStr, "DANGER");
							} else if (maxDivergenceRatio >= 5.0) {
								strcpy(securityStr, "WARNING");
							} else {
								strcpy(securityStr, "MINOR");
						}
						} else if (suspiciousPackets > 100) {
							strcpy(securityStr, "SUSPECT");
						} else {
							strcpy(securityStr, "OK");
						}

						// Format last seen time
						if (lastSeen == 0) {
							strcpy(lastSeenStr, "never");
						} else {
							uint64_t now = OSUtils::now();
							uint64_t secondsAgo = (now - lastSeen) / 1000;
							if (secondsAgo < 60) {
								snprintf(lastSeenStr, sizeof(lastSeenStr), "%lus", (unsigned long)secondsAgo);
							} else if (secondsAgo < 3600) {
								snprintf(lastSeenStr, sizeof(lastSeenStr), "%lum", (unsigned long)(secondsAgo / 60));
							} else if (secondsAgo < 86400) {
								snprintf(lastSeenStr, sizeof(lastSeenStr), "%luh", (unsigned long)(secondsAgo / 3600));
							} else {
								snprintf(lastSeenStr, sizeof(lastSeenStr), "%lud", (unsigned long)(secondsAgo / 86400));
							}
						}

						// Build port usage string in correct order
						std::string portUsage;
						bool hasAnyTraffic = false;

						// Get port configuration to determine correct order
						uint32_t primaryPort = 9993;   // Default
						uint32_t secondaryPort = 0;
						uint32_t tertiaryPort = 0;

						if (j.contains("portConfiguration")) {
							auto& portConfig = j["portConfiguration"];
							primaryPort = portConfig.value("primaryPort", 9993U);
							secondaryPort = portConfig.value("secondaryPort", 0U);
							tertiaryPort = portConfig.value("tertiaryPort", 0U);
						}

						// Get port data for both tiers
						// TIER 1: Wire-level port usage (all packets at wire level)
						auto wireIncomingPorts = peerData.value("wireIncomingPorts", nlohmann::json::object());
						auto wireOutgoingPorts = peerData.value("wireOutgoingPorts", nlohmann::json::object());

						// TIER 2: Authenticated port usage (cryptographically verified packets only)
						auto authIncomingPorts = peerData.value("authIncomingPorts", nlohmann::json::object());
						auto authOutgoingPorts = peerData.value("authOutgoingPorts", nlohmann::json::object());

						// Fallback to legacy field names for backward compatibility
						if (authIncomingPorts.empty()) {
							authIncomingPorts = peerData.value("incomingPorts", nlohmann::json::object());
						}
						if (authOutgoingPorts.empty()) {
							authOutgoingPorts = peerData.value("outgoingPorts", nlohmann::json::object());
						}

						// Order ports: primary, secondary, tertiary, then any others
						std::vector<std::string> orderedPorts;
						std::set<std::string> usedPorts;

						// Add primary port first (check both tiers)
						std::string primaryStr = std::to_string(primaryPort);
						if (wireIncomingPorts.contains(primaryStr) || wireOutgoingPorts.contains(primaryStr) ||
							authIncomingPorts.contains(primaryStr) || authOutgoingPorts.contains(primaryStr)) {
							orderedPorts.push_back(primaryStr);
							usedPorts.insert(primaryStr);
						}

						// Add secondary port if enabled (check both tiers)
						if (secondaryPort > 0) {
							std::string secondaryStr = std::to_string(secondaryPort);
							if (wireIncomingPorts.contains(secondaryStr) || wireOutgoingPorts.contains(secondaryStr) ||
								authIncomingPorts.contains(secondaryStr) || authOutgoingPorts.contains(secondaryStr)) {
								orderedPorts.push_back(secondaryStr);
								usedPorts.insert(secondaryStr);
							}
						}

						// Add tertiary port (check both tiers)
						if (tertiaryPort > 0) {
							std::string tertiaryStr = std::to_string(tertiaryPort);
							if (wireIncomingPorts.contains(tertiaryStr) || wireOutgoingPorts.contains(tertiaryStr) ||
								authIncomingPorts.contains(tertiaryStr) || authOutgoingPorts.contains(tertiaryStr)) {
								orderedPorts.push_back(tertiaryStr);
								usedPorts.insert(tertiaryStr);
							}
						}

						// Collect other ports (not primary/secondary/tertiary) from both tiers
						std::set<std::string> otherPorts;
						uint64_t otherWireIncoming = 0, otherWireOutgoing = 0;
						uint64_t otherAuthIncoming = 0, otherAuthOutgoing = 0;

						// Wire-level other ports
						for (auto& [port, count] : wireIncomingPorts.items()) {
							if (usedPorts.find(port) == usedPorts.end()) {
								otherPorts.insert(port);
								otherWireIncoming += count.get<uint64_t>();
							}
						}
						for (auto& [port, count] : wireOutgoingPorts.items()) {
							if (usedPorts.find(port) == usedPorts.end()) {
								otherPorts.insert(port);
								otherWireOutgoing += wireOutgoingPorts.value(port, 0ULL);
							}
						}

						// Authenticated other ports
						for (auto& [port, count] : authIncomingPorts.items()) {
							if (usedPorts.find(port) == usedPorts.end()) {
								otherPorts.insert(port);
								otherAuthIncoming += count.get<uint64_t>();
							}
						}
						for (auto& [port, count] : authOutgoingPorts.items()) {
							if (usedPorts.find(port) == usedPorts.end()) {
								otherPorts.insert(port);
								otherAuthOutgoing += authOutgoingPorts.value(port, 0ULL);
							}
						}

						// Add summary for other ports if any exist
						if (!otherPorts.empty()) {
							if (otherPorts.size() == 1) {
								// If only one "other" port, show it explicitly
								orderedPorts.push_back(*otherPorts.begin());
							} else {
								// If multiple "other" ports, show them as a summary
								orderedPorts.push_back("other");
							}
						}

						// Build the display string with two-tier format: port:wire_in/wire_out(auth_in/auth_out)
						bool first = true;
						for (const auto& port : orderedPorts) {
							if (!first) portUsage += ", ";

							if (port == "other") {
								// Special handling for summarized other ports
								uint64_t totalWireIn = otherWireIncoming;
								uint64_t totalWireOut = otherWireOutgoing;
								uint64_t totalAuthIn = otherAuthIncoming;
								uint64_t totalAuthOut = otherAuthOutgoing;

								if (totalAuthIn > 0 || totalAuthOut > 0) {
									portUsage += "other:" + std::to_string(totalWireIn) + "/" + std::to_string(totalWireOut) +
											   "," + std::to_string(totalAuthIn) + "/" + std::to_string(totalAuthOut);
								} else {
									portUsage += "other:" + std::to_string(totalWireIn) + "/" + std::to_string(totalWireOut);
								}
							} else {
								// Normal port display with two-tier format
								uint64_t wireInCount = wireIncomingPorts.value(port, 0ULL);
								uint64_t wireOutCount = wireOutgoingPorts.value(port, 0ULL);
								uint64_t authInCount = authIncomingPorts.value(port, 0ULL);
								uint64_t authOutCount = authOutgoingPorts.value(port, 0ULL);

								if (authInCount > 0 || authOutCount > 0) {
									// Show both wire and auth counts: port:wire_in/wire_out,auth_in/auth_out
									portUsage += port + ":" + std::to_string(wireInCount) + "/" + std::to_string(wireOutCount) +
											   "," + std::to_string(authInCount) + "/" + std::to_string(authOutCount);
								} else {
									// Show only wire counts when no auth traffic: port:wire_in/wire_out
									portUsage += port + ":" + std::to_string(wireInCount) + "/" + std::to_string(wireOutCount);
								}
							}

							first = false;
							hasAnyTraffic = true;
						} // loop through orderedPorts

						if (!hasAnyTraffic) portUsage = "none";

						printf("%-10s %-15s %-9s %-9s %-8s %-10s %s" ZT_EOL_S,
							ztaddr.c_str(), ipAddress.c_str(), rxBytesStr, txBytesStr, securityStr, lastSeenStr, portUsage.c_str());
					} // loop through peersByZtAddressAndIP
				} // if j.contains("peersByZtAddressAndIP
			} // else if json
			return 0;
		} else { // if scode == 200
			printf("%u %s %s" ZT_EOL_S, scode, command.c_str(), responseBody.c_str());
			return 1;
		}
	} else if (command == "dump") {
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
		dump << "zerotier version: " << ZEROTIER_ONE_VERSION_MAJOR << "."
			<< ZEROTIER_ONE_VERSION_MINOR << "." << ZEROTIER_ONE_VERSION_REVISION << ZT_EOL_S << ZT_EOL_S;

		// grab status
		dump << "status" << ZT_EOL_S << "------" << ZT_EOL_S;
		unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/status",requestHeaders,responseHeaders,responseBody);
		if (scode != 200) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}
		dump << responseBody << ZT_EOL_S;

		responseHeaders.clear();
		responseBody = "";

		// grab network list
		dump << ZT_EOL_S << "networks" << ZT_EOL_S << "--------" << ZT_EOL_S;
		scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/network",requestHeaders,responseHeaders,responseBody);
		if (scode != 200) {
			printf("Error connecting to the ZeroTier service: %s\n\nPlease check that the service is running and that TCP port 9993 can be contacted via 127.0.0.1." ZT_EOL_S, responseBody.c_str());
			return 1;
		}
		dump << responseBody << ZT_EOL_S;

		responseHeaders.clear();
		responseBody = "";

		// list peers
		dump << ZT_EOL_S << "peers" << ZT_EOL_S << "-----" << ZT_EOL_S;
		scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/peer",requestHeaders,responseHeaders,responseBody);
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
		for(CFIndex i = 0; i < size; ++i) {
			SCNetworkInterfaceRef iface = (SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaces, i);

			dump << "Interface " << i << ZT_EOL_S << "-----------" << ZT_EOL_S;
			CFStringRef tmp = SCNetworkInterfaceGetBSDName(iface);
			char stringBuffer[512] = {};
			CFStringGetCString(tmp,stringBuffer, sizeof(stringBuffer), kCFStringEncodingUTF8);
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
			void *addr;
			getifaddrs(&ifap);
			for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
				if (strcmp(ifName.c_str(), ifa->ifa_name) == 0) {
					if (ifa->ifa_addr->sa_family == AF_INET) {
						struct sockaddr_in *ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
						addr = &ipv4->sin_addr;
					} else if (ifa->ifa_addr->sa_family == AF_INET6) {
						struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)ifa->ifa_addr;
						addr = &ipv6->sin6_addr;
					} else {
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
		if (FSFindFolder(kUserDomain, kDesktopFolderType, kDontCreateFolder, &fsref) == noErr &&
				FSRefMakePath(&fsref, path, sizeof(path)) == noErr) {

		} else if (getenv("SUDO_USER")) {
			sprintf((char*)path, "/Users/%s/Desktop", getenv("SUDO_USER"));
		} else {
			fprintf(stdout, "%s", dump.str().c_str());
			return 0;
		}

		sprintf((char*)path, "%s%szerotier_dump.txt", (char*)path, ZT_PATH_SEPARATOR_S);

		fprintf(stdout, "Writing dump to: %s\n", path);
		int fd = open((char*)path, O_CREAT|O_RDWR,0664);
		if (fd == -1) {
			fprintf(stderr, "Error creating file.\n");
			return 1;
		}
		write(fd, dump.str().c_str(), dump.str().size());
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
				sprintf(macBuffer, "%02x:%02x:%02x:%02x:%02x:%02x",
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
						WSAAddressToStringA(
							pUnicast->Address.lpSockaddr,
							pUnicast->Address.iSockaddrLength,
							NULL,
							buf,
							&bufLen
						);
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
			sprintf(path, "%s%szerotier_dump.txt", path, ZT_PATH_SEPARATOR_S);
			fprintf(stdout, "Writing dump to: %s\n", path);
			HANDLE file = CreateFileA(
				path,
				GENERIC_WRITE,
				0,
				NULL,
				CREATE_ALWAYS,
				FILE_ATTRIBUTE_NORMAL,
				NULL
			);
			if (file == INVALID_HANDLE_VALUE) {
				fprintf(stdout, "%s", dump.str().c_str());
				return 0;
			}

			BOOL err = WriteFile(
				file,
				dump.str().c_str(),
				dump.str().size(),
				NULL,
				NULL
			);
			if (err = FALSE) {
				fprintf(stderr, "Error writing file");
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

		struct ifreq *it = ifc.ifc_req;
		const struct ifreq * const end = it + (ifc.ifc_len / sizeof(struct ifreq));
		int count = 0;
		for(; it != end; ++it) {
			strcpy(ifr.ifr_name, it->ifr_name);
			if(ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
				if (!(ifr.ifr_flags & IFF_LOOPBACK)) { // skip loopback
					dump << "Interface " << count++ << ZT_EOL_S << "-----------" << ZT_EOL_S;
					dump << "Name: " << ifr.ifr_name << ZT_EOL_S;
					if (ioctl(sock, SIOCGIFMTU, &ifr) == 0) {
						dump << "MTU: " << ifr.ifr_mtu << ZT_EOL_S;
					}
					if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
						unsigned char mac_addr[6];
						memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
						char macStr[18];
						sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",
								mac_addr[0],
								mac_addr[1],
								mac_addr[2],
								mac_addr[3],
								mac_addr[4],
								mac_addr[5]);
						dump << "MAC: " << macStr << ZT_EOL_S;
					}

					dump << "Addresses: " << ZT_EOL_S;
					struct ifaddrs *ifap, *ifa;
					void *addr;
					getifaddrs(&ifap);
					for(ifa = ifap; ifa; ifa = ifa->ifa_next) {
						if(strcmp(ifr.ifr_name, ifa->ifa_name) == 0 && ifa->ifa_addr != NULL) {
							if(ifa->ifa_addr->sa_family == AF_INET) {
								struct sockaddr_in *ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
								addr = &ipv4->sin_addr;
							} else if (ifa->ifa_addr->sa_family == AF_INET6) {
								struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)ifa->ifa_addr;
								addr = &ipv6->sin6_addr;
							} else {
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
		getcwd(cwd, sizeof(cwd));
		sprintf(cwd, "%s%szerotier_dump.txt", cwd, ZT_PATH_SEPARATOR_S);
		fprintf(stdout, "Writing dump to: %s\n", cwd);
		int fd = open(cwd, O_CREAT|O_RDWR,0664);
		if (fd == -1) {
			fprintf(stderr, "Error creating file.\n");
			return 1;
		}
		write(fd, dump.str().c_str(), dump.str().size());
		close(fd);
#else
	fprintf(stderr, "%s", dump.str().c_str());
#endif

		// fprintf(stderr, "%s\n", dump.str().c_str());

	} else if (command == "set-iptables-enabled") {
		if (arg1.length()) {
			nlohmann::json j;
			j["settings"]["iptablesEnabled"] = (arg1 == "true");
			if (arg1 != "true" && arg1 != "false") {
				j["settings"]["iptablesWanInterface"] = arg1;
			}

			requestHeaders["Content-Type"] = "application/json";

			std::string postData = j.dump();
			const unsigned int scode = Http::POST(
				1024 * 1024 * 16,
				60000,
				(const struct sockaddr *)&addr,
				"/iptables",
				requestHeaders,
				postData.data(),
				postData.length(),
				responseHeaders,
				responseBody
			);
			if (scode == 200) {
				printf("200 set-iptables-enabled OK" ZT_EOL_S);
			} else {
				fprintf(stderr, "%u %s" ZT_EOL_S, scode, responseBody.c_str());
				return 1;
			}
		} else {
			cliPrintHelp(argv[0], stdout);
			return 1;
		}
	} else if (command == "findztaddr") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli findztaddr <ip_address>" ZT_EOL_S);
			return 2;
		}

		// Parse the target IP address
		std::string targetIp = arg1;
		size_t slashPos = targetIp.find('/');
		if (slashPos != std::string::npos) {
			targetIp = targetIp.substr(0, slashPos); // Remove CIDR suffix if present
		}

		// Get network list to find which networks we're on
		const unsigned int netscode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/network",requestHeaders,responseHeaders,responseBody);
		if (netscode != 200) {
			printf("Error getting network list: %u %s" ZT_EOL_S, netscode, responseBody.c_str());
			return 1;
		}

		nlohmann::json networks;
		try {
			networks = OSUtils::jsonParse(responseBody);
		} catch (...) {
			printf("Error parsing network JSON" ZT_EOL_S);
			return 1;
		}

		std::string foundNetwork;
		bool ipInOurNetwork = false;

		// Check if the target IP is in any of our networks
		if (networks.is_array()) {
			for (unsigned long i = 0; i < networks.size(); ++i) {
				nlohmann::json &network = networks[i];
				std::string nwid = OSUtils::jsonString(network["id"], "");
				nlohmann::json &routes = network["routes"];

				if (routes.is_array()) {
					for (unsigned long j = 0; j < routes.size(); ++j) {
						nlohmann::json &route = routes[j];
						std::string target = OSUtils::jsonString(route["target"], "");

						// Simple check if IP is in network range
						if (!target.empty()) {
							size_t slashPos = target.find('/');
							if (slashPos != std::string::npos) {
								std::string networkBase = target.substr(0, slashPos);
								// Basic prefix matching for demonstration
								if (targetIp.find(networkBase.substr(0, networkBase.rfind('.'))) == 0) {
									foundNetwork = nwid;
									ipInOurNetwork = true;
									break;
								}
							}
						}
					}
				}
				if (ipInOurNetwork) break;
			}
		}

		if (!ipInOurNetwork) {
			printf("IP %s does not appear to be in any of your ZeroTier networks" ZT_EOL_S, targetIp.c_str());
			return 1;
		}

				// Check if this is our own IP first
		for (unsigned long i = 0; i < networks.size(); ++i) {
			nlohmann::json &network = networks[i];
			nlohmann::json &assignedAddresses = network["assignedAddresses"];

			if (assignedAddresses.is_array()) {
				for (unsigned long j = 0; j < assignedAddresses.size(); ++j) {
					std::string assignedIp = assignedAddresses[j];
					size_t slashPos = assignedIp.find('/');
					if (slashPos != std::string::npos) {
						assignedIp = assignedIp.substr(0, slashPos);
					}

					if (assignedIp == targetIp) {
						// This IP belongs to our local node
						const unsigned int statuscode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/status",requestHeaders,responseHeaders,responseBody);
						if (statuscode == 200) {
							nlohmann::json status = OSUtils::jsonParse(responseBody);
							std::string ourAddress = OSUtils::jsonString(status["address"], "");
							printf("200 findip %s %s (local)" ZT_EOL_S, targetIp.c_str(), ourAddress.c_str());
							return 0;
						}
					}
				}
			}
		}

		// For remote peers, try to resolve by triggering ARP and checking system ARP cache
		printf("Searching for ZeroTier address for IP %s..." ZT_EOL_S, targetIp.c_str());

		// First try ZeroTier Central API if we have an API token
		std::string apiToken;
		char tokenPath[1024];
		snprintf(tokenPath, sizeof(tokenPath), "%s/central-api-token", homeDir.c_str());
		std::string tokenData;
		if (OSUtils::readFile(tokenPath, tokenData)) {
			// Remove any whitespace/newlines
			size_t pos = tokenData.find_first_of(" \t\r\n");
			if (pos != std::string::npos) {
				apiToken = tokenData.substr(0, pos);
			} else {
				apiToken = tokenData;
			}
		}

		// First, determine which network this IP belongs to
		std::string targetNetworkId;
		std::string targetInterface;
		for (unsigned long i = 0; i < networks.size(); ++i) {
			nlohmann::json &network = networks[i];
			nlohmann::json &routes = network["routes"];

			if (routes.is_array()) {
				for (unsigned long j = 0; j < routes.size(); ++j) {
					nlohmann::json &route = routes[j];
					std::string target = OSUtils::jsonString(route["target"], "");

					if (!target.empty() && target.find('/') != std::string::npos) {
						// Parse network CIDR (e.g., "192.168.192.0/24")
						std::string networkBase = target.substr(0, target.find('/'));
						std::string maskStr = target.substr(target.find('/') + 1);
						int maskBits = atoi(maskStr.c_str());

						// Convert IP strings to integers for subnet matching
						uint32_t targetIpInt = 0, networkInt = 0;
						inet_pton(AF_INET, targetIp.c_str(), &targetIpInt);
						inet_pton(AF_INET, networkBase.c_str(), &networkInt);

						// Create subnet mask
						uint32_t mask = (maskBits == 0) ? 0 : (~0U << (32 - maskBits));

						// Check if target IP is in this subnet
						if ((ntohl(targetIpInt) & mask) == (ntohl(networkInt) & mask)) {
							targetNetworkId = OSUtils::jsonString(network["id"], "");
							targetInterface = OSUtils::jsonString(network["portDeviceName"], "");
							break;
						}
					}
				}
				if (!targetNetworkId.empty()) break;
			}
		}

		if (targetNetworkId.empty()) {
			printf("Could not determine which ZeroTier network contains this IP" ZT_EOL_S);
			return 1;
		}

		printf("Found IP in network %s (interface %s)" ZT_EOL_S, targetNetworkId.c_str(), targetInterface.c_str());

		// If we have an API token, try the Central API first
		if (!apiToken.empty()) {
			printf("Querying ZeroTier Central API..." ZT_EOL_S);

			// Query Central API for network members
			std::string centralUrl = "https://api.zerotier.com/api/v1/network/" + targetNetworkId + "/member";
			std::string curlCmd = "curl -s -H 'Authorization: token " + apiToken + "' '" + centralUrl + "'";

			FILE* curlPipe = popen(curlCmd.c_str(), "r");
			if (curlPipe) {
				std::string apiResponse;
				char buffer[4096];
				while (fgets(buffer, sizeof(buffer), curlPipe)) {
					apiResponse += buffer;
				}
				pclose(curlPipe);

				try {
					nlohmann::json members = OSUtils::jsonParse(apiResponse);
					if (members.is_array()) {
						for (unsigned long j = 0; j < members.size(); ++j) {
							nlohmann::json &member = members[j];
							nlohmann::json &ipAssignments = member["config"]["ipAssignments"];

							if (ipAssignments.is_array()) {
								for (unsigned long k = 0; k < ipAssignments.size(); ++k) {
									std::string assignedIp = ipAssignments[k];
									size_t slashPos = assignedIp.find('/');
									if (slashPos != std::string::npos) {
										assignedIp = assignedIp.substr(0, slashPos);
									}

									if (assignedIp == targetIp) {
										std::string memberId = OSUtils::jsonString(member["nodeId"], "");
										printf("200 findztaddr %s %s (network %s, via Central API)" ZT_EOL_S,
											   targetIp.c_str(), memberId.c_str(), targetNetworkId.c_str());
										return 0;
									}
								}
							}
						}
					}
				} catch (...) {
					// API query failed, fall back to ARP method
				}
			}

			printf("IP not found via Central API, falling back to ARP method..." ZT_EOL_S);
		}

		// Trigger ARP resolution by sending a ping
		printf("Triggering ARP resolution..." ZT_EOL_S);
		std::string pingCmd = "ping -c 1 -W 1 " + targetIp + " >/dev/null 2>&1";
		(void)system(pingCmd.c_str());

		// Small delay to allow ARP cache to populate
		usleep(100000); // 100ms

		// Now check ARP cache for the MAC address
		std::string arpCmd = "ip neigh show " + targetIp + " 2>/dev/null | awk '{print $5}' | head -1";
		FILE* arpPipe = popen(arpCmd.c_str(), "r");
		if (!arpPipe) {
			printf("Failed to check ARP cache" ZT_EOL_S);
			return 1;
		}

		char macBuffer[32] = {0};
		if (fgets(macBuffer, sizeof(macBuffer), arpPipe)) {
			// Remove trailing newline
			char* newline = strchr(macBuffer, '\n');
			if (newline) *newline = '\0';

			// Parse MAC address and convert to ZeroTier address
			if (strlen(macBuffer) >= 17) { // MAC format: XX:XX:XX:XX:XX:XX
				uint64_t macInt = 0;
				unsigned int macBytes[6];
				if (sscanf(macBuffer, "%02x:%02x:%02x:%02x:%02x:%02x",
						   &macBytes[0], &macBytes[1], &macBytes[2],
						   &macBytes[3], &macBytes[4], &macBytes[5]) == 6) {

					// Convert to 64-bit MAC
					for (int i = 0; i < 6; i++) {
						macInt = (macInt << 8) | (macBytes[i] & 0xFF);
					}

					// Convert network ID string to uint64_t
					uint64_t nwid = strtoull(targetNetworkId.c_str(), NULL, 16);

					// Convert MAC back to ZeroTier address using the reverse algorithm
					// This reverses the fromAddress() function in MAC.hpp
					uint64_t ztAddr = macInt & 0xffffffffffULL; // least significant 40 bits
					ztAddr ^= ((nwid >> 8) & 0xff) << 32;
					ztAddr ^= ((nwid >> 16) & 0xff) << 24;
					ztAddr ^= ((nwid >> 24) & 0xff) << 16;
					ztAddr ^= ((nwid >> 32) & 0xff) << 8;
					ztAddr ^= (nwid >> 40) & 0xff;

					// Format as 10-character hex string (40 bits = 5 bytes)
					char ztAddrStr[16];
					snprintf(ztAddrStr, sizeof(ztAddrStr), "%010llx", (unsigned long long)(ztAddr & 0xffffffffffULL));

					printf("200 findztaddr %s %s (via MAC %s)" ZT_EOL_S, targetIp.c_str(), ztAddrStr, macBuffer);
					pclose(arpPipe);
					return 0;
				}
			}
		}
		pclose(arpPipe);

		printf("Could not resolve IP to MAC address via ARP" ZT_EOL_S);
		printf("" ZT_EOL_S);
		printf("This could mean:" ZT_EOL_S);
		printf("  - The device is offline or unreachable" ZT_EOL_S);
		printf("  - ARP cache has expired and device didn't respond to ping" ZT_EOL_S);
		printf("  - The IP address is not currently assigned to any ZeroTier peer" ZT_EOL_S);
		printf("" ZT_EOL_S);
		printf("Try:" ZT_EOL_S);
		printf("  - Ensure the target device is online and reachable" ZT_EOL_S);
		printf("  - Try again after some network activity to the target IP" ZT_EOL_S);
		printf("  - Check 'ip neigh show %s' manually" ZT_EOL_S, targetIp.c_str());

		return 1;
	} else if (command == "stats-by-ip") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/stats/by-ip",requestHeaders,responseHeaders,responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,cliFixJsonCRs(responseBody).c_str());
			} else {
				nlohmann::json result = OSUtils::jsonParse(responseBody);
				printf("IP Address Statistics (aggregated by IP only):" ZT_EOL_S);
				printf("%-15s %-12s %-12s %-20s" ZT_EOL_S, "IP Address", "RX Bytes", "TX Bytes", "Last Seen");
				printf("%-15s %-12s %-12s %-20s" ZT_EOL_S, "---------------", "------------", "------------", "--------------------");

				for (auto it = result.begin(); it != result.end(); ++it) {
					const std::string& ipAddr = it.key();
					const nlohmann::json& stats = it.value();

					uint64_t rxBytes = OSUtils::jsonInt(stats["incomingBytes"], 0ULL);
					uint64_t txBytes = OSUtils::jsonInt(stats["outgoingBytes"], 0ULL);
					uint64_t lastSeen = OSUtils::jsonInt(stats["lastSeen"], 0ULL);

					char rxStr[32], txStr[32], lastSeenStr[32];

					// Format bytes in human-readable format
					auto formatBytes = [](uint64_t bytes, char* str) {
						if (bytes >= 1073741824ULL) {
							snprintf(str, 32, "%.1f GB", (double)bytes / 1073741824.0);
						} else if (bytes >= 1048576ULL) {
							snprintf(str, 32, "%.1f MB", (double)bytes / 1048576.0);
						} else if (bytes >= 1024ULL) {
							snprintf(str, 32, "%.1f KB", (double)bytes / 1024.0);
						} else {
							snprintf(str, 32, "%llu B", (unsigned long long)bytes);
						}
					};

					formatBytes(rxBytes, rxStr);
					formatBytes(txBytes, txStr);

					if (lastSeen > 0) {
						time_t t = (time_t)(lastSeen / 1000ULL);
						struct tm *tm = localtime(&t);
						strftime(lastSeenStr, sizeof(lastSeenStr), "%Y-%m-%d %H:%M:%S", tm);
					} else {
						strcpy(lastSeenStr, "never");
					}

					printf("%-15s %-12s %-12s %-20s" ZT_EOL_S, ipAddr.c_str(), rxStr, txStr, lastSeenStr);
				}
			}
		} else {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}
	} else if (command == "health") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/health",requestHeaders,responseHeaders,responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,cliFixJsonCRs(responseBody).c_str());
			} else {
				nlohmann::json result = OSUtils::jsonParse(responseBody);
				printf("System Health Status:" ZT_EOL_S);
				printf("Status: %s" ZT_EOL_S, OSUtils::jsonString(result["status"], "unknown").c_str());
				printf("Uptime: %llu seconds" ZT_EOL_S, (unsigned long long)OSUtils::jsonInt(result["uptime"], 0ULL));
				printf("Clock: %llu" ZT_EOL_S, (unsigned long long)OSUtils::jsonInt(result["clock"], 0ULL));
			}
		} else {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}
	} else if (command == "metrics") {
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/metrics",requestHeaders,responseHeaders,responseBody);
		if (scode == 200) {
			printf("System Metrics:" ZT_EOL_S);
			printf("%s" ZT_EOL_S, responseBody.c_str());
		} else {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}
	} else if (command == "debug-peer") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli debug-peer <zt_address>" ZT_EOL_S);
			return 2;
		}

		std::string url = "/debug/peer?ztaddr=" + arg1;
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,url.c_str(),requestHeaders,responseHeaders,responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,cliFixJsonCRs(responseBody).c_str());
			} else {
				nlohmann::json result = OSUtils::jsonParse(responseBody);
				printf("Debug Information for Peer %s:" ZT_EOL_S, arg1.c_str());
				printf("Address: %s" ZT_EOL_S, OSUtils::jsonString(result["address"], "unknown").c_str());
				printf("Last Seen: %llu" ZT_EOL_S, (unsigned long long)OSUtils::jsonInt(result["lastSeen"], 0ULL));
				printf("Paths: %u" ZT_EOL_S, (unsigned int)OSUtils::jsonInt(result["pathCount"], 0));
				if (result.contains("paths") && result["paths"].is_array()) {
					for (const auto& path : result["paths"]) {
						printf("  Path: %s" ZT_EOL_S, OSUtils::jsonString(path["address"], "unknown").c_str());
					}
				}
			}
		} else {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}
	} else if (command == "debug-lookup") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli debug-lookup <ip_address>" ZT_EOL_S);
			return 2;
		}

		std::string url = "/debug/lookup?ip=" + arg1;
		const unsigned int scode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,url.c_str(),requestHeaders,responseHeaders,responseBody);
		if (scode == 200) {
			if (json) {
				printf("%s" ZT_EOL_S,cliFixJsonCRs(responseBody).c_str());
			} else {
				nlohmann::json result = OSUtils::jsonParse(responseBody);
				printf("Debug Lookup for IP %s:" ZT_EOL_S, arg1.c_str());
				printf("Found ZT Addresses:" ZT_EOL_S);
				if (result.contains("addresses") && result["addresses"].is_array()) {
					for (const auto& addr : result["addresses"]) {
						printf("  %s" ZT_EOL_S, addr.get<std::string>().c_str());
					}
				} else {
					printf("  None found" ZT_EOL_S);
				}
			}
		} else {
			printf("Error %u: %s" ZT_EOL_S, scode, responseBody.c_str());
			return 1;
		}

	} else if (command == "findip") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli findip <zt_address>" ZT_EOL_S);
			return 2;
		}

		// Parse the ZeroTier address
		std::string targetZtAddr = arg1;
		if (targetZtAddr.length() != 10) {
			printf("Invalid ZeroTier address format. Expected 10 hex characters." ZT_EOL_S);
			return 2;
		}

		// Convert ZeroTier address string to uint64_t
		uint64_t ztAddr = strtoull(targetZtAddr.c_str(), NULL, 16);
		if (ztAddr == 0) {
			printf("Invalid ZeroTier address: %s" ZT_EOL_S, targetZtAddr.c_str());
			return 2;
		}

		printf("Searching for IP address for ZeroTier address %s..." ZT_EOL_S, targetZtAddr.c_str());

		// First try ZeroTier Central API if we have an API token
		std::string apiToken;
		char tokenPath[1024];
		snprintf(tokenPath, sizeof(tokenPath), "%s/central-api-token", homeDir.c_str());
		std::string tokenData;
		if (OSUtils::readFile(tokenPath, tokenData)) {
			// Remove any whitespace/newlines
			size_t pos = tokenData.find_first_of(" \t\r\n");
			if (pos != std::string::npos) {
				apiToken = tokenData.substr(0, pos);
			} else {
				apiToken = tokenData;
			}
		}

		// Get network list
		const unsigned int netscode = Http::GET(1024 * 1024 * 16,60000,(const struct sockaddr *)&addr,"/network",requestHeaders,responseHeaders,responseBody);
		if (netscode != 200) {
			printf("Error getting network list: %u %s" ZT_EOL_S, netscode, responseBody.c_str());
			return 1;
		}

		nlohmann::json networks;
		try {
			networks = OSUtils::jsonParse(responseBody);
		} catch (...) {
			printf("Error parsing network list" ZT_EOL_S);
			return 1;
		}

		if (!networks.is_array()) {
			printf("Invalid network list format" ZT_EOL_S);
			return 1;
		}

		std::vector<std::string> foundIps; // Store all found IPs
		std::set<std::string> networksFoundInAPI; // Track which networks were successfully queried via API
		bool foundViaAPI = false;

		// If we have an API token, try the Central API first
		if (!apiToken.empty()) {
			printf("Querying ZeroTier Central API..." ZT_EOL_S);

			for (unsigned long i = 0; i < networks.size(); ++i) {
				nlohmann::json &network = networks[i];
				std::string networkId = OSUtils::jsonString(network["id"], "");
				if (networkId.empty()) continue;

				// Query Central API for network members
				std::string centralUrl = "https://api.zerotier.com/api/v1/network/" + networkId + "/member";
				std::string curlCmd = "curl -s -H 'Authorization: token " + apiToken + "' '" + centralUrl + "'";

				FILE* curlPipe = popen(curlCmd.c_str(), "r");
				if (curlPipe) {
					std::string apiResponse;
					char buffer[4096];
					while (fgets(buffer, sizeof(buffer), curlPipe)) {
						apiResponse += buffer;
					}
					pclose(curlPipe);

					try {
						nlohmann::json members = OSUtils::jsonParse(apiResponse);
						if (members.is_array()) {
							// Mark this network as successfully queried via API
							networksFoundInAPI.insert(networkId);

							for (unsigned long j = 0; j < members.size(); ++j) {
								nlohmann::json &member = members[j];
								std::string memberId = OSUtils::jsonString(member["nodeId"], "");

								if (memberId == targetZtAddr) {
									nlohmann::json &ipAssignments = member["config"]["ipAssignments"];
									if (ipAssignments.is_array()) {
										for (unsigned long k = 0; k < ipAssignments.size(); ++k) {
											std::string assignedIp = ipAssignments[k];
											std::string result = "200 findip " + targetZtAddr + " " + assignedIp + " (network " + networkId + ", via Central API)";
											foundIps.push_back(result);
											foundViaAPI = true;
										}
									}
								}
							}
						}
					} catch (...) {
						// API query failed for this network, we'll try ARP method for it
					}
				}
			}

			if (!foundViaAPI) {
				printf("ZeroTier address not found via Central API, checking local networks..." ZT_EOL_S);
			} else {
				printf("Found via Central API. Checking remaining local networks..." ZT_EOL_S);
			}
		}

		// Check each network for this ZeroTier address (only networks not found via API)
		for (unsigned long i = 0; i < networks.size(); ++i) {
			nlohmann::json &network = networks[i];
			std::string networkId = OSUtils::jsonString(network["id"], "");
			std::string portDeviceName = OSUtils::jsonString(network["portDeviceName"], "");

			if (networkId.empty()) continue;

			// Skip networks that were already successfully queried via Central API
			if (networksFoundInAPI.find(networkId) != networksFoundInAPI.end()) {
				continue;
			}

			// Convert network ID to uint64_t
			uint64_t nwid = strtoull(networkId.c_str(), NULL, 16);

			// Generate the expected MAC address for this ZeroTier address on this network
			// Using the same algorithm as MAC::fromAddress()
			uint64_t expectedMac = ((uint64_t)((unsigned char)((nwid & 0xfe) | 0x02))) << 40; // first octet
			if (((expectedMac >> 40) & 0xff) == 0x52) { // blacklist 0x52
				expectedMac = (expectedMac & 0xff0000000000ULL) | (0x32ULL << 40);
			}
			expectedMac |= ztAddr; // ZT address goes in lower 40 bits
			expectedMac ^= ((nwid >> 8) & 0xff) << 32;
			expectedMac ^= ((nwid >> 16) & 0xff) << 24;
			expectedMac ^= ((nwid >> 24) & 0xff) << 16;
			expectedMac ^= ((nwid >> 32) & 0xff) << 8;
			expectedMac ^= (nwid >> 40) & 0xff;

			// Format MAC address as string
			char expectedMacStr[18];
			snprintf(expectedMacStr, sizeof(expectedMacStr), "%02x:%02x:%02x:%02x:%02x:%02x",
				(unsigned int)((expectedMac >> 40) & 0xff),
				(unsigned int)((expectedMac >> 32) & 0xff),
				(unsigned int)((expectedMac >> 24) & 0xff),
				(unsigned int)((expectedMac >> 16) & 0xff),
				(unsigned int)((expectedMac >> 8) & 0xff),
				(unsigned int)(expectedMac & 0xff));

			printf("Looking for MAC %s in network %s..." ZT_EOL_S, expectedMacStr, networkId.c_str());

			// First check if this MAC is already in ARP cache
			std::string arpCmd = "ip neigh show | grep -i " + std::string(expectedMacStr) + " | awk '{print $1}' | head -1";
			FILE* arpPipe = popen(arpCmd.c_str(), "r");
			std::string foundIp;

			if (arpPipe) {
				char ipBuffer[64] = {0};
				if (fgets(ipBuffer, sizeof(ipBuffer), arpPipe)) {
					// Remove trailing newline
					char* newline = strchr(ipBuffer, '\n');
					if (newline) *newline = '\0';

					if (strlen(ipBuffer) > 0) {
						foundIp = std::string(ipBuffer);
					}
				}
				pclose(arpPipe);
			}

			// If not found in ARP cache, try to discover it by scanning the network
			if (foundIp.empty()) {
				printf("MAC not in ARP cache, scanning network %s..." ZT_EOL_S, networkId.c_str());

				// Get the network routes to determine what IP ranges to scan
				nlohmann::json &routes = network["routes"];
				if (routes.is_array()) {
					for (unsigned long j = 0; j < routes.size(); ++j) {
						nlohmann::json &route = routes[j];
						std::string target = OSUtils::jsonString(route["target"], "");

						if (!target.empty() && target.find('/') != std::string::npos) {
							// Parse network CIDR (e.g., "192.168.193.0/24")
							std::string networkBase = target.substr(0, target.find('/'));
							std::string maskStr = target.substr(target.find('/') + 1);
							int maskBits = atoi(maskStr.c_str());

							// For small networks (>= /24), do a quick ping sweep
							if (maskBits >= 24) {
								printf("Ping sweeping %s..." ZT_EOL_S, target.c_str());

								// Extract base network (e.g., "192.168.193" from "192.168.193.0")
								size_t lastDot = networkBase.rfind('.');
								if (lastDot != std::string::npos) {
									std::string baseNetwork = networkBase.substr(0, lastDot);

									// Ping sweep the network (parallel pings for speed)
									// Use a more reliable approach with seq instead of bash ranges
									std::string pingCmd = "seq 1 254 | xargs -I {} -P 50 ping -c 1 -W 1 " + baseNetwork + ".{} >/dev/null 2>&1";
									printf("Running: %s" ZT_EOL_S, pingCmd.c_str());
									(void)system(pingCmd.c_str());

									// Small delay to let ARP cache populate
									usleep(500000); // 500ms

									// Check ARP cache again
									FILE* arpPipe2 = popen(arpCmd.c_str(), "r");
									if (arpPipe2) {
										char ipBuffer2[64] = {0};
										if (fgets(ipBuffer2, sizeof(ipBuffer2), arpPipe2)) {
											char* newline = strchr(ipBuffer2, '\n');
											if (newline) *newline = '\0';

											if (strlen(ipBuffer2) > 0) {
												foundIp = std::string(ipBuffer2);
											}
										}
										pclose(arpPipe2);
									}
								}
							}

							if (!foundIp.empty()) break;
						}
					}
				}
			}

			if (!foundIp.empty()) {
				std::string result = "200 findip " + targetZtAddr + " " + foundIp + " (network " + networkId + ", MAC " + expectedMacStr + ")";
				foundIps.push_back(result);
			}
		}

		// Display all found results
		if (!foundIps.empty()) {
			for (const std::string& result : foundIps) {
				printf("%s" ZT_EOL_S, result.c_str());
			}
			return 0;
		}

		printf("No IP address found for ZeroTier address %s" ZT_EOL_S, targetZtAddr.c_str());
		printf("" ZT_EOL_S);
		printf("This could mean:" ZT_EOL_S);
		printf("  - The ZeroTier address is not currently online" ZT_EOL_S);
		printf("  - No recent network communication has occurred" ZT_EOL_S);
		printf("  - The address is not a member of any of your networks" ZT_EOL_S);
		printf("" ZT_EOL_S);
		printf("Try:" ZT_EOL_S);
		printf("  - Ensure the target device is online and communicating" ZT_EOL_S);
		printf("  - Try 'zerotier-cli listpeers' to see if the peer is known" ZT_EOL_S);
		printf("  - Generate some network traffic to populate ARP cache" ZT_EOL_S);

		return 1;
	} else if (command == "set-api-token") {
		if (arg1.empty()) {
			printf("usage: zerotier-cli set-api-token <token>" ZT_EOL_S);
			printf("" ZT_EOL_S);
			printf("Get your API token from https://my.zerotier.com/account" ZT_EOL_S);
			return 2;
		}

		// Save API token to a secure file
		char tokenPath[1024];
		snprintf(tokenPath, sizeof(tokenPath), "%s/central-api-token", homeDir.c_str());

		if (OSUtils::writeFile(tokenPath, arg1.c_str(), arg1.length())) {
			// Set restrictive permissions (owner read/write only)
			chmod(tokenPath, 0600);
			printf("200 set-api-token API token saved successfully" ZT_EOL_S);
			printf("Enhanced IP/ZeroTier address lookups are now available" ZT_EOL_S);
			return 0;
		} else {
			printf("Error saving API token to %s" ZT_EOL_S, tokenPath);
			return 1;
		}
	} else {
		cliPrintHelp(argv[0],stderr);
		return 0;
	}

	return 0;
}

/****************************************************************************/
/* zerotier-idtool personality                                              */
/****************************************************************************/

static void idtoolPrintHelp(FILE *out,const char *pn)
{
	fprintf(out,
		"%s version %d.%d.%d" ZT_EOL_S,
		PROGRAM_NAME,
		ZEROTIER_ONE_VERSION_MAJOR, ZEROTIER_ONE_VERSION_MINOR, ZEROTIER_ONE_VERSION_REVISION);
	fprintf(out,
		COPYRIGHT_NOTICE ZT_EOL_S
		LICENSE_GRANT ZT_EOL_S);
	fprintf(out,"Usage: %s <command> [<args>]" ZT_EOL_S"" ZT_EOL_S"Commands:" ZT_EOL_S,pn);
	fprintf(out,"  generate [<identity.secret>] [<identity.public>] [<vanity>]" ZT_EOL_S);
	fprintf(out,"  validate <identity.secret/public>" ZT_EOL_S);
	fprintf(out,"  getpublic <identity.secret>" ZT_EOL_S);
	fprintf(out,"  sign <identity.secret> <file>" ZT_EOL_S);
	fprintf(out,"  verify <identity.secret/public> <file> <signature>" ZT_EOL_S);
	fprintf(out,"  initmoon <identity.public of first seed>" ZT_EOL_S);
	fprintf(out,"  genmoon <moon json>" ZT_EOL_S);
}

static Identity getIdFromArg(char *arg)
{
	Identity id;
	if ((strlen(arg) > 32)&&(arg[10] == ':')) { // identity is a literal on the command line
		if (id.fromString(arg))
			return id;
	} else { // identity is to be read from a file
		std::string idser;
		if (OSUtils::readFile(arg,idser)) {
			if (id.fromString(idser.c_str()))
				return id;
		}
	}
	return Identity();
}

#ifdef __WINDOWS__
static int idtool(int argc, _TCHAR* argv[])
#else
static int idtool(int argc,char **argv)
#endif
{
	if (argc < 2) {
		idtoolPrintHelp(stdout,argv[0]);
		return 1;
	}

	if (!strcmp(argv[1],"generate")) {
		uint64_t vanity = 0;
		int vanityBits = 0;
		if (argc >= 5) {
			vanity = Utils::hexStrToU64(argv[4]) & 0xffffffffffULL;
			vanityBits = 4 * (int)strlen(argv[4]);
			if (vanityBits > 40)
				vanityBits = 40;
		}

		Identity id;
		for(;;) {
			id.generate();
			if ((id.address().toInt() >> (40 - vanityBits)) == vanity) {
				if (vanityBits > 0) {
					fprintf(stderr,"vanity address: found %.10llx !\n",(unsigned long long)id.address().toInt());
				}
				break;
			} else {
				fprintf(stderr,"vanity address: tried %.10llx looking for first %d bits of %.10llx\n",(unsigned long long)id.address().toInt(),vanityBits,(unsigned long long)(vanity << (40 - vanityBits)));
			}
		}

		char idtmp[1024];
		std::string idser = id.toString(true,idtmp);
		if (argc >= 3) {
			if (!OSUtils::writeFile(argv[2],idser)) {
				fprintf(stderr,"Error writing to %s" ZT_EOL_S,argv[2]);
				return 1;
			} else printf("%s written" ZT_EOL_S,argv[2]);
			if (argc >= 4) {
				idser = id.toString(false,idtmp);
				if (!OSUtils::writeFile(argv[3],idser)) {
					fprintf(stderr,"Error writing to %s" ZT_EOL_S,argv[3]);
					return 1;
				} else printf("%s written" ZT_EOL_S,argv[3]);
			}
		} else printf("%s",idser.c_str());
	} else if (!strcmp(argv[1],"validate")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout,argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (!id) {
			fprintf(stderr,"Identity argument invalid or file unreadable: %s" ZT_EOL_S,argv[2]);
			return 1;
		}

		if (!id.locallyValidate()) {
			fprintf(stderr,"%s FAILED validation." ZT_EOL_S,argv[2]);
			return 1;
		} else printf("%s is a valid identity" ZT_EOL_S,argv[2]);
	} else if (!strcmp(argv[1],"getpublic")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout,argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (!id) {
			fprintf(stderr,"Identity argument invalid or file unreadable: %s" ZT_EOL_S,argv[2]);
			return 1;
		}

		char idtmp[1024];
		printf("%s",id.toString(false,idtmp));
	} else if (!strcmp(argv[1],"sign")) {
		if (argc < 4) {
			idtoolPrintHelp(stdout,argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (!id) {
			fprintf(stderr,"Identity argument invalid or file unreadable: %s" ZT_EOL_S,argv[2]);
			return 1;
		}

		if (!id.hasPrivate()) {
			fprintf(stderr,"%s does not contain a private key (must use private to sign)" ZT_EOL_S,argv[2]);
			return 1;
		}

		std::string inf;
		if (!OSUtils::readFile(argv[3],inf)) {
			fprintf(stderr,"%s is not readable" ZT_EOL_S,argv[3]);
			return 1;
		}
		C25519::Signature signature = id.sign(inf.data(),(unsigned int)inf.length());
		char hexbuf[1024];
		printf("%s",Utils::hex(signature.data,ZT_C25519_SIGNATURE_LEN,hexbuf));
	} else if (!strcmp(argv[1],"verify")) {
		if (argc < 5) {
			idtoolPrintHelp(stdout,argv[0]);
			return 1;
		}

		Identity id = getIdFromArg(argv[2]);
		if (!id) {
			fprintf(stderr,"Identity argument invalid or file unreadable: %s" ZT_EOL_S,argv[2]);
			return 1;
		}

		std::string inf;
		if (!OSUtils::readFile(argv[3],inf)) {
			fprintf(stderr,"%s is not readable" ZT_EOL_S,argv[3]);
			return 1;
		}

		char buf[4096];
		std::string signature(buf,Utils::unhex(argv[4],buf,(unsigned int)sizeof(buf)));
		if ((signature.length() > ZT_ADDRESS_LENGTH)&&(id.verify(inf.data(),(unsigned int)inf.length(),signature.data(),(unsigned int)signature.length()))) {
			printf("%s signature valid" ZT_EOL_S,argv[3]);
		} else {
			signature.clear();
			if (OSUtils::readFile(argv[4],signature)) {
				signature.assign(buf,Utils::unhex(signature.c_str(),buf,(unsigned int)sizeof(buf)));
				if ((signature.length() > ZT_ADDRESS_LENGTH)&&(id.verify(inf.data(),(unsigned int)inf.length(),signature.data(),(unsigned int)signature.length()))) {
					printf("%s signature valid" ZT_EOL_S,argv[3]);
				} else {
					fprintf(stderr,"%s signature check FAILED" ZT_EOL_S,argv[3]);
					return 1;
				}
			} else {
				fprintf(stderr,"%s signature check FAILED" ZT_EOL_S,argv[3]);
				return 1;
			}
		}
	} else if (!strcmp(argv[1],"initmoon")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout,argv[0]);
		} else {
			const Identity id = getIdFromArg(argv[2]);
			if (!id) {
				fprintf(stderr,"%s is not a valid identity" ZT_EOL_S,argv[2]);
				return 1;
			}

			C25519::Pair kp(C25519::generate());

			char idtmp[4096];
			nlohmann::json mj;
			mj["objtype"] = "world";
			mj["worldType"] = "moon";
			mj["updatesMustBeSignedBy"] = mj["signingKey"] = Utils::hex(kp.pub.data,ZT_C25519_PUBLIC_KEY_LEN,idtmp);
			mj["signingKey_SECRET"] = Utils::hex(kp.priv.data,ZT_C25519_PRIVATE_KEY_LEN,idtmp);
			mj["id"] = id.address().toString(idtmp);
			nlohmann::json seedj;
			seedj["identity"] = id.toString(false,idtmp);
			seedj["stableEndpoints"] = nlohmann::json::array();
			(mj["roots"] = nlohmann::json::array()).push_back(seedj);
			std::string mjd(OSUtils::jsonDump(mj));

			printf("%s" ZT_EOL_S,mjd.c_str());
		}
	} else if (!strcmp(argv[1],"genmoon")) {
		if (argc < 3) {
			idtoolPrintHelp(stdout,argv[0]);
		} else {
			std::string buf;
			if (!OSUtils::readFile(argv[2],buf)) {
				fprintf(stderr,"cannot read %s" ZT_EOL_S,argv[2]);
				return 1;
			}
			nlohmann::json mj(OSUtils::jsonParse(buf));

			const uint64_t id = Utils::hexStrToU64(OSUtils::jsonString(mj["id"],"0").c_str());
			if (!id) {
				fprintf(stderr,"ID in %s is invalid" ZT_EOL_S,argv[2]);
				return 1;
			}

			World::Type t;
			if (mj["worldType"] == "moon") {
				t = World::TYPE_MOON;
			} else if (mj["worldType"] == "planet") {
				t = World::TYPE_PLANET;
			} else {
				fprintf(stderr,"invalid worldType" ZT_EOL_S);
				return 1;
			}

			C25519::Pair signingKey;
			C25519::Public updatesMustBeSignedBy;
			Utils::unhex(OSUtils::jsonString(mj["signingKey"],"").c_str(),signingKey.pub.data,ZT_C25519_PUBLIC_KEY_LEN);
			Utils::unhex(OSUtils::jsonString(mj["signingKey_SECRET"],"").c_str(),signingKey.priv.data,ZT_C25519_PRIVATE_KEY_LEN);
			Utils::unhex(OSUtils::jsonString(mj["updatesMustBeSignedBy"],"").c_str(),updatesMustBeSignedBy.data,ZT_C25519_PUBLIC_KEY_LEN);

			std::vector<World::Root> roots;
			nlohmann::json &rootsj = mj["roots"];
			if (rootsj.is_array()) {
				for(unsigned long i=0;i<(unsigned long)rootsj.size();++i) {
					nlohmann::json &r = rootsj[i];
					if (r.is_object()) {
						roots.push_back(World::Root());
						roots.back().identity = Identity(OSUtils::jsonString(r["identity"],"").c_str());
						nlohmann::json &stableEndpointsj = r["stableEndpoints"];
						if (stableEndpointsj.is_array()) {
							for(unsigned long k=0;k<(unsigned long)stableEndpointsj.size();++k)
								roots.back().stableEndpoints.push_back(InetAddress(OSUtils::jsonString(stableEndpointsj[k],"").c_str()));
							std::sort(roots.back().stableEndpoints.begin(),roots.back().stableEndpoints.end());
						}
					}
				}
			}
			std::sort(roots.begin(),roots.end());

			const int64_t now = OSUtils::now();
			World w(World::make(t,id,now,updatesMustBeSignedBy,roots,signingKey));
			Buffer<ZT_WORLD_MAX_SERIALIZED_LENGTH> wbuf;
			w.serialize(wbuf);
			char fn[128];
			OSUtils::ztsnprintf(fn,sizeof(fn),"%.16llx.moon",w.id());
			OSUtils::writeFile(fn,wbuf.data(),wbuf.size());
			printf("wrote %s (signed world with timestamp %llu)" ZT_EOL_S,fn,(unsigned long long)now);
		}
	} else {
		idtoolPrintHelp(stdout,argv[0]);
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
	alarm(5); // force exit after 5s
	OneService *s = zt1Service;
	if (s)
		s->terminate();
	else exit(0);
}
#endif

// Drop privileges on Linux, if supported by libc etc. and "zerotier-one" user exists on system
#if defined(__LINUX__) && !defined(ZT_NO_CAPABILITIES)
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_IS_SET 1
#define PR_CAP_AMBIENT_RAISE 2
#define PR_CAP_AMBIENT_LOWER 3
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#define ZT_LINUX_USER "zerotier-one"
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
static inline int _zt_capset(cap_header_struct* hdrp, cap_data_struct* datap) { return syscall(SYS_capset, hdrp, datap); }

static void _notDropping(const char *procName,const std::string &homeDir)
{
	struct stat buf;
	if (lstat(homeDir.c_str(),&buf) < 0) {
		if (buf.st_uid != 0 || buf.st_gid != 0) {
			fprintf(stderr, "%s: FATAL: failed to drop privileges and can't run as root since privileges were previously dropped (home directory not owned by root)" ZT_EOL_S,procName);
			exit(1);
		}
	}
	fprintf(stderr, "%s: WARNING: failed to drop privileges (kernel may not support required prctl features), running as root" ZT_EOL_S,procName);
}

static int _setCapabilities(int flags)
{
	cap_header_struct capheader = {_LINUX_CAPABILITY_VERSION_1, 0};
	cap_data_struct capdata;
	capdata.inheritable = capdata.permitted = capdata.effective = flags;
	return _zt_capset(&capheader, &capdata);
}

static void _recursiveChown(const char *path,uid_t uid,gid_t gid)
{
	struct dirent de;
	struct dirent *dptr;
	lchown(path,uid,gid);
	DIR *d = opendir(path);
	if (!d)
		return;
	dptr = (struct dirent *)0;
	for(;;) {
		if (readdir_r(d,&de,&dptr) != 0)
			break;
		if (!dptr)
			break;
		if ((strcmp(dptr->d_name,".") != 0)&&(strcmp(dptr->d_name,"..") != 0)&&(strlen(dptr->d_name) > 0)) {
			std::string p(path);
			p.push_back(ZT_PATH_SEPARATOR);
			p.append(dptr->d_name);
			_recursiveChown(p.c_str(),uid,gid); // will just fail and return on regular files
		}
	}
	closedir(d);
}

static void dropPrivileges(const char *procName,const std::string &homeDir)
{
	if (getuid() != 0)
		return;

	// dropPrivileges switches to zerotier-one user while retaining CAP_NET_ADMIN
	// and CAP_NET_RAW capabilities.
	struct passwd *targetUser = getpwnam(ZT_LINUX_USER);
	if (!targetUser)
		return;

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_RAW, 0, 0) < 0) {
		// Kernel has no support for ambient capabilities.
		_notDropping(procName,homeDir);
		return;
	}
	if (prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS | SECBIT_NOROOT) < 0) {
		_notDropping(procName,homeDir);
		return;
	}

	// Change ownership of our home directory if everything looks good (does nothing if already chown'd)
	_recursiveChown(homeDir.c_str(),targetUser->pw_uid,targetUser->pw_gid);

	if (_setCapabilities((1 << CAP_NET_ADMIN) | (1 << CAP_NET_RAW) | (1 << CAP_SETUID) | (1 << CAP_SETGID) | (1 << CAP_NET_BIND_SERVICE)) < 0) {
		_notDropping(procName,homeDir);
		return;
	}

	int oldDumpable = prctl(PR_GET_DUMPABLE);
	if (prctl(PR_SET_DUMPABLE, 0) < 0) {
		// Disable ptracing. Otherwise there is a small window when previous
		// compromised ZeroTier process could ptrace us, when we still have CAP_SETUID.
		// (this is mitigated anyway on most distros by ptrace_scope=1)
		fprintf(stderr,"%s: FATAL: prctl(PR_SET_DUMPABLE) failed while attempting to relinquish root permissions" ZT_EOL_S,procName);
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
		fprintf(stderr,"%s: FATAL: unable to drop capabilities after relinquishing root" ZT_EOL_S,procName);
		exit(1);
	}

	if (prctl(PR_SET_DUMPABLE, oldDumpable) < 0) {
		fprintf(stderr,"%s: FATAL: prctl(PR_SET_DUMPABLE) failed while attempting to relinquish root permissions" ZT_EOL_S,procName);
		exit(1);
	}

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0) < 0) {
		fprintf(stderr,"%s: FATAL: prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_NET_ADMIN) failed while attempting to relinquish root permissions" ZT_EOL_S,procName);
		exit(1);
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW, 0, 0) < 0) {
		fprintf(stderr,"%s: FATAL: prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_NET_RAW) failed while attempting to relinquish root permissions" ZT_EOL_S,procName);
		exit(1);
	}
}

} // anonymous namespace
#endif // __LINUX__

/****************************************************************************/
/* Windows helper functions and signal handlers                             */
/****************************************************************************/

#ifdef __WINDOWS__
// Console signal handler routine to allow CTRL+C to work, mostly for testing
static BOOL WINAPI _winConsoleCtrlHandler(DWORD dwCtrlType)
{
	switch(dwCtrlType) {
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			OneService *s = zt1Service;
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
	DWORD ps = GetModuleFileNameA(NULL,myPath,sizeof(myPath));
	if ((ps > 0)&&(ps < (DWORD)sizeof(myPath))) {
		STARTUPINFOA startupInfo;
		PROCESS_INFORMATION processInfo;

		startupInfo.cb = sizeof(startupInfo);
		memset(&startupInfo,0,sizeof(STARTUPINFOA));
		memset(&processInfo,0,sizeof(PROCESS_INFORMATION));
		if (CreateProcessA(NULL,(LPSTR)(std::string("C:\\Windows\\System32\\netsh.exe advfirewall firewall delete rule name=\"ZeroTier One\" program=\"") + myPath + "\"").c_str(),NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startupInfo,&processInfo)) {
			WaitForSingleObject(processInfo.hProcess,INFINITE);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}

		startupInfo.cb = sizeof(startupInfo);
		memset(&startupInfo,0,sizeof(STARTUPINFOA));
		memset(&processInfo,0,sizeof(PROCESS_INFORMATION));
		if (CreateProcessA(NULL,(LPSTR)(std::string("C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"ZeroTier One\" dir=in action=allow program=\"") + myPath + "\" enable=yes").c_str(),NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startupInfo,&processInfo)) {
			WaitForSingleObject(processInfo.hProcess,INFINITE);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}

		startupInfo.cb = sizeof(startupInfo);
		memset(&startupInfo,0,sizeof(STARTUPINFOA));
		memset(&processInfo,0,sizeof(PROCESS_INFORMATION));
		if (CreateProcessA(NULL,(LPSTR)(std::string("C:\\Windows\\System32\\netsh.exe advfirewall firewall add rule name=\"ZeroTier One\" dir=out action=allow program=\"") + myPath + "\" enable=yes").c_str(),NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startupInfo,&processInfo)) {
			WaitForSingleObject(processInfo.hProcess,INFINITE);
			CloseHandle(processInfo.hProcess);
			CloseHandle(processInfo.hThread);
		}
	}
}

// Returns true if this is running as the local administrator
static BOOL IsCurrentUserLocalAdministrator(void)
{
	BOOL   fReturn         = FALSE;
	DWORD  dwStatus;
	DWORD  dwAccessMask;
	DWORD  dwAccessDesired;
	DWORD  dwACLSize;
	DWORD  dwStructureSize = sizeof(PRIVILEGE_SET);
	PACL   pACL            = NULL;
	PSID   psidAdmin       = NULL;

	HANDLE hToken              = NULL;
	HANDLE hImpersonationToken = NULL;

	PRIVILEGE_SET   ps;
	GENERIC_MAPPING GenericMapping;

	PSECURITY_DESCRIPTOR     psdAdmin           = NULL;
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;

	const DWORD ACCESS_READ  = 1;
	const DWORD ACCESS_WRITE = 2;

	__try
	{
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE|TOKEN_QUERY,TRUE,&hToken))
		{
			if (GetLastError() != ERROR_NO_TOKEN)
				__leave;
			if (!OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY, &hToken))
				__leave;
		}
		if (!DuplicateToken (hToken, SecurityImpersonation,&hImpersonationToken))
			__leave;
		if (!AllocateAndInitializeSid(&SystemSidAuthority, 2,
			SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0, &psidAdmin))
			__leave;
		psdAdmin = LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
		if (psdAdmin == NULL)
			__leave;
		if (!InitializeSecurityDescriptor(psdAdmin,SECURITY_DESCRIPTOR_REVISION))
			__leave;
		dwACLSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psidAdmin) - sizeof(DWORD);
		pACL = (PACL)LocalAlloc(LPTR, dwACLSize);
		if (pACL == NULL)
			__leave;
		if (!InitializeAcl(pACL, dwACLSize, ACL_REVISION2))
			__leave;
		dwAccessMask= ACCESS_READ | ACCESS_WRITE;
		if (!AddAccessAllowedAce(pACL, ACL_REVISION2, dwAccessMask, psidAdmin))
			__leave;
		if (!SetSecurityDescriptorDacl(psdAdmin, TRUE, pACL, FALSE))
			__leave;

		SetSecurityDescriptorGroup(psdAdmin, psidAdmin, FALSE);
		SetSecurityDescriptorOwner(psdAdmin, psidAdmin, FALSE);

		if (!IsValidSecurityDescriptor(psdAdmin))
			__leave;
		dwAccessDesired = ACCESS_READ;

		GenericMapping.GenericRead    = ACCESS_READ;
		GenericMapping.GenericWrite   = ACCESS_WRITE;
		GenericMapping.GenericExecute = 0;
		GenericMapping.GenericAll     = ACCESS_READ | ACCESS_WRITE;

		if (!AccessCheck(psdAdmin, hImpersonationToken, dwAccessDesired,
			&GenericMapping, &ps, &dwStructureSize, &dwStatus,
			&fReturn))
		{
			fReturn = FALSE;
			__leave;
		}
	}
	__finally
	{
		// Clean up.
		if (pACL) LocalFree(pACL);
		if (psdAdmin) LocalFree(psdAdmin);
		if (psidAdmin) FreeSid(psidAdmin);
		if (hImpersonationToken) CloseHandle (hImpersonationToken);
		if (hToken) CloseHandle (hToken);
	}

	return fReturn;
}
#endif // __WINDOWS__

/****************************************************************************/
/* main() and friends                                                       */
/****************************************************************************/

static void printHelp(const char *cn,FILE *out)
{
	fprintf(out,
		"%s version %d.%d.%d" ZT_EOL_S,
		PROGRAM_NAME,
		ZEROTIER_ONE_VERSION_MAJOR, ZEROTIER_ONE_VERSION_MINOR, ZEROTIER_ONE_VERSION_REVISION);
	fprintf(out,
		COPYRIGHT_NOTICE ZT_EOL_S
		LICENSE_GRANT ZT_EOL_S);
	fprintf(out,"Usage: %s [-switches] [home directory]" ZT_EOL_S"" ZT_EOL_S,cn);
	fprintf(out,"Available switches:" ZT_EOL_S);
	fprintf(out,"  -h                - Display this help" ZT_EOL_S);
	fprintf(out,"  -v                - Show version" ZT_EOL_S);
	fprintf(out,"  -U                - Skip privilege check and do not attempt to drop privileges" ZT_EOL_S);
	fprintf(out,"  -p<port>          - Port for UDP and TCP/HTTP (default: 9993, 0 for random)" ZT_EOL_S);

#ifdef __UNIX_LIKE__
	fprintf(out,"  -d                - Fork and run as daemon (Unix-ish OSes)" ZT_EOL_S);
#endif // __UNIX_LIKE__

#ifdef __WINDOWS__
	fprintf(out,"  -C                - Run from command line instead of as service (Windows)" ZT_EOL_S);
	fprintf(out,"  -I                - Install Windows service (Windows)" ZT_EOL_S);
	fprintf(out,"  -R                - Uninstall Windows service (Windows)" ZT_EOL_S);
	fprintf(out,"  -D                - Remove all instances of Windows tap device (Windows)" ZT_EOL_S);
#endif // __WINDOWS__

	fprintf(out,"  -i                - Generate and manage identities (zerotier-idtool)" ZT_EOL_S);
	fprintf(out,"  -q                - Query API (zerotier-cli)" ZT_EOL_S);
}

class _OneServiceRunner
{
public:
	_OneServiceRunner(const char *pn,const std::string &hd,unsigned int p) : progname(pn),returnValue(0),port(p),homeDir(hd) {}
	void threadMain()
		throw()
	{
		try {
			for(;;) {
				zt1Service = OneService::newInstance(homeDir.c_str(),port);
				switch(zt1Service->run()) {
					case OneService::ONE_STILL_RUNNING: // shouldn't happen, run() won't return until done
					case OneService::ONE_NORMAL_TERMINATION:
						break;
					case OneService::ONE_UNRECOVERABLE_ERROR:
						fprintf(stderr,"%s: fatal error: %s" ZT_EOL_S,progname,zt1Service->fatalErrorMessage().c_str());
						returnValue = 1;
						break;
					case OneService::ONE_IDENTITY_COLLISION: {
						delete zt1Service;
						zt1Service = (OneService *)0;
						std::string oldid;
						OSUtils::readFile((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret").c_str(),oldid);
						if (oldid.length()) {
							OSUtils::writeFile((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret.saved_after_collision").c_str(),oldid);
							OSUtils::rm((homeDir + ZT_PATH_SEPARATOR_S + "identity.secret").c_str());
							OSUtils::rm((homeDir + ZT_PATH_SEPARATOR_S + "identity.public").c_str());
						}
					}	continue; // restart!
				}
				break; // terminate loop -- normally we don't keep restarting
			}

			delete zt1Service;
			zt1Service = (OneService *)0;
		} catch ( ... ) {
			fprintf(stderr,"%s: unexpected exception starting main OneService instance" ZT_EOL_S,progname);
			returnValue = 1;
		}
	}
	const char *progname;
	unsigned int returnValue;
	unsigned int port;
	const std::string &homeDir;
};

#ifdef __WINDOWS__
int __cdecl _tmain(int argc, _TCHAR* argv[])
#else
int main(int argc,char **argv)
#endif
{
#if defined(__LINUX__) && ( (!defined(__GLIBC__)) || ((__GLIBC__ >= 2) && (__GLIBC_MINOR__ >= 18)) )
	// This corrects for systems with abnormally small defaults (musl) and also
	// shrinks the stack on systems with large defaults to save a bit of memory.
	pthread_attr_t tattr;
	pthread_attr_init(&tattr);
	pthread_attr_setstacksize(&tattr,1048576);
	pthread_setattr_default_np(&tattr);
	pthread_attr_destroy(&tattr);
#endif

#ifdef __UNIX_LIKE__
	signal(SIGHUP,&_sighandlerHup);
	signal(SIGPIPE,SIG_IGN);
	signal(SIGIO,SIG_IGN);
	signal(SIGUSR1,SIG_IGN);
	signal(SIGUSR2,SIG_IGN);
	signal(SIGALRM,&_sighandlerReallyQuit);
	signal(SIGINT,&_sighandlerQuit);
	signal(SIGTERM,&_sighandlerQuit);
	signal(SIGQUIT,&_sighandlerQuit);
	signal(SIGINT,&_sighandlerQuit);

	/* Ensure that there are no inherited file descriptors open from a previous
	 * incarnation. This is a hack to ensure that GitHub issue #61 or variants
	 * of it do not return, and should not do anything otherwise bad. */
	{
		int mfd = STDIN_FILENO;
		if (STDOUT_FILENO > mfd) mfd = STDOUT_FILENO;
		if (STDERR_FILENO > mfd) mfd = STDERR_FILENO;
		for(int f=mfd+1;f<1024;++f)
			::close(f);
	}

	bool runAsDaemon = false;
#endif // __UNIX_LIKE__

#ifdef __WINDOWS__
	{
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2,2),&wsaData);
	}

#ifdef ZT_WIN_RUN_IN_CONSOLE
	bool winRunFromCommandLine = true;
#else
	bool winRunFromCommandLine = false;
#endif
#endif // __WINDOWS__

	if ((strstr(argv[0],"zerotier-idtool"))||(strstr(argv[0],"ZEROTIER-IDTOOL")))
		return idtool(argc,argv);
	if ((strstr(argv[0],"zerotier-cli"))||(strstr(argv[0],"ZEROTIER-CLI")))
		return cli(argc,argv);

	std::string homeDir;
	unsigned int port = ZT_DEFAULT_PORT;
	bool skipRootCheck = false;

	for(int i=1;i<argc;++i) {
		if (argv[i][0] == '-') {
			switch(argv[i][1]) {

				case 'p': // port -- for both UDP and TCP, packets and control plane
					port = Utils::strToUInt(argv[i] + 2);
					if (port > 0xffff) {
						printHelp(argv[0],stdout);
						return 1;
					}
					break;

#ifdef __UNIX_LIKE__
				case 'd': // Run in background as daemon
					runAsDaemon = true;
					break;
#endif // __UNIX_LIKE__

				case 'U':
					skipRootCheck = true;
					break;

				case 'v': // Display version
					printf("%d.%d.%d" ZT_EOL_S,ZEROTIER_ONE_VERSION_MAJOR,ZEROTIER_ONE_VERSION_MINOR,ZEROTIER_ONE_VERSION_REVISION);
					return 0;

				case 'i': // Invoke idtool personality
					if (argv[i][2]) {
						printHelp(argv[0],stdout);
						return 0;
					} else return idtool(argc-1,argv+1);

				case 'q': // Invoke cli personality
					if (argv[i][2]) {
						printHelp(argv[0],stdout);
						return 0;
					} else return cli(argc,argv);

#ifdef __WINDOWS__
				case 'C': // Run from command line instead of as Windows service
					winRunFromCommandLine = true;
					break;

				case 'I': { // Install this binary as a Windows service
						if (IsCurrentUserLocalAdministrator() != TRUE) {
							fprintf(stderr,"%s: must be run as a local administrator." ZT_EOL_S,argv[0]);
							return 1;
						}
						std::string ret(InstallService(ZT_SERVICE_NAME,ZT_SERVICE_DISPLAY_NAME,ZT_SERVICE_START_TYPE,ZT_SERVICE_DEPENDENCIES,ZT_SERVICE_ACCOUNT,ZT_SERVICE_PASSWORD));
						if (ret.length()) {
							fprintf(stderr,"%s: unable to install service: %s" ZT_EOL_S,argv[0],ret.c_str());
							return 3;
						}
						return 0;
					} break;

				case 'R': { // Uninstall this binary as Windows service
						if (IsCurrentUserLocalAdministrator() != TRUE) {
							fprintf(stderr,"%s: must be run as a local administrator." ZT_EOL_S,argv[0]);
							return 1;
						}
						std::string ret(UninstallService(ZT_SERVICE_NAME));
						if (ret.length()) {
							fprintf(stderr,"%s: unable to uninstall service: %s" ZT_EOL_S,argv[0],ret.c_str());
							return 3;
						}
						return 0;
					} break;

				case 'D': {
						std::string err = WindowsEthernetTap::destroyAllPersistentTapDevices();
						if (err.length() > 0) {
							fprintf(stderr,"%s: unable to uninstall one or more persistent tap devices: %s" ZT_EOL_S,argv[0],err.c_str());
							return 3;
						}
						return 0;
					} break;
#endif // __WINDOWS__

				case 'h':
				case '?':
				default:
					printHelp(argv[0],stdout);
					return 0;
			}
		} else {
			if (homeDir.length()) {
				printHelp(argv[0],stdout);
				return 0;
			} else {
				homeDir = argv[i];
			}
		}
	}

	if (!homeDir.length())
		homeDir = OneService::platformDefaultHomePath();
	if (!homeDir.length()) {
		fprintf(stderr,"%s: no home path specified and no platform default available" ZT_EOL_S,argv[0]);
		return 1;
	} else {
		std::vector<std::string> hpsp(OSUtils::split(homeDir.c_str(),ZT_PATH_SEPARATOR_S,"",""));
		std::string ptmp;
		if (homeDir[0] == ZT_PATH_SEPARATOR)
			ptmp.push_back(ZT_PATH_SEPARATOR);
		for(std::vector<std::string>::iterator pi(hpsp.begin());pi!=hpsp.end();++pi) {
			if (ptmp.length() > 0)
				ptmp.push_back(ZT_PATH_SEPARATOR);
			ptmp.append(*pi);
			if ((*pi != ".")&&(*pi != "..")) {
				if (!OSUtils::mkdir(ptmp))
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
	if (OSUtils::fileExists((homeDir + ZT_PATH_SEPARATOR_S + "controller.db").c_str(),true)) {
		fprintf(stderr,"%s: FATAL: an old controller.db exists in %s -- see instructions in controller/README.md for how to migrate!" ZT_EOL_S,argv[0],homeDir.c_str());
		return 1;
	}

#ifdef __UNIX_LIKE__
#ifndef ZT_ONE_NO_ROOT_CHECK
	if ((!skipRootCheck)&&(getuid() != 0)) {
		fprintf(stderr,"%s: must be run as root (uid 0)" ZT_EOL_S,argv[0]);
		return 1;
	}
#endif // !ZT_ONE_NO_ROOT_CHECK
	if (runAsDaemon) {
		long p = (long)fork();
		if (p < 0) {
			fprintf(stderr,"%s: could not fork" ZT_EOL_S,argv[0]);
			return 1;
		} else if (p > 0)
			return 0; // forked
		// else p == 0, so we are daemonized
	}
#endif // __UNIX_LIKE__

#ifdef __WINDOWS__
	// Uninstall legacy tap devices. New devices will automatically be installed and configured
	// when tap instances are created.
	WindowsEthernetTap::destroyAllLegacyPersistentTapDevices();

	if (winRunFromCommandLine) {
		// Running in "interactive" mode (mostly for debugging)
		if (IsCurrentUserLocalAdministrator() != TRUE) {
			if (!skipRootCheck) {
				fprintf(stderr,"%s: must be run as a local administrator." ZT_EOL_S,argv[0]);
				return 1;
			}
		} else {
			_winPokeAHole();
		}
		SetConsoleCtrlHandler(&_winConsoleCtrlHandler,TRUE);
		// continues on to ordinary command line execution code below...
	} else {
		// Running from service manager
		_winPokeAHole();
		ZeroTierOneService zt1WindowsService;
		if (CServiceBase::Run(zt1WindowsService) == TRUE) {
			return 0;
		} else {
			fprintf(stderr,"%s: unable to start service (try -h for help)" ZT_EOL_S,argv[0]);
			return 1;
		}
	}
#endif // __WINDOWS__

#ifdef __UNIX_LIKE__
#ifdef ZT_HAVE_DROP_PRIVILEGES
	if (!skipRootCheck)
		dropPrivileges(argv[0],homeDir);
#endif

	std::string pidPath(homeDir + ZT_PATH_SEPARATOR_S + ZT_PID_PATH);
	{
		// Write .pid file to home folder
		FILE *pf = fopen(pidPath.c_str(),"w");
		if (pf) {
			fprintf(pf,"%ld",(long)getpid());
			fclose(pf);
		}
	}
#endif // __UNIX_LIKE__

	_OneServiceRunner thr(argv[0],homeDir,port);
	thr.threadMain();
	//Thread::join(Thread::start(&thr));

#ifdef __UNIX_LIKE__
	OSUtils::rm(pidPath.c_str());
#endif

	return thr.returnValue;
}
