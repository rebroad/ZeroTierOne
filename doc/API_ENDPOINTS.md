# ZeroTier One Service API Endpoints

This document provides a comprehensive reference for all HTTP API endpoints available in the ZeroTier One service. These endpoints can be accessed via the CLI tool `zerotier-cli` or directly via HTTP requests to the local service (default port 9993).

## Authentication

All API requests require authentication using the auth token found in `authtoken.secret` in the ZeroTier home directory. The token can be provided via:

- URL parameter: `?auth=<token>`
- HTTP header: `X-ZT1-Auth: <token>`
- Bearer token: `Authorization: Bearer <token>`

For metrics endpoint specifically, use the token from `metricstoken.secret`.

## Base URL

- **IPv4**: `http://127.0.0.1:9993`
- **IPv6**: `http://[::1]:9993`

Note: Both IPv4 and IPv6 endpoints provide identical functionality.

---

## Core Service Endpoints

### `/status`
**Methods**: `GET`  
**Description**: Get running node status and addressing information  
**CLI Command**: `zerotier-cli info`

**Response Fields**:
| Field | Type | Description |
|-------|------|-------------|
| address | string | 10-digit hex ZeroTier address of this node |
| publicIdentity | string | Node's ZeroTier identity.public |
| worldId | integer | ZeroTier world ID |
| worldTimestamp | integer | Timestamp of most recent world definition |
| online | boolean | True if at least one upstream peer is reachable |
| tcpFallbackActive | boolean | True if using slow TCP fallback |
| relayPolicy | string | Relay policy: ALWAYS, TRUSTED, or NEVER |
| versionMajor | integer | Software major version |
| versionMinor | integer | Software minor version |
| versionRev | integer | Software revision |
| version | string | major.minor.revision |
| clock | integer | Current system clock (ms since epoch) |

### `/health`
**Methods**: `GET`  
**Description**: Get health status of the service  
**CLI Command**: Not directly accessible

---

## Network Management

### `/network`
**Methods**: `GET`  
**Description**: Get all network memberships  
**CLI Command**: `zerotier-cli listnetworks`

**Returns**: Array of network objects

### `/network/<network_id>`
**Methods**: `GET`, `POST`, `PUT`, `DELETE`  
**Description**: Get, join, configure, or leave a specific network  
**CLI Commands**:
- Join: `zerotier-cli join <network_id>`
- Leave: `zerotier-cli leave <network_id>`
- Info: `zerotier-cli listnetworks` (shows specific network)

**Network Object Fields**:
| Field | Type | Description | Writable |
|-------|------|-------------|----------|
| id | string | 16-digit hex network ID | no |
| nwid | string | 16-digit hex network ID (legacy) | no |
| mac | string | MAC address of network device | no |
| name | string | Network name from controller | no |
| status | string | Network status (OK, ACCESS_DENIED, etc.) | no |
| type | string | Network type (PUBLIC or PRIVATE) | no |
| mtu | integer | Ethernet MTU | no |
| dhcp | boolean | If DHCP should be used | no |
| bridge | boolean | If device can bridge others | no |
| broadcastEnabled | boolean | If broadcasts work | no |
| portError | integer | Error code from tap driver | no |
| netconfRevision | integer | Network config revision ID | no |
| assignedAddresses | array | ZT-assigned IP addresses | no |
| routes | array | ZT-assigned routes | no |
| portDeviceName | string | Virtual network device name | no |
| allowManaged | boolean | Allow IP and route management | yes |
| allowGlobal | boolean | Allow IPs overlapping global IPs | yes |
| allowDefault | boolean | Allow default route override | yes |
| allowDNS | boolean | Allow DNS configuration | yes |

---

## Peer Management

### `/peer`
**Methods**: `GET`  
**Description**: Get all current peers  
**CLI Command**: `zerotier-cli peers`

**Returns**: Array of peer objects

### `/peer/<address>`
**Methods**: `GET`, `POST`  
**Description**: Get or configure information about a specific peer  
**CLI Command**: `zerotier-cli peers` (shows specific peer info)

**Peer Object Fields**:
| Field | Type | Description | Writable |
|-------|------|-------------|----------|
| address | string | 10-digit hex ZeroTier address | no |
| versionMajor | integer | Major version of remote | no |
| versionMinor | integer | Minor version of remote | no |
| versionRev | integer | Software revision of remote | no |
| version | string | major.minor.revision | no |
| latency | integer | Latency in milliseconds | no |
| role | string | LEAF, UPSTREAM, ROOT, or PLANET | no |
| paths | array | Currently active physical paths | no |

---

## Moon Management

### `/moon`
**Methods**: `GET`  
**Description**: List all moons  
**CLI Command**: `zerotier-cli listmoons`

### `/moon/<moon_id>`
**Methods**: `GET`, `POST`, `PUT`, `DELETE`  
**Description**: Get, orbit, or deorbit a specific moon  
**CLI Commands**:
- Orbit: `zerotier-cli orbit <moon_id> <moon_seed>`
- Deorbit: `zerotier-cli deorbit <moon_id>`

---

## Bonding and Path Management

### `/bond/show/<address>`
**Methods**: `GET`  
**Description**: Show bonding information for a specific peer  
**CLI Command**: `zerotier-cli bond <address> show`

### `/bond/rotate/<address>`
**Methods**: `POST`, `PUT`  
**Description**: Rotate bonding policy for a peer  
**CLI Command**: `zerotier-cli bond <address> rotate`

### `/bond/setmtu/<mtu>/<device>/<address>`
**Methods**: `POST`, `PUT`  
**Description**: Set MTU for a specific bond  
**CLI Command**: `zerotier-cli bond <address> setmtu <mtu> <device>`

---

## Configuration Management

### `/config`
**Methods**: `GET`  
**Description**: Get current configuration  
**CLI Command**: Not directly accessible

### `/config/settings`
**Methods**: `POST`, `PUT`  
**Description**: Update configuration settings  
**CLI Command**: `zerotier-cli set <setting> <value>`

---

## Security and Monitoring

### `/security/events`
**Methods**: `GET`  
**Description**: Get security events  
**CLI Command**: `zerotier-cli security events`

### `/security/metrics`
**Methods**: `GET`  
**Description**: Get security metrics  
**CLI Command**: `zerotier-cli security metrics`

### `/security/threats`
**Methods**: `GET`  
**Description**: Get security threats information  
**CLI Command**: `zerotier-cli security threats`

### `/stats`
**Methods**: `GET`  
**Description**: Get comprehensive peer statistics with advanced aggregation and security monitoring  
**CLI Command**: `zerotier-cli stats`

**Features**:
- **Two-Tier Statistics System**:
  - **Tier 1 (Wire-level)**: All incoming packets including spoofed/malicious (UNTRUSTED)
  - **Tier 2 (Protocol-level)**: Only authenticated ZeroTier packets (TRUSTED)
- **Smart Aggregation**: Compares IP-level vs ZT-address-level stats, uses higher values
- **Infrastructure Filtering**: Excludes IP-level stats for PLANET/MOON nodes
- **Source Indicators**: Shows "i" (IP stats) or "z" (ZT address stats) for transparency
- **Attack Detection**: Divergence analysis between wire and authenticated packet counts
- **Port Usage Tracking**: Detailed port usage statistics per peer
- **Sorting**: Ordered by highest total bytes (RX+TX) using the higher of IP vs ZT stats

**Response Structure**:
```json
{
  "peersByZtAddressAndIP": {
    "abc123def@192.168.1.100": {
      "ztAddress": "abc123def",
      "ipAddress": "192.168.1.100",
      "displayBytesIncoming": 1572864,
      "displayBytesOutgoing": 2097152,
      "rxSource": "i",
      "txSource": "z",
      "isInfrastructureNode": false,
      "WireBytesIncoming": 1572864,
      "WireBytesOutgoing": 2097152,
      "AuthBytesIncoming": 1572864,
      "AuthBytesOutgoing": 2097152,
      "SuspiciousPacketCount": 0,
      "AttackEventCount": 0,
      "MaxDivergenceRatio": 0.0,
      "incomingPorts": {"9993": 45},
      "outgoingPorts": {"9993": 12}
    }
  }
}
```

**Key Fields**:
| Field | Type | Description |
|-------|------|-------------|
| displayBytesIncoming | integer | Higher of IP vs ZT address incoming bytes (use for enforcement) |
| displayBytesOutgoing | integer | Higher of IP vs ZT address outgoing bytes (use for enforcement) |
| rxSource | string | "i" if display RX from IP stats, "z" if from ZT address stats |
| txSource | string | "i" if display TX from IP stats, "z" if from ZT address stats |
| isInfrastructureNode | boolean | True if ZT address is PLANET/MOON (IP stats excluded) |
| WireBytesIncoming/Outgoing | integer | All wire-level packets (includes attacks) |
| AuthBytesIncoming/Outgoing | integer | Only authenticated packets (trusted) |
| SuspiciousPacketCount | integer | Packets that failed authentication |
| AttackEventCount | integer | Number of attack detection events |
| MaxDivergenceRatio | number | Highest wire:auth ratio detected |

**CLI Display Format**:
```
ZT Address IP Address     RX Bytes      TX Bytes      Security Port Usage
---------- --------------- ------------- ------------- -------- ----------
abc123def  192.168.1.100  1.5Mi         2.1Mz         OK       9993:45/12
```
- `1.5Mi` = 1.5MB from IP stats (higher), `2.1Mz` = 2.1MB from ZT stats (higher)
- Security: OK/SUSPECT/MINOR/WARNING/DANGER based on attack detection

**Note**: The `/stats/wire-packets` endpoint has been removed and its functionality merged into `/stats`.

---

## Prometheus Metrics

### `/metrics`
**Methods**: `GET`  
**Description**: Get Prometheus-formatted metrics  
**Authentication**: Requires `metricstoken.secret`  
**CLI Access**: Not directly available via CLI

**Example Usage**:
```bash
# Linux
curl -H "X-ZT1-Auth: $(sudo cat /var/lib/zerotier-one/metricstoken.secret)" http://localhost:9993/metrics

# macOS  
curl -H "X-ZT1-Auth: $(sudo cat /Library/Application\ Support/ZeroTier/One/metricstoken.secret)" http://localhost:9993/metrics

# Windows PowerShell (Admin)
Invoke-RestMethod -Headers @{'X-ZT1-Auth' = "$(Get-Content C:\ProgramData\ZeroTier\One\metricstoken.secret)"; } -Uri http://localhost:9993/metrics
```

---

## Advanced Endpoints

### `/sso`
**Methods**: `GET`  
**Description**: Single Sign-On endpoint for SSO-enabled networks  
**CLI Command**: Not directly accessible

### `/iptables`
**Methods**: `POST`  
**Description**: Configure iptables integration  
**CLI Command**: `zerotier-cli set-iptables-enabled <setting>`

### `/debug/peer`
**Methods**: `GET`  
**Description**: Debug endpoint for peer validation and status checking  
**Parameters**: `?ztaddr=<address>`  
**CLI Command**: Not directly accessible

**Response Example**:
```json
{
  "ztAddress": "abc123def",
  "isValidAddress": true,
  "nodeReady": true,
  "existsInTopology": true,
  "isAlive": true,
  "hasDirectPath": true,
  "remoteVersionKnown": true,
  "remoteVersion": "1.10.6",
  "hasStatsEntry": true,
  "totalIncoming": 1572864,
  "totalOutgoing": 2097152,
  "ipAddressCount": 2,
  "statsPerIP": [
    {
      "ipAddress": "192.168.1.100",
      "totalIncoming": 1048576,
      "totalOutgoing": 1572864
    }
  ]
}
```

### `/debug/lookup`
**Methods**: `GET`  
**Description**: Lookup ZT addresses by IP address or IP addresses by ZT address  
**Parameters**: 
- `?ip=<ip_address>` - Find all ZT addresses for an IP
- `?ztaddr=<address>` - Find all IP addresses for a ZT address
**CLI Command**: Not directly accessible

**Usage Examples**:
```bash
# Find all ZT addresses using IP 192.168.1.100
curl "http://localhost:9993/debug/lookup?ip=192.168.1.100" -H "X-ZT1-Auth: $(cat authtoken.secret)"

# Find all IP addresses for ZT address abc123def
curl "http://localhost:9993/debug/lookup?ztaddr=abc123def" -H "X-ZT1-Auth: $(cat authtoken.secret)"
```

**Response Examples**:

*Lookup by IP*:
```json
{
  "ipAddress": "192.168.1.100",
  "ztAddresses": [
    {
      "ztAddress": "abc123def",
      "isInfrastructure": false
    },
    {
      "ztAddress": "def456abc",
      "isInfrastructure": true
    }
  ]
}
```

*Lookup by ZT Address*:
```json
{
  "ztAddress": "abc123def",
  "ipAddresses": ["192.168.1.100", "10.0.0.50"],
  "isInfrastructure": false
}
```

**Features**:
- **Infrastructure Detection**: Identifies PLANET/MOON nodes
- **Multi-mapping Support**: Shows all associations (one IP can have multiple ZT addresses)
- **Real-time Data**: Uses current statistics database
- **Security Context**: Helps identify potential IP spoofing or relay scenarios

---

## App Server

### `/app/*`
**Methods**: `GET`  
**Description**: Static file server for Single Page Applications  
**Base URL**: `http://localhost:9993/app/<app-path>`

The service can host static web applications in subdirectories under the `app/` folder in the ZeroTier home directory.

---

## Statistics System Architecture

### Two-Tier Statistics Model

ZeroTier One implements a sophisticated two-tier statistics system designed for both bandwidth management and security monitoring:

#### **Tier 1: Wire-Level Statistics (UNTRUSTED)**
- **Purpose**: Network monitoring, attack detection, debugging
- **Scope**: ALL incoming packets that can be attributed to a ZT address
- **Includes**: Spoofed packets, malformed packets, failed authentication, replay attacks
- **Fields**: `WirePacketsIncoming/Outgoing`, `WireBytesIncoming/Outgoing`
- **Use Case**: Detecting unusual traffic patterns, DoS attacks, network diagnostics

#### **Tier 2: Protocol-Level Statistics (TRUSTED)**
- **Purpose**: Bandwidth enforcement, billing, user quotas
- **Scope**: Only cryptographically verified ZeroTier protocol packets
- **Includes**: Successfully authenticated packets only
- **Fields**: `AuthPacketsIncoming/Outgoing`, `AuthBytesIncoming/Outgoing`
- **Use Case**: Accurate bandwidth measurement for enforcement decisions

### Smart Aggregation System

The system aggregates statistics at two levels:

1. **By IP Address**: Sum of all traffic from/to a specific IP address
2. **By ZT Address**: Sum of all traffic from/to a specific ZeroTier address

For each peer entry, the system:
1. Compares IP-level vs ZT-address-level aggregated stats
2. Uses the **higher value** for each direction (RX/TX)
3. Marks the source with indicators: "i" (IP stats) or "z" (ZT address stats)
4. Provides `displayBytesIncoming/Outgoing` fields for enforcement decisions

### Infrastructure Node Filtering

**PLANET and MOON nodes are treated specially**:
- **ZT Address Stats**: Always collected (for monitoring infrastructure health)
- **IP Address Stats**: **EXCLUDED** from aggregation (prevents pollution of IP-based quotas)
- **Rationale**: Infrastructure nodes shouldn't affect per-IP bandwidth analysis
- **Detection**: Uses `topology->role()` to identify `ZT_PEER_ROLE_PLANET`/`ZT_PEER_ROLE_MOON`

### Attack Detection

The system monitors for divergence between wire-level and authenticated packet counts:
- **Divergence Ratio**: `WireBytes / AuthBytes`
- **Thresholds**: 
  - `>= 20.0`: DANGER (severe attack)
  - `>= 5.0`: WARNING (moderate attack)
  - `< 5.0`: MINOR (low-level suspicious activity)
- **Metrics**: Tracks `SuspiciousPacketCount`, `AttackEventCount`, `MaxDivergenceRatio`

### Lookup Functions

The system provides bidirectional lookup capabilities:
- **IP → ZT Addresses**: Find all ZeroTier addresses using a specific IP
- **ZT Address → IPs**: Find all IP addresses used by a ZeroTier address
- **Use Cases**: Security analysis, debugging connectivity issues, identifying relay scenarios

---

## Notes

1. **Regex Patterns**: Many endpoints use regex patterns for parameter validation:
   - `([0-9a-fA-F]{10})` - 10-digit hex addresses (peers, moons)
   - `([0-9a-fA-F]{16})` - 16-digit hex network IDs
   - `([0-9]{1,6})` - MTU values
   - `([a-zA-Z0-9_]{1,16})` - Device names
   - `([0-9a-fA-F\\.\\:]{1,39})` - IP addresses

2. **Controller Endpoints**: If running an embedded controller, additional endpoints are available under `/controller/*` for network and member management.

3. **JSON Type Sensitivity**: All POST/PUT requests are extremely type-sensitive. Ensure proper JSON formatting with correct data types.

4. **JSONP Support**: Add `?jsonp=<callback>` to any GET request for JSONP encapsulation.

5. **IPv6 Support**: All endpoints are available on both IPv4 and IPv6 interfaces with identical functionality.

---

## CLI to API Mapping

| CLI Command | HTTP Endpoint | Method | Notes |
|-------------|---------------|---------|-------|
| `zerotier-cli info` | `/status` | GET | |
| `zerotier-cli listnetworks` | `/network` | GET | |
| `zerotier-cli join <nwid>` | `/network/<nwid>` | POST | |
| `zerotier-cli leave <nwid>` | `/network/<nwid>` | DELETE | |
| `zerotier-cli peers` | `/peer` | GET | |
| `zerotier-cli listmoons` | `/moon` | GET | |
| `zerotier-cli orbit <moon> <seed>` | `/moon/<moon>` | POST | |
| `zerotier-cli deorbit <moon>` | `/moon/<moon>` | DELETE | |
| `zerotier-cli stats` | `/stats` | GET | Enhanced with two-tier stats & infrastructure filtering |
| `zerotier-cli security events` | `/security/events` | GET | |
| `zerotier-cli security metrics` | `/security/metrics` | GET | |
| `zerotier-cli security threats` | `/security/threats` | GET | |
| `zerotier-cli bond <addr> show` | `/bond/show/<addr>` | GET | |
| `zerotier-cli bond <addr> rotate` | `/bond/rotate/<addr>` | POST | |
| N/A | `/debug/peer?ztaddr=<addr>` | GET | Debug peer validation & stats |
| N/A | `/debug/lookup?ip=<ip>` | GET | Find ZT addresses for IP |
| N/A | `/debug/lookup?ztaddr=<addr>` | GET | Find IPs for ZT address |

This comprehensive reference should help developers integrate with the ZeroTier One service API effectively. 