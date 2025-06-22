# ZeroTier Metrics Documentation

This document provides a comprehensive overview of all metrics available in ZeroTier, their purposes, and how they differ from each other.

## Overview

ZeroTier uses Prometheus-compatible metrics to provide detailed monitoring and observability. Metrics are available at the `/metrics` API endpoint and are also written to disk as `metrics.prom` in the ZeroTier working directory.

## Metric Categories

### 1. Packet Type Metrics (`zt_packet`)

**Purpose**: Monitor ZeroTier protocol message exchanges by packet type and direction.

**Labels**: 
- `packet_type`: The ZeroTier protocol message type (hello, ok, frame, etc.)
- `direction`: `rx` (incoming) or `tx` (outgoing)

**Key Packet Types**:
- `hello`: Initial peer discovery and keepalive messages
- `ok`: Acknowledgment responses  
- `frame`/`ext_frame`: Actual network data frames
- `whois`: Peer identity lookup requests
- `network_config_request`: Network configuration requests
- `push_direct_paths`: Direct path advertisements

**Use Cases**:
- Monitor protocol health and message flow
- Identify peers having connectivity issues (missing hellos/oks)
- Track network data volume (frame packets)

### 2. Protocol Error Metrics (`zt_packet_error`)

**Purpose**: Track ZeroTier protocol-level errors and authentication failures.

**Labels**:
- `error_type`: The specific error type
- `direction`: `rx` (incoming) or `tx` (outgoing)

**Common Error Types**:
- `authentication_required`: Peer authentication failures
- `network_access_denied`: Network access authorization failures
- `obj_not_found`: Requests for unknown objects/peers
- `need_membership_cert`: Missing network membership certificates

**Use Cases**:
- Monitor authentication and authorization issues
- Identify configuration problems
- Track security-related events

### 3. Physical Transport Metrics (`zt_data`)

**Purpose**: Monitor raw bandwidth usage at the UDP/TCP transport layer.

**Labels**:
- `protocol`: `udp` or `tcp`
- `direction`: `rx` (received) or `tx` (sent)

**Important Note**: These metrics track actual bytes on the wire, including ZeroTier protocol overhead, encryption, and headers. This is different from application-level data.

**Use Cases**:
- Monitor total bandwidth consumption
- Compare UDP vs TCP usage
- Track physical network utilization

### 4. Wire Packet Processing Metrics (`zt_wire_packets`, `zt_wire_packet_bytes`)

**Purpose**: Detailed tracking of packet processing results with peer-specific information.

**Labels**:
- `peer_zt_addr`: ZeroTier address of the peer
- `peer_ip`: Physical IP address of the peer  
- `direction`: Currently `rx` (incoming packets)
- `result`: `ok` (successful processing) or `error` (failed processing)

**Key Differences from Other Metrics**:
- Tracks raw wire packets before/after processing
- Includes both successful and failed processing attempts
- Provides peer-specific granularity with both ZT address and IP
- Useful for debugging relay scenarios and processing failures

**Use Cases**:
- Monitor packet processing success rates per peer
- Identify problematic peers sending malformed packets
- Track relay scenarios (when physical IP differs from logical peer)
- Debug connectivity issues with specific peers

### 5. Per-Peer Metrics (when `ZT_NO_PEER_METRICS` is not defined)

#### Peer Latency (`zt_peer_latency`)
**Purpose**: Histogram of round-trip times to peers.
**Labels**: `node_id` (peer ZeroTier address)
**Use Cases**: Monitor network quality, identify high-latency peers

#### Peer Path Count (`zt_peer_path_count`) 
**Purpose**: Number of network paths to each peer.
**Labels**: `node_id` (peer address), `status` (`alive` or `dead`)
**Use Cases**: Monitor path redundancy, connectivity health

#### Peer Packets (`zt_peer_packets`)
**Purpose**: Successful ZeroTier protocol exchanges with peers.
**Labels**: `direction` (`rx`/`tx`), `node_id` (peer address)

**Key Differences from Wire Packet Metrics**:
- Only counts successful protocol exchanges (after processing)
- Incremented in `Peer::received()` and `Peer::recordOutgoingPacket()`
- No IP address information (only ZeroTier addresses)
- No failed processing attempts

**Use Cases**: Monitor successful communication patterns with specific peers

#### Peer Packet Errors (`zt_peer_packet_errors`)
**Purpose**: Processing errors from specific peers.
**Labels**: `node_id` (peer address)
**Use Cases**: Identify peers sending malformed packets

### 6. Network Metrics

- `zt_num_networks`: Number of networks joined
- `zt_network_multicast_groups_subscribed`: Multicast group subscriptions per network
- `zt_network_packets`: Packet counts per network

### 7. Controller Metrics

Available when running as a network controller, tracking network and member management operations, database interactions, and SSO functionality.

## Metric Comparison: Understanding the Differences

### Wire Packets vs Peer Packets vs Protocol Packets

1. **Protocol Packets (`zt_packet`)**:
   - Counts by ZeroTier message type (hello, frame, etc.)
   - No peer-specific information
   - Global counters for protocol message types

2. **Peer Packets (`zt_peer_packets`)**:
   - Counts successful exchanges with specific peers
   - Only ZeroTier addresses (no IP information)
   - Only successful processing (no errors)

3. **Wire Packets (`zt_wire_packets`)**:
   - Counts all processing attempts (success + failure)
   - Includes both ZeroTier address and physical IP
   - Useful for debugging relay scenarios
   - Tracks processing results

### Transport Data vs Wire Packet Bytes

- **Transport Data (`zt_data`)**: Raw UDP/TCP bytes including all overhead
- **Wire Packet Bytes (`zt_wire_packet_bytes`)**: ZeroTier packet payload sizes with peer context

## Accessing Metrics

### HTTP Endpoint
```bash
curl -H "X-ZT1-Auth: $(cat /var/lib/zerotier-one/metricstoken.secret)" \
     http://localhost:9993/metrics
```

### File System
- Linux: `/var/lib/zerotier-one/metrics.prom`
- macOS: `/Library/Application Support/ZeroTier/One/metrics.prom`  
- Windows: `C:\ProgramData\ZeroTier\One\metrics.prom`

## Common Use Cases

### Monitoring Peer Connectivity
- Use `zt_peer_path_count` for path redundancy
- Use `zt_peer_latency` for network quality
- Use `zt_peer_packets` for successful communication
- Use `zt_wire_packets` for processing success rates

### Debugging Packet Processing Issues
- Compare `zt_wire_packets{result="ok"}` vs `zt_wire_packets{result="error"}`
- Check `zt_peer_packet_errors` for problematic peers
- Use `zt_packet_error` for protocol-level issues

### Bandwidth Monitoring
- Use `zt_data` for total physical bandwidth
- Use `zt_wire_packet_bytes` for peer-specific traffic analysis
- Use `zt_network_packets` for per-network traffic

### Authentication/Security Monitoring
- Monitor `zt_packet_error{error_type="authentication_required"}`
- Track `zt_packet_error{error_type="network_access_denied"}`
- Watch for unusual patterns in error metrics 