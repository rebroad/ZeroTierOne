# Stats Collection Architecture (Current + Improvement Plan)

This document describes how stats are collected in the current code (`service/OneService.cpp`) and where we can improve CPU/memory efficiency.

## 1. Collection Points

Stats/log updates currently happen at two transport/control-plane points:

- Incoming UDP path:
  - `phyOnDatagram()` calls `_handlePacketAtLayer7(...)` for authenticated packets.
  - Local port comes from `localAddr.port()` (reliable).
- Outgoing UDP path:
  - `nodeWirePacketSendFunction()` calls `_handlePacketAtLayer7(...)` after send result is known.
  - If a specific socket is used, local port is obtained from that socket.
  - If `udpSendAll` is used, each bound local port is reported via observer callback.

Related first-seen debug logs:

- `PACKET_TO` and `PACKET_FROM` include:
  - `remote_ip`
  - `remote_port`
  - `peer` (ZT address)
  - `local_port`

## 2. Keys and Aggregation

Primary stats map:

- `_peerStats: map<pair<Address, InetAddress>, PeerStats>`
- Key is `(ztAddr, ipOnly(remote))` (remote port stripped for stats keying).

First-seen dedupe sets:

- `_seenIncomingPeerPorts: set<((ztAddr, fullRemoteIpPort), localPort)>`
- `_seenOutgoingPeerPorts: set<((ztAddr, fullRemoteIpPort), localPort)>`

This means:

- Stats aggregate by peer+remote IP (port-agnostic),
- while logging dedupe remains per peer+remote endpoint+local source port.

## 3. What `/stats` Currently Returns

`/stats` returns:

- Port configuration (`primary/secondary/tertiary`, `actualBoundPorts`)
- `peersByZtAddressAndIP` array with display bytes/source flags
- Diagnostics counts (table sizes and unique key counts)

## 4. Current Gaps

Some `PeerStats` fields are present but not actively maintained in the current path:

- `WireBytesIncoming`, `WireBytesOutgoing`, `AuthBytesIncoming`, `AuthBytesOutgoing`
- `wireIncomingPortCounts`, `wireOutgoingPortCounts`, etc.

`/stats` still computes display bytes from those fields, so byte values can be under-populated unless other code paths update them.

## 5. Efficiency Review

### Current data-structure cost profile

- `std::map` and `std::set` incur node allocations and pointer chasing.
- Per-packet updates lock `_peerStats_m` and update tree-based containers.
- Dedupe sets can grow without explicit aging.

### Recommended improvements

1. Replace tree containers with hash containers.

- `std::unordered_map` / `std::unordered_set` for `_peerStats` and dedupe sets.
- Add custom hash for `(Address, InetAddress)` and nested tuple key.

2. Add bounded retention / TTL for dedupe sets.

- Keep only recent N entries or expire by timestamp.
- Prevent unbounded memory growth.

3. Keep integer counters in fixed structs where possible.

- Avoid per-key nested maps for ports unless needed.
- If only known local ports matter, use fixed slots for primary/secondary/tertiary + "other".

4. Separate hot-path writes from heavy aggregation.

- Fast-path counters only on packet events.
- Build expensive report views lazily for `/stats` calls.

5. Consider lock sharding.

- Shard by hash bucket for high packet-rate systems.
- Reduces contention vs single global mutex.

## 6. Tier Naming Guidance

Historically this code uses "Tier 1 / Tier 2" labels:

- Tier 1: wire/transport observation (pre-auth)
- Tier 2: authenticated protocol-level observation

For clarity, prefer explicit names in docs and code comments:

- `wire_observed` (pre-auth)
- `authenticated_zt` (post-auth)

This is clearer than OSI references here, because these counters are about trust stage, not strict OSI layer semantics.

## 7. Suggested Migration Direction

Best practical direction:

- Keep wire-level collection for complete visibility,
- attach authenticated identity when available,
- and expose both perspectives in `/stats`.

That gives the strongest debugging/security value without losing observability on failed/spoofed traffic.

