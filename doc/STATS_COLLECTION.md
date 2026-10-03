# Peer UDP Port Statistics

`/stats` and `zerotier-cli stats` report successful authenticated UDP packet counts by peer, remote IP, and local UDP port. Counters are held in memory and reset when the service restarts. The service retains at most 4096 peer/IP rows and evicts the least recently observed row when a new row exceeds that limit. Unauthenticated packets are excluded because they cannot be safely attributed to a peer.

## Collection points

- Incoming UDP: `phyOnDatagram()` passes the receiving local port to `Node::processWirePacket()`. That call returns the source peer only after packet authentication succeeds.
- Outgoing UDP: `nodeWirePacketSendFunction()` reads the packet destination and records successful sends. A specific socket supplies its local port; `udpSendAll()` reports each bound socket through its observer callback.

## Keys and output

The service keys rows by `(peer ZeroTier address, remote IP address)`. Remote UDP port is excluded. Each row contains incoming and outgoing packet counts keyed by local UDP port, the last observation time, and counts for the configured primary, secondary, and tertiary ports.

The `/stats` endpoint uses the normal authenticated control-plane access policy. `zerotier-cli stats` renders the peer/IP rows; `zerotier-cli -j stats` prints the JSON response.

## Limits and future work

The endpoint reports packet counts only. It does not report byte totals, unauthenticated wire observations, overlay traffic, or attack/divergence analysis. Those fields appeared in the older experimental implementation but were not reliably maintained there. If unauthenticated observations are added later, they must remain separate from authenticated peer attribution.

The implementation uses ordered maps and a mutex on the packet path. Consider changing those structures only if profiling shows they are a bottleneck.
