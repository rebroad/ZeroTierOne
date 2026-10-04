# Peer UDP Port Statistics

`/stats` and `zerotier-cli stats` report successfully authenticated incoming packets and successfully sent outgoing packets. The aggregate table correlates a ZeroTier peer with a remote IP and local UDP ports. A separate endpoint table retains the full remote IP and UDP port, correlated with the peer's ZeroTier address and the local ports used for incoming and outgoing packets. Unauthenticated packets are excluded. Counters are in memory and reset when the service restarts.

## Collection points

- Incoming UDP: `phyOnDatagram()` passes the receiving local port to `Node::processWirePacket()`. That call returns the source peer only after packet authentication succeeds. The packet's source `InetAddress` supplies the remote IP and UDP port.
- Outgoing UDP: `nodeWirePacketSendFunction()` supplies the peer and destination `InetAddress` after a successful send. A specific socket supplies the local port; `udpSendAll()` reports each bound local port through its observer callback.

## Keys and output

`peersByZtAddressAndIP` is keyed by `(peer ZeroTier address, remote IP)` and preserves the existing aggregate behavior. `peersByZtAddressAndEndpoint` is keyed by `(peer ZeroTier address, full remote IP and UDP port)`. Endpoint rows include the remote port plus incoming and outgoing counts indexed by local UDP port. The endpoint table retains at most 4096 rows and evicts the least recently observed row when full; the aggregate table has its own 4096-row bound.

The `/stats` endpoint uses the normal authenticated control-plane access policy. `zerotier-cli stats` prints both aggregate and endpoint views; `zerotier-cli -j stats` prints the JSON response. The observed remote port is the source/destination UDP port of ZeroTier wire traffic, not an application port exposed by the peer.
