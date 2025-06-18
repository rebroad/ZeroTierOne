# ZeroTier One Iptables Integration

This feature automatically manages iptables rules to allow incoming traffic from ZeroTier peers on the WAN interface.

## Overview

When enabled, ZeroTier One will automatically:
- Add iptables rules to allow incoming UDP traffic from peer IP addresses on the configured WAN interface
- Remove iptables rules when peers disconnect
- Clean up all rules when the service shuts down

## Configuration

Add the following settings to your `local.conf` file:

```json
{
  "settings": {
    "iptablesEnabled": true,
    "iptablesWanInterface": "eth0",
    "iptablesUdpPort": 9993
  }
}
```

### Settings

- `iptablesEnabled`: Set to `true` to enable iptables integration (default: `false`)
- `iptablesWanInterface`: The name of your WAN interface (default: `eth0`)
- `iptablesUdpPort`: The UDP port ZeroTier is listening on (default: `9993`)

## Requirements

- Root privileges (required to modify iptables)
- Linux system with iptables
- Valid WAN interface name

## How It Works

1. When a peer connects and a path is discovered, ZeroTier adds an iptables rule:
   ```
   iptables -I INPUT -i <wan_interface> -s <peer_ip> -p udp --dport <udp_port> -j ACCEPT
   ```

2. When a peer disconnects or the path expires, ZeroTier removes the rule:
   ```
   iptables -D INPUT -i <wan_interface> -s <peer_ip> -p udp --dport <udp_port> -j ACCEPT
   ```

3. On service shutdown, all rules created by ZeroTier are automatically removed.

## Security Considerations

- Only allows UDP traffic on the specified port
- Only allows traffic from known ZeroTier peer IP addresses
- Rules are automatically cleaned up when peers disconnect
- Interface name is validated to prevent command injection

## Troubleshooting

### Check if rules are being added:
```bash
sudo iptables -L INPUT -n --line-numbers | grep zerotier
```

### Manual cleanup (if needed):
```bash
sudo iptables -D INPUT -i <wan_interface> -s <peer_ip> -p udp --dport <udp_port> -j ACCEPT
```

### Check logs:
Look for messages like:
- "INFO: Added iptables rule for peer <ip>"
- "INFO: Removed iptables rule for peer <ip>"
- "WARNING: Failed to add/remove iptables rule for peer <ip>"

## Example Configuration

For a system with WAN interface `ens3` and ZeroTier listening on port `9993`:

```json
{
  "settings": {
    "iptablesEnabled": true,
    "iptablesWanInterface": "ens3",
    "iptablesUdpPort": 9993
  }
}
```

## Notes

- This feature requires ZeroTier One to run with root privileges
- The WAN interface must exist and be accessible
- Rules are added to the INPUT chain
- Only UDP traffic is allowed (ZeroTier's protocol)
- Rules are specific to the configured port 