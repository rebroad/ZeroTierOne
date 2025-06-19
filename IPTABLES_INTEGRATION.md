# ZeroTier One Iptables Integration

This feature automatically manages iptables rules and ipsets to allow incoming traffic from ZeroTier peers on the WAN interface.

## Overview

When enabled, ZeroTier One will automatically:
- Create an ipset (`zt_peers`) containing allowed ZeroTier peer IP addresses
- Add iptables rules using the ipset to allow incoming UDP traffic on multiple ports
- Use connection tracking for efficient packet filtering
- Dynamically add/remove peer IP addresses from the ipset as peers connect/disconnect
- Clean up all rules and ipsets when the service shuts down

## Architecture

The implementation uses:
- **ipset**: A single `zt_peers` ipset containing all allowed peer IP addresses
- **Custom iptables chain**: `zt_rules` chain for organized rule management
- **Connection tracking**: ESTABLISHED,RELATED state tracking for efficient filtering
- **Multiple port support**: Handles primary, secondary, and tertiary UDP ports

## Configuration

### Method 1: Configuration File

Add the following settings to your `local.conf` file:

```json
{
  "settings": {
    "iptablesEnabled": true,
    "iptablesWanInterface": "auto"
  }
}
```

### Method 2: CLI Command

```bash
# Enable with auto-detection
sudo zerotier-cli set-iptables-enabled auto

# Enable with specific interface
sudo zerotier-cli set-iptables-enabled eth0

# Disable
sudo zerotier-cli set-iptables-enabled false
```

### Method 3: HTTP API

```bash
# Enable with auto-detection
curl -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"settings":{"iptablesEnabled":true,"iptablesWanInterface":"auto"}}' \
     http://localhost:9993/iptables

# Enable with specific interface
curl -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"settings":{"iptablesEnabled":true,"iptablesWanInterface":"eth0"}}' \
     http://localhost:9993/iptables
```

### Settings

- `iptablesEnabled`: Set to `true` to enable iptables integration (default: `false`)
- `iptablesWanInterface`: WAN interface name or `"auto"` for auto-detection (default: `"auto"`)

## Requirements

- Root privileges (required to modify iptables and ipsets)
- Linux system with iptables and ipset
- Valid WAN interface (auto-detected if not specified)

## How It Works

### 1. Initialization
- Creates ipset: `ipset create zt_peers hash:ip family inet hashsize 1024 maxelem 65536`
- Creates custom chain: `iptables -N zt_rules`
- Adds jump rule: `iptables -I INPUT 1 -j zt_rules`
- Adds connection tracking: `iptables -A zt_rules -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`

### 2. Port Rules
For each active UDP port (primary, secondary, tertiary), creates:
```bash
iptables -A zt_rules -i <wan_interface> -p udp --dport <port> \
  -m set --match-set zt_peers src -m conntrack --ctstate NEW -j ACCEPT
```

### 3. Peer Management
- **Add peer**: `ipset add zt_peers <peer_ip>`
- **Remove peer**: `ipset del zt_peers <peer_ip>`

### 4. Dynamic Updates
- Port changes (secondary port randomization) automatically update rules
- WAN interface changes update rules without restart
- All changes are applied atomically

### 5. Cleanup
- Removes jump rule from INPUT chain
- Flushes and deletes custom chain
- Destroys ipset

## Interface Auto-Detection

When `iptablesWanInterface` is set to `"auto"` (default), ZeroTier will:
1. Execute `ip route get 8.8.8.8` to find the primary route
2. Extract the interface name from the route output
3. Use that interface for iptables rules

## Multiple Port Support

The system automatically handles:
- **Primary port**: Main ZeroTier UDP port (usually 9993)
- **Secondary port**: Randomized port for NAT traversal
- **Tertiary port**: UPnP/NAT-PMP mapped port

Rules are automatically updated when ports change (e.g., secondary port randomization).

## Security Considerations

- Only allows UDP traffic on ZeroTier ports
- Only allows traffic from known ZeroTier peer IP addresses (via ipset)
- Uses connection tracking to allow only NEW connections inbound
- Established/related traffic is handled efficiently
- Interface names are validated to prevent command injection
- Rules are automatically cleaned up when peers disconnect

## Troubleshooting

### Check if ipset is created:
```bash
sudo ipset list zt_peers
```

### Check if rules are active:
```bash
sudo iptables -L zt_rules -n --line-numbers
```

### Check peer IPs in ipset:
```bash
sudo ipset list zt_peers -t
```

### Check INPUT chain jump rule:
```bash
sudo iptables -L INPUT -n --line-numbers | grep zt_rules
```

### Manual cleanup (if needed):
```bash
# Remove rules and ipset
sudo iptables -D INPUT -j zt_rules 2>/dev/null
sudo iptables -F zt_rules 2>/dev/null
sudo iptables -X zt_rules 2>/dev/null
sudo ipset destroy zt_peers 2>/dev/null
```

### Check logs:
Look for messages like:
- "INFO: Iptables manager initialized with WAN interface 'X' and N UDP ports"
- "INFO: Auto-detected WAN interface 'X' for iptables"
- "INFO: Added iptables rule for peer X"
- "INFO: Removed iptables rule for peer X"
- "WARNING: Failed to add/remove iptables rule for peer X"

## Example Configurations

### Basic setup with auto-detection:
```json
{
  "settings": {
    "iptablesEnabled": true
  }
}
```

### Specific interface:
```json
{
  "settings": {
    "iptablesEnabled": true,
    "iptablesWanInterface": "ens3"
  }
}
```

## Runtime Management

### Get current status:
```bash
sudo zerotier-cli info
```

### Enable/disable without restart:
```bash
# Enable
sudo zerotier-cli set-iptables-enabled auto

# Disable  
sudo zerotier-cli set-iptables-enabled false
```

### Check active peers:
```bash
sudo zerotier-cli listpeers
```

## Notes

- Requires ZeroTier One to run with root privileges
- The WAN interface must exist and be accessible
- IPv4 only (IPv6 support can be added later)
- Uses modern iptables features (ipset, conntrack)
- Automatically handles port changes and interface updates
- Configuration changes take effect immediately without service restart 