/*
 * Copyright (c)2024 ZeroTier, Inc.
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

#ifndef ZT_IPTABLESMANAGER_HPP
#define ZT_IPTABLESMANAGER_HPP

#include <string>
#include <set>
#include <vector>
#include <memory>
#include <sstream>
#include "../node/InetAddress.hpp"
#include "../node/Mutex.hpp"

namespace ZeroTier {

/**
 * Firewall type enumeration
 */
enum class FirewallType {
    IPTABLES,  // iptables + ipset
    NFTABLES   // nftables with built-in sets
};

/**
 * Manages firewall rules for ZeroTier peer communication
 *
 * Supports both iptables (with ipsets) and nftables (with built-in sets).
 * Automatically detects which firewall system is in use.
 * Uses sets for efficient peer management instead of individual rules per peer.
 * Supports multiple UDP ports (primary, secondary, tertiary).
 */
class IptablesManager
{
public:
    /**
     * Constructor
     *
     * @param wanInterface Name of the WAN interface (e.g., "eth0", "enp3s0")
     * @param udpPorts Vector of UDP ports ZeroTier is listening on
     */
    explicit IptablesManager(const std::string& wanInterface, const std::vector<unsigned int>& udpPorts);

    /**
     * Destructor - cleans up all iptables rules and ipsets
     */
    ~IptablesManager() noexcept;

    /**
     * Move constructor
     */
    IptablesManager(IptablesManager&& other) noexcept;

    /**
     * Move assignment operator
     */
    IptablesManager& operator=(IptablesManager&& other) noexcept;

    /**
     * Add or remove a peer IP address from the allowed list
     *
     * @param ipString IP address string for ipset command
     * @param add True to add peer, false to remove peer
     * @return True if peer was actually added/removed (false if already existed/didn't exist)
     */
    bool updatePeer(const std::string& ipString, bool add);

    /**
     * Update the list of UDP ports (e.g., when secondary port changes)
     *
     * @param udpPorts New list of UDP ports
     * @return True if ports were updated successfully
     */
    bool updateUdpPorts(const std::vector<unsigned int>& udpPorts);

    /**
     * Update the WAN interface (e.g., when network configuration changes)
     *
     * @param wanInterface New WAN interface name
     * @return True if interface was updated successfully
     */
    bool updateWanInterface(const std::string& wanInterface);

    /**
     * Get the WAN interface name
     *
     * @return WAN interface name
     */
    inline const std::string& getWanInterface() const noexcept { return _wanInterface; }

    /**
     * Get the current UDP ports
     *
     * @return Vector of current UDP ports
     */
    inline const std::vector<unsigned int>& getUdpPorts() const noexcept { return _udpPorts; }

    /**
     * Get the firewall type (iptables or nftables)
     *
     * @return FirewallType enum value
     */
    inline FirewallType getFirewallType() const noexcept { return _firewallType; }

    /**
     * Check if firewall rules exist and restore them if they were deleted
     * This is useful for recovery after firewall reset or similar commands
     *
     * @return True if rules exist or were successfully restored
     */
    bool checkAndRestoreRules();

private:
    /**
     * Detect which firewall system is in use (iptables or nftables)
     *
     * @return FirewallType enum value
     */
    static FirewallType detectFirewallType();

    /**
     * Execute a shell command
     *
     * @param command The command to execute
     * @return True if command executed successfully
     */
    bool executeCommand(const std::string& command) const;

    /**
     * Initialize the firewall rules (ipset/iptables or nftables set/rules)
     */
    void initializeRules();

    /**
     * Clean up all firewall rules and sets
     * Called on service shutdown
     */
    void cleanup();

    /**
     * Clean up any existing firewall rules and sets from previous runs
     * Called during initialization to handle unclean shutdowns
     */
    void cleanupExistingRules();

    /**
     * Perform the actual cleanup of firewall rules and sets
     * Shared implementation used by both cleanup() and cleanupExistingRules()
     */
    void performCleanup();

    /**
     * Create firewall rules for the current UDP ports (iptables or nftables)
     */
    void createFirewallRules();

    /**
     * Create iptables rules for the current UDP ports
     */
    void createIptablesRules();

    /**
     * Create nftables rules for the current UDP ports
     */
    void createNftablesRules();

    /**
     * Efficiently replace the multiport rule with new ports (1 command)
     */
    bool replaceMultiportRule(const std::vector<unsigned int>& newPorts);

    /**
     * Fallback: Create individual iptables rules for each port (compatibility)
     */
    void createIndividualPortRules();

    /**
     * Remove firewall rules for the current UDP ports (iptables or nftables)
     */
    void removeFirewallRules();

    /**
     * Remove iptables rules for the current UDP ports
     */
    void removeIptablesRules();

    /**
     * Remove nftables rules for the current UDP ports
     */
    void removeNftablesRules();

    /**
     * Build multiport rule strings for LOG and ACCEPT
     *
     * @param portList Comma-separated list of ports
     * @param logRule Output stream for LOG rule
     * @param acceptRule Output stream for ACCEPT rule
     * @param useAppend If true, use -A (append), if false, use -R (replace)
     * @param ruleNumbers If using replace, the rule numbers (1 for LOG, 2 for ACCEPT)
     */
    void buildMultiportRules(const std::string& portList, std::stringstream& logRule,
                           std::stringstream& acceptRule, bool useAppend = true,
                           int logRuleNumber = 1, int acceptRuleNumber = 2);

    std::string _wanInterface;
    std::vector<unsigned int> _udpPorts;
    bool _initialized;
    FirewallType _firewallType;

    // Peer tracking to avoid redundant set commands
    std::set<std::string> _activePeers;
    mutable Mutex _peers_mutex;

    // Disable copy constructor and assignment operator
    IptablesManager(const IptablesManager&) = delete;
    IptablesManager& operator=(const IptablesManager&) = delete;
};

} // namespace ZeroTier

#endif
