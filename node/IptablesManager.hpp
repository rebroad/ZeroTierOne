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
#include <mutex>
#include <memory>
#include "../node/InetAddress.hpp"
#include "../node/Mutex.hpp"

namespace ZeroTier {

/**
 * Manages iptables rules for ZeroTier peer connections
 *
 * This class automatically adds iptables rules to allow incoming traffic
 * from ZeroTier peers on the WAN interface, and removes them when peers disconnect.
 */
class IptablesManager
{
public:
    /**
     * Constructor
     *
     * @param wanInterface Name of the WAN interface (e.g., "eth0", "enp3s0")
     * @param udpPort UDP port ZeroTier is listening on (default: 9993)
     */
    IptablesManager(const std::string& wanInterface, unsigned int udpPort = 9993);

    /**
     * Destructor - cleans up all iptables rules
     */
    ~IptablesManager();

    /**
     * Add iptables rule for a peer
     *
     * @param peerAddress IP address of the peer
     * @return True if rule was added successfully
     */
    bool addPeerRule(const InetAddress& peerAddress);

    /**
     * Remove iptables rule for a peer
     *
     * @param peerAddress IP address of the peer
     * @return True if rule was removed successfully
     */
    bool removePeerRule(const InetAddress& peerAddress);

    /**
     * Check if a peer rule exists
     *
     * @param peerAddress IP address of the peer
     * @return True if rule exists
     */
    bool hasPeerRule(const InetAddress& peerAddress) const;

    /**
     * Get the WAN interface name
     *
     * @return WAN interface name
     */
    inline const std::string& getWanInterface() const { return _wanInterface; }

    /**
     * Get the UDP port
     *
     * @return UDP port
     */
    inline unsigned int getUdpPort() const { return _udpPort; }

    /**
     * Set the WAN interface name
     *
     * @param wanInterface New WAN interface name
     */
    void setWanInterface(const std::string& wanInterface);

    /**
     * Set the UDP port
     *
     * @param udpPort New UDP port
     */
    void setUdpPort(unsigned int udpPort);

    /**
     * Get the number of active peer rules
     *
     * @return Number of active rules
     */
    inline size_t getActiveRuleCount() const {
        Mutex::Lock _l(_rules_mutex);
        return _activeRules.size();
    }

    /**
     * Clean up all iptables rules created by this manager
     * Called on service shutdown
     */
    void cleanup();

private:
    /**
     * Execute an iptables command
     *
     * @param command The iptables command to execute
     * @return True if command executed successfully
     */
    bool executeIptablesCommand(const std::string& command) const;

    /**
     * Generate iptables rule string for adding a peer
     *
     * @param peerAddress IP address of the peer
     * @return iptables command string
     */
    std::string generateAddRuleCommand(const InetAddress& peerAddress) const;

    /**
     * Generate iptables rule string for removing a peer
     *
     * @param peerAddress IP address of the peer
     * @return iptables command string
     */
    std::string generateRemoveRuleCommand(const InetAddress& peerAddress) const;

    /**
     * Sanitize IP address for use in shell commands
     *
     * @param addr IP address to sanitize
     * @return Sanitized IP address string
     */
    std::string sanitizeIpAddress(const InetAddress& addr) const;

    std::string _wanInterface;
    unsigned int _udpPort;
    std::set<InetAddress> _activeRules;
    mutable Mutex _rules_mutex;

    // Disable copy constructor and assignment operator
    IptablesManager(const IptablesManager&) = delete;
    IptablesManager& operator=(const IptablesManager&) = delete;
};

} // namespace ZeroTier

#endif
