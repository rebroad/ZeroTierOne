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

#include "../node/InetAddress.hpp"
#include "../node/Mutex.hpp"
#include <string>
#include <set>
#include <memory>

// iptables C library headers
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_state.h>
#include <linux/netfilter/xt_conntrack.h>
#include <linux/netfilter/xt_tcpudp.h>

namespace ZeroTier {

/**
 * Manages iptables rules for ZeroTier peer connections
 * Uses libiptc for direct kernel communication instead of shell commands
 */
class IptablesManager
{
public:
    /**
     * Constructor
     * @param wanInterface The WAN interface name
     * @param udpPort The UDP port to protect
     */
    IptablesManager(const std::string& wanInterface, unsigned int udpPort);

    /**
     * Destructor - cleans up iptables rules
     */
    ~IptablesManager();

    /**
     * Add an iptables rule for a specific peer
     * @param peerAddress The peer's IP address
     * @return true if successful, false otherwise
     */
    bool addPeerRule(const InetAddress& peerAddress);

    /**
     * Remove an iptables rule for a specific peer
     * @param peerAddress The peer's IP address
     * @return true if successful, false otherwise
     */
    bool removePeerRule(const InetAddress& peerAddress);

    /**
     * Check if a peer rule exists
     * @param peerAddress The peer's IP address
     * @return true if rule exists, false otherwise
     */
    bool hasPeerRule(const InetAddress& peerAddress) const;

    /**
     * Update the WAN interface
     * @param wanInterface The new WAN interface name
     */
    void setWanInterface(const std::string& wanInterface);

    /**
     * Update the UDP port
     * @param udpPort The new UDP port
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

private:
    std::string _wanInterface;
    unsigned int _udpPort;
    mutable Mutex _rules_mutex;
    std::set<InetAddress> _activeRules;

    /**
     * Initialize the iptables chain and basic rules
     */
    bool initializeChain();

    /**
     * Clean up all iptables rules and chains
     */
    void cleanup();

    /**
     * Create an iptables rule entry for a peer
     * @param peerAddress The peer's IP address
     * @return Pointer to allocated ipt_entry, or nullptr on failure
     */
    struct ipt_entry* createPeerRule(const InetAddress& peerAddress) const;

    /**
     * Get the iptc handle for the filter table
     * @return Pointer to iptc_handle, or nullptr on failure
     */
    struct iptc_handle* getIptcHandle() const;

    /**
     * Sanitize IP address for use in rules
     * @param addr The address to sanitize
     * @return Sanitized IP address string
     */
    std::string sanitizeIpAddress(const InetAddress& addr) const;

    // Disable copy constructor and assignment operator
    IptablesManager(const IptablesManager&) = delete;
    IptablesManager& operator=(const IptablesManager&) = delete;
};

} // namespace ZeroTier

#endif // ZT_IPTABLESMANAGER_HPP
