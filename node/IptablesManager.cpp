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

#include "IptablesManager.hpp"
#include "Utils.hpp"
#include "../osdep/OSUtils.hpp"

#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace ZeroTier {

IptablesManager::IptablesManager(const std::string& wanInterface, const std::vector<unsigned int>& udpPorts)
    : _wanInterface(wanInterface)
    , _udpPorts(udpPorts)
    , _initialized(false)
{
    // Validate WAN interface name to prevent command injection
    if (_wanInterface.empty() || _wanInterface.find_first_of(";|&`$()<>") != std::string::npos) {
        throw std::invalid_argument("Invalid WAN interface name");
    }

    // Validate UDP ports
    for (unsigned int port : _udpPorts) {
        if (port == 0 || port > 65535) {
            throw std::invalid_argument("Invalid UDP port number: " + std::to_string(port));
        }
    }

    // Remove duplicates and sort ports
    std::sort(_udpPorts.begin(), _udpPorts.end());
    _udpPorts.erase(std::unique(_udpPorts.begin(), _udpPorts.end()), _udpPorts.end());

    // Clean up any existing rules from previous runs (in case of unclean shutdown)
    // Use a lock to prevent race conditions during initialization
    {
        Mutex::Lock _l(_peers_mutex);
        cleanupExistingRules();

        // Initialize the ipset and iptables rules
        initializeRules();
    }
}

IptablesManager::~IptablesManager() noexcept
{
    cleanup();
}

IptablesManager::IptablesManager(IptablesManager&& other) noexcept
    : _wanInterface(std::move(other._wanInterface))
    , _udpPorts(std::move(other._udpPorts))
    , _activePeers(std::move(other._activePeers))
    , _initialized(other._initialized)
{
    // Clear the other object's data to prevent double cleanup
    other._initialized = false;
    other._udpPorts.clear();
    other._activePeers.clear();
}

IptablesManager& IptablesManager::operator=(IptablesManager&& other) noexcept
{
    if (this != &other) {
        // Clean up our existing rules
        cleanup();

        // Move data from other
        _wanInterface = std::move(other._wanInterface);
        _udpPorts = std::move(other._udpPorts);
        _activePeers = std::move(other._activePeers);
        _initialized = other._initialized;

        // Clear the other object's data
        other._initialized = false;
        other._udpPorts.clear();
        other._activePeers.clear();
    }
    return *this;
}

bool IptablesManager::addPeer(const InetAddress& peerAddress)
{
    if (!peerAddress) {
        return false;
    }

    // Only handle IPv4 addresses for now (IPv6 support can be added later)
    if (peerAddress.ss_family != AF_INET) {
        return false;
    }

    Mutex::Lock _l(_peers_mutex);

    // Check if peer already exists
    if (_activePeers.find(peerAddress) != _activePeers.end()) {
        return true; // Peer already exists
    }

    // Add peer to ipset
    std::string command = "ipset add zt_peers " + sanitizeIpAddress(peerAddress);
    if (executeCommand(command)) {
        _activePeers.insert(peerAddress);
        return true;
    }

    return false;
}

bool IptablesManager::removePeer(const InetAddress& peerAddress)
{
    if (!peerAddress) {
        return false;
    }

    Mutex::Lock _l(_peers_mutex);

    // Check if peer exists
    if (_activePeers.find(peerAddress) == _activePeers.end()) {
        return true; // Peer doesn't exist, consider it "removed"
    }

    // Remove peer from ipset
    std::string command = "ipset del zt_peers " + sanitizeIpAddress(peerAddress);
    if (executeCommand(command)) {
        _activePeers.erase(peerAddress);
        return true;
    }

    return false;
}

bool IptablesManager::hasPeer(const InetAddress& peerAddress) const noexcept
{
    if (!peerAddress) {
        return false;
    }

    Mutex::Lock _l(_peers_mutex);
    return _activePeers.find(peerAddress) != _activePeers.end();
}

bool IptablesManager::updateUdpPorts(const std::vector<unsigned int>& udpPorts)
{
    // Validate new ports
    for (unsigned int port : udpPorts) {
        if (port == 0 || port > 65535) {
            return false;
        }
    }

    // Remove duplicates and sort
    std::vector<unsigned int> newPorts = udpPorts;
    std::sort(newPorts.begin(), newPorts.end());
    newPorts.erase(std::unique(newPorts.begin(), newPorts.end()), newPorts.end());

    // Check if ports actually changed
    if (newPorts == _udpPorts) {
        return true; // No change needed
    }

    // Remove old iptables rules (but keep the ipset - only startup/shutdown should destroy/flush ipset)
    removeIptablesRules();

    // Update ports
    _udpPorts = newPorts;

    // Create new iptables rules
    createIptablesRules();

    return true;
}

bool IptablesManager::updateWanInterface(const std::string& wanInterface)
{
    // Validate new WAN interface name
    if (wanInterface.empty() || wanInterface.find_first_of(";|&`$()<>") != std::string::npos) {
        return false;
    }

    // Check if interface actually changed
    if (wanInterface == _wanInterface) {
        return true; // No change needed
    }

    // Remove old iptables rules (but keep the ipset - only startup/shutdown should destroy/flush ipset)
    removeIptablesRules();

    // Update WAN interface
    _wanInterface = wanInterface;

    // Create new iptables rules with the new interface
    createIptablesRules();

    return true;
}

bool IptablesManager::executeCommand(const std::string& command) const
{
    // Additional security check - ensure command starts with expected commands
    if (command.find("ipset") != 0 && command.find("iptables") != 0) {
        return false;
    }

    // Debug: print the command being executed
    fprintf(stderr, "[IptablesManager] Executing: %s\n", command.c_str());

    // Execute the command using system()
    int result = std::system(command.c_str());

    // Debug: print the result
    fprintf(stderr, "[IptablesManager] Result: %d\n", result);

    // system() returns the exit status of the command
    // 0 means success, non-zero means failure
    return (result == 0);
}

void IptablesManager::initializeRules()
{
    // Create the ipset for ZeroTier peers
    // Use hash:ip family inet with reasonable size limits
    std::string createIpsetCmd = "ipset create zt_peers hash:ip family inet hashsize 1024 maxelem 65536";
    if (!executeCommand(createIpsetCmd)) {
        // If creation fails, the set might already exist (from a previous flush)
        // Try to flush it first to ensure it's clean, then try creation again
        executeCommand("ipset flush zt_peers 2>/dev/null");
        if (!executeCommand(createIpsetCmd)) {
            // If it still fails, try to destroy and recreate
            executeCommand("ipset destroy zt_peers 2>/dev/null");
            if (!executeCommand(createIpsetCmd)) {
                throw std::runtime_error("Failed to create ipset 'zt_peers'");
            }
        }
    }

    // Create iptables rules for each UDP port
    createIptablesRules();

    _initialized = true;
}

void IptablesManager::createIptablesRules()
{
    // Clean up any existing rules first
    removeIptablesRules();

    // Create a new chain for our rules to keep things clean
    executeCommand("iptables -N zt_rules 2>/dev/null");

    // Jump to our chain from INPUT
    executeCommand("iptables -I INPUT 1 -j zt_rules 2>/dev/null");

    // Allow established and related traffic, which handles replies to our outbound packets
    executeCommand("iptables -A zt_rules -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");

    // Create rules for each UDP port
    for (unsigned int port : _udpPorts) {
        std::stringstream ss;
        ss << "iptables -A zt_rules -i " << _wanInterface
           << " -p udp --dport " << port
           << " -m set --match-set zt_peers src"
           << " -m conntrack --ctstate NEW -j ACCEPT";

        if (!executeCommand(ss.str())) {
            fprintf(stderr, "WARNING: Failed to create iptables rule for port %u" ZT_EOL_S, port);
        }
    }
}

void IptablesManager::removeIptablesRules()
{
    // Remove the jump rule from the INPUT chain (ignore errors if it doesn't exist)
    executeCommand("iptables -D INPUT -j zt_rules 2>/dev/null");

    // Flush all rules from our custom chain (ignore errors if it doesn't exist)
    executeCommand("iptables -F zt_rules 2>/dev/null");

    // Delete our custom chain (ignore errors if it doesn't exist)
    executeCommand("iptables -X zt_rules 2>/dev/null");
}

void IptablesManager::cleanup()
{
    Mutex::Lock _l(_peers_mutex);
    performCleanup();
}

void IptablesManager::cleanupExistingRules()
{
    // No lock needed here since this is called during construction
    // and the object isn't fully initialized yet
    performCleanup();
}

void IptablesManager::performCleanup()
{
    // NOTE: This method is only called at service startup (cleanupExistingRules) 
    // and shutdown (destructor). It should NOT be called during normal operation
    // when only rules need to be updated (use updateUdpPorts/updateWanInterface instead).

    // Remove iptables rules
    removeIptablesRules();

    // Flush the ipset (remove all entries but keep the set)
    // Only destroy if flush fails (set doesn't exist)
    if (!executeCommand("ipset flush zt_peers 2>/dev/null")) {
        // If flush fails, try to destroy (ignore errors if it doesn't exist)
        executeCommand("ipset destroy zt_peers 2>/dev/null");
    }

    // Clear our internal tracking
    _activePeers.clear();
    _initialized = false;
}

std::string IptablesManager::sanitizeIpAddress(const InetAddress& addr) const
{
    if (!addr) {
        return "";
    }

    // Convert to string representation
    char tmp[128];
    addr.toString(tmp);

    // Extract only the IP address part (remove port if present)
    std::string result(tmp);
    size_t slashPos = result.find('/');
    if (slashPos != std::string::npos) {
        result = result.substr(0, slashPos);
    }

    // Additional sanitization - only allow valid IP characters
    if (result.find_first_not_of("0123456789.") != std::string::npos) {
        return ""; // Invalid characters found
    }

    return result;
}

} // namespace ZeroTier
