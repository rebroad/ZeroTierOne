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

namespace ZeroTier {

IptablesManager::IptablesManager(const std::string& wanInterface, unsigned int udpPort)
    : _wanInterface(wanInterface)
    , _udpPort(udpPort)
{
    // Validate WAN interface name to prevent command injection
    if (_wanInterface.empty() || _wanInterface.find_first_of(";|&`$()<>") != std::string::npos) {
        throw std::invalid_argument("Invalid WAN interface name");
    }

    // Validate UDP port
    if (_udpPort == 0 || _udpPort > 65535) {
        throw std::invalid_argument("Invalid UDP port number");
    }

	// Create a new chain for our rules to keep things clean
	executeIptablesCommand("iptables -N zt_rules");
	// Jump to our chain from INPUT
	executeIptablesCommand("iptables -I INPUT 1 -j zt_rules");
	// Allow established and related traffic, which handles replies to our outbound packets
	executeIptablesCommand("iptables -A zt_rules -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");
}

IptablesManager::~IptablesManager()
{
    cleanup();
}

bool IptablesManager::addPeerRule(const InetAddress& peerAddress)
{
    if (!peerAddress) {
        return false;
    }

    // Only handle IPv4 addresses for now (iptables IPv6 support can be added later)
    if (peerAddress.ss_family != AF_INET) {
        return false;
    }

    Mutex::Lock _l(_rules_mutex);

    // Check if rule already exists
    if (_activeRules.find(peerAddress) != _activeRules.end()) {
        return true; // Rule already exists
    }

    // Generate and execute the iptables command
    std::string command = generateAddRuleCommand(peerAddress);
    if (executeIptablesCommand(command)) {
        _activeRules.insert(peerAddress);
        return true;
    }

    return false;
}

bool IptablesManager::removePeerRule(const InetAddress& peerAddress)
{
    if (!peerAddress) {
        return false;
    }

    Mutex::Lock _l(_rules_mutex);

    // Check if rule exists
    if (_activeRules.find(peerAddress) == _activeRules.end()) {
        return true; // Rule doesn't exist, consider it "removed"
    }

    // Generate and execute the iptables command
    std::string command = generateRemoveRuleCommand(peerAddress);
    if (executeIptablesCommand(command)) {
        _activeRules.erase(peerAddress);
        return true;
    }

    return false;
}

bool IptablesManager::hasPeerRule(const InetAddress& peerAddress) const
{
    if (!peerAddress) {
        return false;
    }

    Mutex::Lock _l(_rules_mutex);
    return _activeRules.find(peerAddress) != _activeRules.end();
}

void IptablesManager::setWanInterface(const std::string& wanInterface)
{
    // Validate WAN interface name to prevent command injection
    if (wanInterface.empty() || wanInterface.find_first_of(";|&`$()<>") != std::string::npos) {
        throw std::invalid_argument("Invalid WAN interface name");
    }

    Mutex::Lock _l(_rules_mutex);
    _wanInterface = wanInterface;
}

void IptablesManager::setUdpPort(unsigned int udpPort)
{
    if (udpPort == 0 || udpPort > 65535) {
        throw std::invalid_argument("Invalid UDP port number");
    }

    Mutex::Lock _l(_rules_mutex);
    _udpPort = udpPort;
}

bool IptablesManager::executeIptablesCommand(const std::string& command) const
{
    // Additional security check - ensure command starts with "iptables"
    if (command.find("iptables") != 0) {
        return false;
    }

    // Execute the command using system()
    int result = std::system(command.c_str());

    // system() returns the exit status of the command
    // 0 means success, non-zero means failure
    return (result == 0);
}

std::string IptablesManager::generateAddRuleCommand(const InetAddress& peerAddress) const
{
    std::stringstream ss;
    ss << "iptables -A zt_rules -i " << _wanInterface
       << " -p udp --dport " << _udpPort
       << " -s " << sanitizeIpAddress(peerAddress)
       << " -m conntrack --ctstate NEW -j ACCEPT";
    return ss.str();
}

std::string IptablesManager::generateRemoveRuleCommand(const InetAddress& peerAddress) const
{
    std::stringstream ss;
    ss << "iptables -D zt_rules -i " << _wanInterface
       << " -p udp --dport " << _udpPort
       << " -s " << sanitizeIpAddress(peerAddress)
       << " -m conntrack --ctstate NEW -j ACCEPT";
    return ss.str();
}

std::string IptablesManager::sanitizeIpAddress(const InetAddress& addr) const
{
    if (!addr) {
        return "";
    }

    // Convert to string representation
    char tmp[128];
    addr.toString(tmp);

    // Additional sanitization - only allow valid IP characters
    std::string result(tmp);
    if (result.find_first_not_of("0123456789.") != std::string::npos) {
        return ""; // Invalid characters found
    }

    return result;
}

void IptablesManager::cleanup()
{
    Mutex::Lock _l(_rules_mutex);

    // Flush all rules from our custom chain
    executeIptablesCommand("iptables -F zt_rules");

    // Remove the jump rule from the INPUT chain
    executeIptablesCommand("iptables -D INPUT -j zt_rules");

    // Delete our custom chain
    executeIptablesCommand("iptables -X zt_rules");

    _activeRules.clear();
}

} // namespace ZeroTier
