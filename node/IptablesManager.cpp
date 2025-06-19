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

    // Initialize the ipset and iptables rules
    // Use a lock to prevent race conditions during initialization
    {
        Mutex::Lock _l(_peers_mutex);
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
    , _initialized(other._initialized)
    , _activePeers(std::move(other._activePeers))
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
        _initialized = other._initialized;
        _activePeers = std::move(other._activePeers);

        // Clear the other object's data
        other._initialized = false;
        other._udpPorts.clear();
        other._activePeers.clear();
    }
    return *this;
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

    // EFFICIENT UPDATE: Replace just the multiport rule instead of rebuilding everything
    // This is much faster than the old "nuclear" approach
    if (_initialized && !_udpPorts.empty() && !newPorts.empty()) {
        // Replace the multiport rule efficiently
        return replaceMultiportRule(newPorts);
    } else {
        // Fallback to full rebuild (first time setup or edge cases)
        removeIptablesRules();
        _udpPorts = newPorts;
        createIptablesRules();
        return true;
    }
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

    // Execute the command and capture both stdout and stderr
    std::string fullCommand = command + " 2>&1";
    FILE* pipe = popen(fullCommand.c_str(), "r");
    if (!pipe) {
        fprintf(stderr, "[IptablesManager] Failed to execute command\n");
        return false;
    }

    // Read the output
    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }

    int result = pclose(pipe);

    // Debug: print the result
    fprintf(stderr, "[IptablesManager] Result: %d\n", result);

    // If command failed, check for specific error conditions
    if (result != 0 && !output.empty()) {
        // Remove trailing newline for cleaner logging
        if (!output.empty() && output.back() == '\n') {
            output.pop_back();
        }
        fprintf(stderr, "[IptablesManager] Command output: %s\n", output.c_str());
    }

    // system() returns the exit status of the command
    // 0 means success, non-zero means failure
    return (result == 0);
}

void IptablesManager::initializeRules()
{
    // Clean up any existing iptables rules from previous runs (in case of unclean shutdown)
    // This only affects iptables rules, not the ipset
    removeIptablesRules();

    // Initialize ipset for ZeroTier peers
    // First try to flush existing set (if it exists)
    if (executeCommand("ipset flush zt_peers 2>/dev/null")) {
        // Flush succeeded, ipset already exists and is now empty
        fprintf(stderr, "INFO: Reusing existing ipset 'zt_peers'" ZT_EOL_S);
    } else {
        // Flush failed, ipset doesn't exist - create it
        std::string createIpsetCmd = "ipset create zt_peers hash:ip family inet hashsize 1024 maxelem 65536";
        if (!executeCommand(createIpsetCmd)) {
            throw std::runtime_error("Failed to create ipset 'zt_peers'");
        }
        fprintf(stderr, "INFO: Created new ipset 'zt_peers'" ZT_EOL_S);
    }

    // Create iptables rules for each UDP port
    createIptablesRules();

    _initialized = true;
}

void IptablesManager::createIptablesRules()
{
    // Create a new chain for our rules to keep things clean
    executeCommand("iptables -N zt_rules 2>/dev/null");

    // Jump to our chain from INPUT
    executeCommand("iptables -I INPUT 1 -j zt_rules 2>/dev/null");

    // Create a single multiport rule for all UDP ports (much more efficient)
    if (!_udpPorts.empty()) {
        std::stringstream logRule, acceptRule;

        // Build port list for both LOG and ACCEPT rules
        std::string portList;
        for (size_t i = 0; i < _udpPorts.size(); ++i) {
            if (i > 0) portList += ",";
            portList += std::to_string(_udpPorts[i]);
        }

        // Create LOG rule first (rate-limited to avoid spam)
        logRule << "iptables -A zt_rules -i " << _wanInterface
                << " -p udp -m multiport --dports " << portList
                << " -m set --match-set zt_peers src"
                << " -m conntrack --ctstate NEW"
                << " -m limit --limit 10/min --limit-burst 5"
                << " -j LOG --log-prefix \"ZT-ALLOW: \"";

        // Create ACCEPT rule
        acceptRule << "iptables -A zt_rules -i " << _wanInterface
                   << " -p udp -m multiport --dports " << portList
                   << " -m set --match-set zt_peers src"
                   << " -m conntrack --ctstate NEW -j ACCEPT";

        if (!executeCommand(logRule.str()) || !executeCommand(acceptRule.str())) {
            fprintf(stderr, "WARNING: Failed to create multiport iptables rules, trying fallback" ZT_EOL_S);
            // Fallback to individual rules if multiport fails
            createIndividualPortRules();
        } else {
            fprintf(stderr, "INFO: Created iptables LOG+ACCEPT rules for %zu UDP ports" ZT_EOL_S, _udpPorts.size());
        }

        // Add RETURN rule at the end so non-matching packets return to INPUT chain
        if (!executeCommand("iptables -A zt_rules -j RETURN")) {
            fprintf(stderr, "WARNING: Failed to add RETURN rule to zt_rules chain" ZT_EOL_S);
        }
    }
}

bool IptablesManager::replaceMultiportRule(const std::vector<unsigned int>& newPorts)
{
    // Build port list
    std::string portList;
    for (size_t i = 0; i < newPorts.size(); ++i) {
        if (i > 0) portList += ",";
        portList += std::to_string(newPorts[i]);
    }

    // Build new LOG rule (rule #1)
    std::stringstream logRule;
    logRule << "iptables -R zt_rules 1 -i " << _wanInterface
            << " -p udp -m multiport --dports " << portList
            << " -m set --match-set zt_peers src"
            << " -m conntrack --ctstate NEW"
            << " -m limit --limit 10/min --limit-burst 5"
            << " -j LOG --log-prefix \"ZT-ALLOW: \"";

    // Build new ACCEPT rule (rule #2)
    std::stringstream acceptRule;
    acceptRule << "iptables -R zt_rules 2 -i " << _wanInterface
               << " -p udp -m multiport --dports " << portList
               << " -m set --match-set zt_peers src"
               << " -m conntrack --ctstate NEW -j ACCEPT";

    // Try to replace both rules (rule #3 is RETURN and doesn't need updating)
    if (executeCommand(logRule.str()) && executeCommand(acceptRule.str())) {
        _udpPorts = newPorts;
        fprintf(stderr, "INFO: Efficiently updated multiport LOG+ACCEPT rules with %zu UDP ports (2 commands)" ZT_EOL_S, newPorts.size());
        return true;
    } else {
        // If replacement fails, fall back to full rebuild
        fprintf(stderr, "WARNING: Failed to replace multiport rules, falling back to full rebuild" ZT_EOL_S);
        removeIptablesRules();
        _udpPorts = newPorts;
        createIptablesRules();
        return true;
    }
}

void IptablesManager::createIndividualPortRules()
{
    // Fallback: Create individual rules for each UDP port (less efficient but more compatible)
    for (unsigned int port : _udpPorts) {
        std::stringstream logRule, acceptRule;

        // Create LOG rule for this port (rate-limited)
        logRule << "iptables -A zt_rules -i " << _wanInterface
                << " -p udp --dport " << port
                << " -m set --match-set zt_peers src"
                << " -m conntrack --ctstate NEW"
                << " -m limit --limit 10/min --limit-burst 5"
                << " -j LOG --log-prefix \"ZT-ALLOW: \"";

        // Create ACCEPT rule for this port
        acceptRule << "iptables -A zt_rules -i " << _wanInterface
                   << " -p udp --dport " << port
                   << " -m set --match-set zt_peers src"
                   << " -m conntrack --ctstate NEW -j ACCEPT";

        if (!executeCommand(logRule.str()) || !executeCommand(acceptRule.str())) {
            fprintf(stderr, "WARNING: Failed to create iptables LOG+ACCEPT rules for port %u" ZT_EOL_S, port);
        }
    }
    fprintf(stderr, "INFO: Created %zu individual iptables LOG+ACCEPT rule pairs (multiport fallback)" ZT_EOL_S, _udpPorts.size());

    // Add RETURN rule at the end so non-matching packets return to INPUT chain
    if (!executeCommand("iptables -A zt_rules -j RETURN")) {
        fprintf(stderr, "WARNING: Failed to add RETURN rule to zt_rules chain" ZT_EOL_S);
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

bool IptablesManager::addPeer(const std::string& ipString)
{
    if (!_initialized) {
        return false;
    }

    // Check if peer is already tracked to avoid unnecessary ipset commands
    {
        Mutex::Lock _l(_peers_mutex);
        if (_activePeers.find(ipString) != _activePeers.end()) {
            return false; // Already exists, skip expensive ipset command
        }
    }

    std::string cmd = "ipset add zt_peers " + ipString;
    bool success = executeCommand(cmd);

    if (success) {
        Mutex::Lock _l(_peers_mutex);
        _activePeers.insert(ipString);
        fprintf(stderr, "INFO: Added peer %s to iptables ipset" ZT_EOL_S, ipString.c_str());
    } else {
        fprintf(stderr, "WARNING: Failed to add peer %s to iptables ipset" ZT_EOL_S, ipString.c_str());
    }

    return success;
}

bool IptablesManager::removePeer(const std::string& ipString)
{
    if (!_initialized) {
        return false;
    }

    // Check if peer is tracked to avoid unnecessary ipset commands
    {
        Mutex::Lock _l(_peers_mutex);
        if (_activePeers.find(ipString) == _activePeers.end()) {
            return false; // Doesn't exist, skip expensive ipset command
        }
    }

    std::string cmd = "ipset del zt_peers " + ipString;
    bool success = executeCommand(cmd);

    if (success) {
        Mutex::Lock _l(_peers_mutex);
        _activePeers.erase(ipString);
        fprintf(stderr, "INFO: Removed peer %s from iptables ipset" ZT_EOL_S, ipString.c_str());
    } else {
        fprintf(stderr, "WARNING: Failed to remove peer %s from iptables ipset" ZT_EOL_S, ipString.c_str());
    }

    return success;
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

    // Clear internal state
    _activePeers.clear();
    _initialized = false;
}

} // namespace ZeroTier
