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
    , _firewallType(detectFirewallType())
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

    // Log detected firewall type
    const char* firewallName = (_firewallType == FirewallType::NFTABLES) ? "nftables" : "iptables";
    fprintf(stderr, "INFO: Detected firewall system: %s" ZT_EOL_S, firewallName);

    // Initialize the firewall rules (ipset/iptables or nftables)
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
    , _firewallType(other._firewallType)
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
        _firewallType = other._firewallType;
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
        if (_firewallType == FirewallType::NFTABLES) {
            // For nftables, we need to rebuild (nft replace doesn't work the same way)
            // But we can update the set reference in the rules
            removeNftablesRules();
            _udpPorts = newPorts;
            createNftablesRules();
            return true;
        } else {
            return replaceMultiportRule(newPorts);
        }
    } else {
        // Fallback to full rebuild (first time setup or edge cases)
        removeFirewallRules();
        _udpPorts = newPorts;
        createFirewallRules();
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

    // Remove old firewall rules (but keep the set - only startup/shutdown should destroy/flush set)
    removeFirewallRules();

    // Update WAN interface
    _wanInterface = wanInterface;

    // Create new firewall rules with the new interface
    createFirewallRules();

    return true;
}

FirewallType IptablesManager::detectFirewallType()
{
    // Check if nftables is in use by checking if nft list tables succeeds
    // and if there are any tables (indicates nftables is active)
    FILE* pipe = popen("nft list tables 2>/dev/null", "r");
    if (pipe) {
        char buffer[256];
        bool hasTables = false;
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            // If we get any output, nftables is available
            if (strlen(buffer) > 0) {
                hasTables = true;
                break;
            }
        }
        pclose(pipe);

        if (hasTables) {
            // Check if ipset is available (iptables might still be used with nftables)
            // If ipset is NOT available, definitely use nftables
            FILE* ipsetPipe = popen("which ipset >/dev/null 2>&1", "r");
            if (ipsetPipe) {
                pclose(ipsetPipe);
                // ipset exists, but we have nftables tables - prefer nftables
                // (system has switched to nftables)
                return FirewallType::NFTABLES;
            } else {
                // No ipset, definitely use nftables
                return FirewallType::NFTABLES;
            }
        }
    }

    // Default to iptables if nftables detection fails or no tables found
    return FirewallType::IPTABLES;
}

bool IptablesManager::checkAndRestoreRules()
{
    if (!_initialized) {
        return false;
    }

    if (_firewallType == FirewallType::NFTABLES) {
        // Check if our nftables table/chain exists
        std::string checkCmd = "nft list table inet zerotier >/dev/null 2>&1";
        if (executeCommand(checkCmd)) {
            return true;
        }

        // Table/chain doesn't exist - restore everything
        fprintf(stderr, "INFO: zerotier table missing, restoring nftables integration" ZT_EOL_S);
        createNftablesRules();
        fprintf(stderr, "INFO: Successfully restored nftables integration" ZT_EOL_S);
        return true;
    } else {
        // Check if our custom chain exists by trying to list it
        std::string checkChainCmd = "iptables -L zt_rules -n >/dev/null 2>&1";
        if (executeCommand(checkChainCmd)) {
            return true;
        }

        // Chain doesn't exist - restore everything
        fprintf(stderr, "INFO: zt_rules chain missing, restoring iptables integration" ZT_EOL_S);

        // Recreate iptables rules
        createIptablesRules();
        fprintf(stderr, "INFO: Successfully restored iptables integration" ZT_EOL_S);
        return true;
    }
}

bool IptablesManager::executeCommand(const std::string& command) const
{
    // Additional security check - ensure command starts with expected commands
    if (command.find("ipset") != 0 &&
        command.find("iptables") != 0 &&
        command.find("nft") != 0) {
        return false;
    }

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

    if (result) {
        // Debug: print the result
        fprintf(stderr, "[IptablesManager] Executed: %s\n", command.c_str());
        fprintf(stderr, "[IptablesManager] Result: %d\n", result);
    }

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
    // Clean up any existing firewall rules from previous runs (in case of unclean shutdown)
    removeFirewallRules();

    if (_firewallType == FirewallType::NFTABLES) {
        // Initialize nftables set for ZeroTier peers
        // First try to flush existing set (if it exists)
        if (executeCommand("nft flush set inet zerotier zt_peers 2>/dev/null")) {
            // Flush succeeded, set already exists and is now empty
            fprintf(stderr, "INFO: Reusing existing nftables set 'zt_peers'" ZT_EOL_S);
        } else {
            // Set doesn't exist - create table and set
            // Create table first
            if (!executeCommand("nft create table inet zerotier 2>/dev/null")) {
                // Table might already exist, try to create set anyway
            }

            // Create set (quote braces to prevent shell interpretation)
            std::string createSetCmd = "nft create set inet zerotier zt_peers '{ type ipv4_addr; size 65536; }'";
            if (!executeCommand(createSetCmd)) {
                throw std::runtime_error("Failed to create nftables set 'zt_peers'");
            }
            fprintf(stderr, "INFO: Created new nftables set 'zt_peers'" ZT_EOL_S);
        }

        // Create nftables rules for each UDP port
        createNftablesRules();
    } else {
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
    }

    _initialized = true;
}

void IptablesManager::createFirewallRules()
{
    if (_firewallType == FirewallType::NFTABLES) {
        createNftablesRules();
    } else {
        createIptablesRules();
    }
}

void IptablesManager::createIptablesRules()
{
    // Create a new chain for our rules to keep things clean
    executeCommand("iptables -N zt_rules 2>/dev/null");

    // Jump to our chain from INPUT
    executeCommand("iptables -I INPUT 1 -j zt_rules 2>/dev/null");

    // Create a single multiport rule for all UDP ports (much more efficient)
    if (!_udpPorts.empty()) {
        // Build port list
        std::string portList;
        for (size_t i = 0; i < _udpPorts.size(); ++i) {
            if (i > 0) portList += ",";
            portList += std::to_string(_udpPorts[i]);
        }

        // Build LOG and ACCEPT rules using helper function
        std::stringstream logRule, acceptRule;
        buildMultiportRules(portList, logRule, acceptRule, true);

        if (!executeCommand(logRule.str()) || !executeCommand(acceptRule.str())) {
            fprintf(stderr, "WARNING: Failed to create multiport iptables rules, trying fallback" ZT_EOL_S);
            // Fallback to individual rules if multiport fails
            createIndividualPortRules();
        } else {
            fprintf(stderr, "INFO: Created iptables LOG+ACCEPT rules for %zu UDP ports" ZT_EOL_S, _udpPorts.size());
        }

        // Add RETURN rule at the end so non-matching packets return to INPUT chain
        // (applies to both multiport and individual port fallback)
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

    // Build LOG and ACCEPT rules using helper function (replace mode)
    std::stringstream logRule, acceptRule;
    buildMultiportRules(portList, logRule, acceptRule, false, 1, 2);

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
}

void IptablesManager::buildMultiportRules(const std::string& portList, std::stringstream& logRule,
                                        std::stringstream& acceptRule, bool useAppend,
                                        int logRuleNumber, int acceptRuleNumber)
{
    // Build LOG rule
    logRule << "iptables " << (useAppend ? "-A" : "-R") << " zt_rules";
    if (!useAppend) logRule << " " << logRuleNumber;
    logRule << " -i " << _wanInterface
            << " -p udp -m multiport --dports " << portList
            << " -m set --match-set zt_peers src"
            << " -m conntrack --ctstate NEW"
            << " -m limit --limit 10/min --limit-burst 5"
            << " -j LOG --log-prefix \"ZT-ALLOW: \"";

    // Build ACCEPT rule
    acceptRule << "iptables " << (useAppend ? "-A" : "-R") << " zt_rules";
    if (!useAppend) acceptRule << " " << acceptRuleNumber;
    acceptRule << " -i " << _wanInterface
               << " -p udp -m multiport --dports " << portList
               << " -m set --match-set zt_peers src"
               << " -m conntrack --ctstate NEW -j ACCEPT";
}

void IptablesManager::createNftablesRules()
{
    // Create table (if it doesn't exist)
    executeCommand("nft create table inet zerotier 2>/dev/null");

    // Create chain in the input hook (quote braces to prevent shell interpretation)
    executeCommand("nft create chain inet zerotier input '{ type filter hook input priority 0; }' 2>/dev/null");

    // Create rules for each UDP port
    if (!_udpPorts.empty()) {
        // Build port list for multiport match
        std::string portList;
        for (size_t i = 0; i < _udpPorts.size(); ++i) {
            if (i > 0) portList += ",";
            portList += std::to_string(_udpPorts[i]);
        }

        // Create LOG rule (rate-limited)
        // nftables requires double-quoted prefix for special characters like colon
        // Use nested quotes: outer single quotes for shell, inner double quotes for nftables
        std::stringstream logRule;
        logRule << "nft add rule inet zerotier input iifname " << _wanInterface
                << " udp dport { " << portList << " } ip saddr @zt_peers"
                << " ct state new limit rate 10/minute burst 5 packets"
                << " log prefix '\"ZT-ALLOW: \"'";

        // Create ACCEPT rule
        std::stringstream acceptRule;
        acceptRule << "nft add rule inet zerotier input iifname " << _wanInterface
                   << " udp dport { " << portList << " } ip saddr @zt_peers"
                   << " ct state new accept";

        if (!executeCommand(logRule.str()) || !executeCommand(acceptRule.str())) {
            fprintf(stderr, "WARNING: Failed to create nftables rules, trying individual port rules" ZT_EOL_S);
            // Fallback to individual rules
            for (unsigned int port : _udpPorts) {
                std::stringstream logRuleSingle, acceptRuleSingle;
                logRuleSingle << "nft add rule inet zerotier input iifname " << _wanInterface
                             << " udp dport " << port << " ip saddr @zt_peers"
                             << " ct state new limit rate 10/minute burst 5 packets"
                             << " log prefix '\"ZT-ALLOW: \"'";
                acceptRuleSingle << "nft add rule inet zerotier input iifname " << _wanInterface
                                << " udp dport " << port << " ip saddr @zt_peers"
                                << " ct state new accept";

                if (!executeCommand(logRuleSingle.str()) || !executeCommand(acceptRuleSingle.str())) {
                    fprintf(stderr, "WARNING: Failed to create nftables rules for port %u" ZT_EOL_S, port);
                }
            }
        } else {
            fprintf(stderr, "INFO: Created nftables LOG+ACCEPT rules for %zu UDP ports" ZT_EOL_S, _udpPorts.size());
        }
    }
}

void IptablesManager::removeFirewallRules()
{
    if (_firewallType == FirewallType::NFTABLES) {
        removeNftablesRules();
    } else {
        removeIptablesRules();
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

void IptablesManager::removeNftablesRules()
{
    // Flush all rules from our chain (ignore errors if it doesn't exist)
    executeCommand("nft flush chain inet zerotier input 2>/dev/null");

    // Delete the chain (ignore errors if it doesn't exist)
    executeCommand("nft delete chain inet zerotier input 2>/dev/null");

    // Note: We don't delete the table here as it might contain the set
    // The set is managed separately in cleanup()
}

bool IptablesManager::updatePeer(const std::string& ipString, bool add)
{
    if (!_initialized) {
        return false;
    }

    // Check if operation is needed to avoid unnecessary set commands
    {
        Mutex::Lock _l(_peers_mutex);
        bool peerExists = (_activePeers.find(ipString) != _activePeers.end());

        if (add && peerExists) {
            return false; // Already exists, skip expensive set command
        }
        if (!add && !peerExists) {
            return false; // Doesn't exist, skip expensive set command
        }
    }

    // Build command based on firewall type
    std::string cmd;
    if (_firewallType == FirewallType::NFTABLES) {
        // Quote braces to prevent shell interpretation
        cmd = "nft " + std::string(add ? "add" : "delete") + " element inet zerotier zt_peers '{ " + ipString + " }'";
    } else {
        cmd = "ipset " + std::string(add ? "add" : "del") + " zt_peers " + ipString;
    }

    bool success = executeCommand(cmd);

    if (success) {
        Mutex::Lock _l(_peers_mutex);
        if (add) {
            _activePeers.insert(ipString);
        } else {
            _activePeers.erase(ipString);
        }
    } else {
        const char* operation = add ? "add" : "remove";
        const char* firewallName = (_firewallType == FirewallType::NFTABLES) ? "nftables" : "iptables/ipset";
        fprintf(stderr, "WARNING: Failed to %s peer %s %s %s" ZT_EOL_S,
                operation, ipString.c_str(), add ? "to" : "from", firewallName);
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

    // Remove firewall rules
    removeFirewallRules();

    if (_firewallType == FirewallType::NFTABLES) {
        // Flush the nftables set (remove all entries but keep the set)
        if (!executeCommand("nft flush set inet zerotier zt_peers 2>/dev/null")) {
            // If flush fails, set might not exist - try to delete table (which will delete set too)
            executeCommand("nft delete table inet zerotier 2>/dev/null");
        }
    } else {
        // Flush the ipset (remove all entries but keep the set)
        // Only destroy if flush fails (set doesn't exist)
        if (!executeCommand("ipset flush zt_peers 2>/dev/null")) {
            // If flush fails, try to destroy (ignore errors if it doesn't exist)
            executeCommand("ipset destroy zt_peers 2>/dev/null");
        }
    }

    // Clear internal state
    _activePeers.clear();
    _initialized = false;
}

} // namespace ZeroTier

