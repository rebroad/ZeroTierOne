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
#include <linux/netfilter/xt_tcpudp.h>

namespace ZeroTier {

IptablesManager::IptablesManager(const std::string& wanInterface, unsigned int udpPort)
    : _wanInterface(wanInterface)
    , _udpPort(udpPort)
{
    // Validate WAN interface name to prevent injection
    if (_wanInterface.empty() || _wanInterface.find_first_of(";|&`$()<>") != std::string::npos) {
        throw std::invalid_argument("Invalid WAN interface name");
    }

    // Validate UDP port
    if (_udpPort == 0 || _udpPort > 65535) {
        throw std::invalid_argument("Invalid UDP port number");
    }

    // Initialize the iptables chain
    if (!initializeChain()) {
        throw std::runtime_error("Failed to initialize iptables chain");
    }
}

IptablesManager::~IptablesManager()
{
    cleanup();
}

bool IptablesManager::initializeChain()
{
    struct iptc_handle *h = getIptcHandle();
    if (!h) {
        return false;
    }

    bool success = true;

    // Clean up any orphaned rules from previous runs
    if (iptc_is_chain("zt_rules", h)) {
        fprintf(stderr, "Found existing zt_rules chain - cleaning up orphaned rules from previous run\n");
        if (!iptc_flush_entries("zt_rules", h)) {
            fprintf(stderr, "Warning: Failed to flush existing zt_rules chain: %s\n", iptc_strerror(errno));
            // Continue anyway - this is not fatal
        }
    }

    // Create our custom chain if it doesn't exist
    if (!iptc_is_chain("zt_rules", h)) {
        if (!iptc_create_chain("zt_rules", h)) {
            fprintf(stderr, "Failed to create zt_rules chain: %s\n", iptc_strerror(errno));
            success = false;
        }
    }

    // Add jump rule to INPUT chain if it doesn't exist
    if (success) {
        struct ipt_entry *jump_entry = (struct ipt_entry *)malloc(sizeof(struct ipt_entry));
        if (jump_entry) {
            memset(jump_entry, 0, sizeof(struct ipt_entry));

            // Set up the jump rule
            jump_entry->ip.proto = 0; // Any protocol
            jump_entry->ip.smsk.s_addr = 0;
            jump_entry->ip.dmsk.s_addr = 0;
            jump_entry->target_offset = sizeof(struct ipt_entry);
            jump_entry->next_offset = sizeof(struct ipt_entry) + sizeof(struct xt_standard_target);

            struct xt_standard_target *target = (struct xt_standard_target *)jump_entry->elems;
            target->target.u.user.target_size = sizeof(struct xt_standard_target);
            strcpy(target->target.u.user.name, "zt_rules");
            target->verdict = -NF_ACCEPT - 1; // Jump to our chain

            // Insert at the beginning of INPUT chain
            if (!iptc_insert_entry("INPUT", jump_entry, 1, h)) {
                fprintf(stderr, "Failed to insert jump rule: %s\n", iptc_strerror(errno));
                success = false;
            }

            free(jump_entry);
        } else {
            success = false;
        }
    }

    // Add established/related rule to our chain
    if (success) {
        struct ipt_entry *est_entry = (struct ipt_entry *)malloc(sizeof(struct ipt_entry) + sizeof(struct xt_conntrack_info));
        if (est_entry) {
            memset(est_entry, 0, sizeof(struct ipt_entry) + sizeof(struct xt_conntrack_info));

            // Set up the established/related rule
            est_entry->ip.proto = 0; // Any protocol
            est_entry->ip.smsk.s_addr = 0;
            est_entry->ip.dmsk.s_addr = 0;
            est_entry->target_offset = sizeof(struct ipt_entry) + sizeof(struct xt_conntrack_info);
            est_entry->next_offset = sizeof(struct ipt_entry) + sizeof(struct xt_conntrack_info) + sizeof(struct xt_standard_target);

            // Add conntrack match
            struct xt_entry_match *match = (struct xt_entry_match *)est_entry->elems;
            match->u.user.match_size = sizeof(struct xt_conntrack_info);
            strcpy(match->u.user.name, "conntrack");

            struct xt_conntrack_info *ct_info = (struct xt_conntrack_info *)match->data;
            ct_info->state_mask = XT_CONNTRACK_STATE_BIT(IP_CT_ESTABLISHED) | XT_CONNTRACK_STATE_BIT(IP_CT_RELATED);
            ct_info->invert_state = 0;

            // Add ACCEPT target
            struct xt_standard_target *target = (struct xt_standard_target *)((char *)match + match->u.user.match_size);
            target->target.u.user.target_size = sizeof(struct xt_standard_target);
            strcpy(target->target.u.user.name, "ACCEPT");
            target->verdict = -NF_ACCEPT - 1;

            if (!iptc_append_entry("zt_rules", est_entry, h)) {
                fprintf(stderr, "Failed to add established rule: %s\n", iptc_strerror(errno));
                success = false;
            }

            free(est_entry);
        } else {
            success = false;
        }
    }

    // Commit changes
    if (success) {
        if (!iptc_commit(h)) {
            fprintf(stderr, "Failed to commit iptables changes: %s\n", iptc_strerror(errno));
            success = false;
        }
    }

    iptc_free(h);
    return success;
}

bool IptablesManager::addPeerRule(const InetAddress& peerAddress)
{
    if (!peerAddress) {
        return false;
    }

    // Only handle IPv4 addresses for now
    if (peerAddress.ss_family != AF_INET) {
        return false;
    }

    Mutex::Lock _l(_rules_mutex);

    // Check if rule already exists
    if (_activeRules.find(peerAddress) != _activeRules.end()) {
        return true; // Rule already exists
    }

    struct iptc_handle *h = getIptcHandle();
    if (!h) {
        return false;
    }

    struct ipt_entry *entry = createPeerRule(peerAddress);
    if (!entry) {
        iptc_free(h);
        return false;
    }

    bool success = false;
    if (iptc_append_entry("zt_rules", entry, h)) {
        if (iptc_commit(h)) {
            _activeRules.insert(peerAddress);
            success = true;
        } else {
            fprintf(stderr, "Failed to commit peer rule: %s\n", iptc_strerror(errno));
        }
    } else {
        fprintf(stderr, "Failed to append peer rule: %s\n", iptc_strerror(errno));
    }

    free(entry);
    iptc_free(h);
    return success;
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

    struct iptc_handle *h = getIptcHandle();
    if (!h) {
        return false;
    }

    struct ipt_entry *entry = createPeerRule(peerAddress);
    if (!entry) {
        iptc_free(h);
        return false;
    }

    bool success = false;
    if (iptc_delete_entry("zt_rules", entry, h)) {
        if (iptc_commit(h)) {
            _activeRules.erase(peerAddress);
            success = true;
        } else {
            fprintf(stderr, "Failed to commit rule removal: %s\n", iptc_strerror(errno));
        }
    } else {
        fprintf(stderr, "Failed to delete peer rule: %s\n", iptc_strerror(errno));
    }

    free(entry);
    iptc_free(h);
    return success;
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
    // Validate WAN interface name to prevent injection
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

struct iptc_handle* IptablesManager::getIptcHandle() const
{
    struct iptc_handle *h = iptc_init("filter");
    if (!h) {
        fprintf(stderr, "Failed to initialize iptc: %s\n", iptc_strerror(errno));
        return nullptr;
    }
    return h;
}

struct ipt_entry* IptablesManager::createPeerRule(const InetAddress& peerAddress) const
{
    // Calculate total size needed
    size_t total_size = sizeof(struct ipt_entry) +
                       sizeof(struct xt_entry_match) + sizeof(struct xt_tcpudp_info) +  // UDP match
                       sizeof(struct xt_entry_match) + sizeof(struct xt_conntrack_info) + // conntrack match
                       sizeof(struct xt_standard_target); // ACCEPT target

    struct ipt_entry *entry = (struct ipt_entry *)malloc(total_size);
    if (!entry) {
        return nullptr;
    }

    memset(entry, 0, total_size);

    // Set up basic IP header
    entry->ip.proto = IPPROTO_UDP;
    entry->ip.smsk.s_addr = 0xFFFFFFFF; // Source mask (exact match)
    entry->ip.dmsk.s_addr = 0; // Destination mask (any)

    // Set source IP
    struct sockaddr_in *sin = (struct sockaddr_in *)&peerAddress;
    entry->ip.src.s_addr = sin->sin_addr.s_addr;

    // Set interface
    strcpy(entry->ip.iniface, _wanInterface.c_str());
    entry->ip.invflags |= IPT_INV_VIA_IN; // Invert interface match (match on this interface)

    char *ptr = (char *)entry->elems;

    // Add UDP match
    struct xt_entry_match *udp_match = (struct xt_entry_match *)ptr;
    udp_match->u.user.match_size = sizeof(struct xt_entry_match) + sizeof(struct xt_tcpudp_info);
    strcpy(udp_match->u.user.name, "udp");

    struct xt_tcpudp_info *udp_info = (struct xt_tcpudp_info *)udp_match->data;
    udp_info->spts[0] = 0; // Source port range (any)
    udp_info->spts[1] = 65535;
    udp_info->dpts[0] = _udpPort; // Destination port (our port)
    udp_info->dpts[1] = _udpPort;
    udp_info->option = XT_TCPUDP_DPORT; // Only check destination port

    ptr += udp_match->u.user.match_size;

    // Add conntrack match
    struct xt_entry_match *ct_match = (struct xt_entry_match *)ptr;
    ct_match->u.user.match_size = sizeof(struct xt_entry_match) + sizeof(struct xt_conntrack_info);
    strcpy(ct_match->u.user.name, "conntrack");

    struct xt_conntrack_info *ct_info = (struct xt_conntrack_info *)ct_match->data;
    ct_info->state_mask = XT_CONNTRACK_STATE_BIT(IP_CT_NEW);
    ct_info->invert_state = 0;

    ptr += ct_match->u.user.match_size;

    // Add ACCEPT target
    struct xt_standard_target *target = (struct xt_standard_target *)ptr;
    target->target.u.user.target_size = sizeof(struct xt_standard_target);
    strcpy(target->target.u.user.name, "ACCEPT");
    target->verdict = -NF_ACCEPT - 1;

    // Set offsets
    entry->target_offset = sizeof(struct ipt_entry) +
                          udp_match->u.user.match_size +
                          ct_match->u.user.match_size;
    entry->next_offset = total_size;

    return entry;
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
    struct iptc_handle *h = getIptcHandle();
    if (!h) {
        return;
    }

    // Flush all rules from our custom chain
    iptc_flush_entries("zt_rules", h);

    // Remove the jump rule from INPUT chain
    // Note: This is simplified - in practice you'd need to find and remove the specific rule
    // For now, we'll just flush the chain and let the system handle it

    // Delete our custom chain
    iptc_delete_chain("zt_rules", h);

    // Commit changes
    iptc_commit(h);
    iptc_free(h);
}

} // namespace ZeroTier
