/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2026-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */

#include "SecurityMonitor.hpp"
#include "RuntimeEnvironment.hpp"
#include "Node.hpp"
#include "Utils.hpp"
#include "../osdep/OSUtils.hpp"

#include <sstream>
#include <algorithm>
#include <cstring>

namespace ZeroTier {

SecurityMonitor::SecurityMonitor(const RuntimeEnvironment *renv) :
    RR(renv),
    _eventBufferPos(0),
    _lastCleanup(0)
{
    _recentEvents.reserve(MAX_RECENT_EVENTS);
}

SecurityMonitor::~SecurityMonitor() {}

void SecurityMonitor::recordSecurityEvent(void *tPtr, const InetAddress &sourceIP,
                                        const Address &sourceZT, SecurityEventType eventType,
                                        const char *description, const char *packetInfo)
{
    const uint64_t now = RR->node->now();

    Mutex::Lock _l(_lock);

    // Update IP-based statistics
    char ipBuf[64];
    std::string ipStr = sourceIP.toString(ipBuf);
    IPStats &ipStats = _ipStats[ipStr];

    if (ipStats.firstSeen == 0) {
        ipStats.firstSeen = now;
    }
    ipStats.lastActivity = now;
    ipStats.totalPackets++;

    // Update specific counters based on event type
    switch (eventType) {
        case SEC_AUTH_FAILURE:
            ipStats.authFailures++;
            break;
        case SEC_RATE_LIMIT_EXCEEDED:
            ipStats.rateLimitViolations++;
            break;
        case SEC_INVALID_PACKET:
            ipStats.invalidPackets++;
            break;
        case SEC_PROTOCOL_VIOLATION:
        case SEC_IDENTITY_COLLISION:
        case SEC_EXCESSIVE_HELLO:
        case SEC_EXCESSIVE_ECHO:
        case SEC_EXCESSIVE_WHOIS:
        case SEC_SUSPICIOUS_PATTERN:
            ipStats.protocolViolations++;
            break;
    }

    // Calculate current threat level
    ThreatLevel newThreatLevel = _calculateThreatLevel(ipStats, now);
    bool threatLevelChanged = (newThreatLevel != ipStats.currentThreatLevel);
    ipStats.currentThreatLevel = newThreatLevel;

    // Create security event record
    SecurityEvent event(now, sourceIP, sourceZT, eventType, newThreatLevel,
                       description ? description : "");
    if (packetInfo) {
        event.packetInfo = packetInfo;
    }

    // Add to circular buffer
    if (_recentEvents.size() < MAX_RECENT_EVENTS) {
        _recentEvents.push_back(event);
    } else {
        _recentEvents[_eventBufferPos] = event;
        _eventBufferPos = (_eventBufferPos + 1) % MAX_RECENT_EVENTS;
    }

    // Log significant events
    if (newThreatLevel >= THREAT_MEDIUM || threatLevelChanged) {
        _logSecurityEvent(event);
    }

    // Periodic cleanup
    if ((now - _lastCleanup) > CLEANUP_INTERVAL) {
        _cleanupOldEntries(now);
        _lastCleanup = now;
    }
}

SecurityMonitor::ThreatLevel SecurityMonitor::getThreatLevel(const InetAddress &sourceIP)
{
    Mutex::Lock _l(_lock);

    char ipBuf[64];
    std::string ipStr = sourceIP.toString(ipBuf);
    auto it = _ipStats.find(ipStr);
    if (it != _ipStats.end()) {
        return it->second.currentThreatLevel;
    }

    return THREAT_LOW;
}

const SecurityMonitor::IPStats* SecurityMonitor::getIPStats(const InetAddress &sourceIP)
{
    Mutex::Lock _l(_lock);

    char ipBuf[64];
    std::string ipStr = sourceIP.toString(ipBuf);
    auto it = _ipStats.find(ipStr);
    if (it != _ipStats.end()) {
        return &it->second;
    }

    return nullptr;
}

std::vector<SecurityMonitor::SecurityEvent> SecurityMonitor::getRecentEvents(size_t maxEvents)
{
    Mutex::Lock _l(_lock);

    std::vector<SecurityEvent> result;
    result.reserve(std::min(maxEvents, _recentEvents.size()));

    if (_recentEvents.size() <= MAX_RECENT_EVENTS) {
        // Buffer not full yet, return from newest to oldest
        size_t start = _recentEvents.size();
        for (size_t i = 0; i < std::min(maxEvents, _recentEvents.size()); ++i) {
            result.push_back(_recentEvents[start - 1 - i]);
        }
    } else {
        // Buffer is full, return from current position backwards
        for (size_t i = 0; i < std::min(maxEvents, _recentEvents.size()); ++i) {
            size_t idx = (_eventBufferPos + MAX_RECENT_EVENTS - 1 - i) % MAX_RECENT_EVENTS;
            result.push_back(_recentEvents[idx]);
        }
    }

    return result;
}

std::string SecurityMonitor::exportPrometheusMetrics()
{
    Mutex::Lock _l(_lock);

    std::ostringstream metrics;

    // Security event counters by type
    std::map<SecurityEventType, uint64_t> eventCounts;
    std::map<ThreatLevel, uint64_t> threatCounts;

    for (const auto &pair : _ipStats) {
        const IPStats &stats = pair.second;
        threatCounts[stats.currentThreatLevel]++;
    }

    // Export threat level distribution
    metrics << "# HELP zt_security_threat_levels Number of IPs by threat level\n";
    metrics << "# TYPE zt_security_threat_levels gauge\n";
    for (const auto &pair : threatCounts) {
        metrics << "zt_security_threat_levels{level=\""
                << _threatLevelToString(pair.first) << "\"} "
                << pair.second << "\n";
    }

    // Export top offending IPs
    std::vector<std::pair<std::string, IPStats>> sortedIPs;
    for (const auto &pair : _ipStats) {
        if (pair.second.currentThreatLevel >= THREAT_MEDIUM) {
            sortedIPs.push_back(pair);
        }
    }

    std::sort(sortedIPs.begin(), sortedIPs.end(),
              [](const auto &a, const auto &b) {
                  return (a.second.authFailures + a.second.rateLimitViolations +
                         a.second.invalidPackets + a.second.protocolViolations) >
                         (b.second.authFailures + b.second.rateLimitViolations +
                         b.second.invalidPackets + b.second.protocolViolations);
              });

    // Export individual IP statistics for high-threat IPs
    metrics << "# HELP zt_security_ip_violations Security violations by IP\n";
    metrics << "# TYPE zt_security_ip_violations counter\n";

    size_t maxIPs = std::min(sortedIPs.size(), size_t(50)); // Limit to top 50
    for (size_t i = 0; i < maxIPs; ++i) {
        const std::string &ip = sortedIPs[i].first;
        const IPStats &stats = sortedIPs[i].second;

        metrics << "zt_security_ip_violations{ip=\"" << ip
                << "\",type=\"auth_failure\"} " << stats.authFailures << "\n";
        metrics << "zt_security_ip_violations{ip=\"" << ip
                << "\",type=\"rate_limit\"} " << stats.rateLimitViolations << "\n";
        metrics << "zt_security_ip_violations{ip=\"" << ip
                << "\",type=\"invalid_packet\"} " << stats.invalidPackets << "\n";
        metrics << "zt_security_ip_violations{ip=\"" << ip
                << "\",type=\"protocol_violation\"} " << stats.protocolViolations << "\n";
    }

    // Export recent event counts
    std::map<SecurityEventType, uint64_t> recentEventCounts;
    const uint64_t now = RR->node->now();
    const uint64_t hourAgo = now - 3600000; // 1 hour ago

    for (const SecurityEvent &event : _recentEvents) {
        if (event.timestamp >= hourAgo) {
            recentEventCounts[event.eventType]++;
        }
    }

    metrics << "# HELP zt_security_events_recent Security events in last hour\n";
    metrics << "# TYPE zt_security_events_recent counter\n";
    for (const auto &pair : recentEventCounts) {
        metrics << "zt_security_events_recent{type=\""
                << _eventTypeToString(pair.first) << "\"} "
                << pair.second << "\n";
    }

    return metrics.str();
}

void SecurityMonitor::doPeriodicMaintenance(void *tPtr, uint64_t now)
{
    Mutex::Lock _l(_lock);

    if ((now - _lastCleanup) > CLEANUP_INTERVAL) {
        _cleanupOldEntries(now);
        _lastCleanup = now;
    }
}

SecurityMonitor::ThreatLevel SecurityMonitor::_calculateThreatLevel(IPStats &stats, uint64_t now)
{
    // Calculate rates per hour for recent activity
    const uint64_t timeWindow = std::min(now - stats.firstSeen, THREAT_ANALYSIS_WINDOW);
    if (timeWindow == 0) return THREAT_LOW;

    const double hoursActive = timeWindow / 3600000.0; // Convert ms to hours
    if (hoursActive < 0.01) return THREAT_LOW; // Less than 36 seconds

    const double authFailureRate = stats.authFailures / hoursActive;
    const double rateLimitRate = stats.rateLimitViolations / hoursActive;
    const double invalidPacketRate = stats.invalidPackets / hoursActive;
    const double protocolViolationRate = stats.protocolViolations / hoursActive;

    // Determine threat level based on violation rates
    int threatScore = 0;

    if (authFailureRate >= AUTH_FAILURE_THRESHOLD_HIGH) threatScore += 3;
    else if (authFailureRate >= AUTH_FAILURE_THRESHOLD_LOW) threatScore += 1;

    if (rateLimitRate >= RATE_LIMIT_THRESHOLD_HIGH) threatScore += 3;
    else if (rateLimitRate >= RATE_LIMIT_THRESHOLD_LOW) threatScore += 1;

    if (invalidPacketRate >= INVALID_PACKET_THRESHOLD_HIGH) threatScore += 3;
    else if (invalidPacketRate >= INVALID_PACKET_THRESHOLD_LOW) threatScore += 1;

    if (protocolViolationRate >= 5) threatScore += 2; // Protocol violations are serious

    // Convert score to threat level
    if (threatScore >= 6) return THREAT_CRITICAL;
    if (threatScore >= 4) return THREAT_HIGH;
    if (threatScore >= 2) return THREAT_MEDIUM;
    return THREAT_LOW;
}

void SecurityMonitor::_logSecurityEvent(const SecurityEvent &event)
{
    // Convert timestamp to readable format
    time_t ts = event.timestamp / 1000; // Convert ms to seconds
    struct tm *tm_info = gmtime(&ts);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", tm_info);

    char ipBuf[64], ztBuf[11];
    char logBuffer[1024];
    snprintf(logBuffer, sizeof(logBuffer),
             "ZT_SECURITY: [%s] %s from %s (ZT:%s) - %s [Threat:%s]%s%s",
             timestamp,
             _eventTypeToString(event.eventType),
             event.sourceIP.toString(ipBuf),
             event.sourceZTAddr.toString(ztBuf),
             event.description.c_str(),
             _threatLevelToString(event.threatLevel),
             event.packetInfo.empty() ? "" : " - ",
             event.packetInfo.c_str());

    // Log to system logger
    fprintf(stderr, "%s\n", logBuffer);

    // TODO: Could also log to syslog, custom log file, or send to external SIEM
}

void SecurityMonitor::_cleanupOldEntries(uint64_t now)
{
    // Remove IP statistics older than 24 hours with no recent activity
    const uint64_t cutoffTime = now - (86400000 * 2); // 2 days

    auto it = _ipStats.begin();
    while (it != _ipStats.end()) {
        if (it->second.lastActivity < cutoffTime &&
            it->second.currentThreatLevel == THREAT_LOW) {
            it = _ipStats.erase(it);
        } else {
            ++it;
        }
    }
}

const char* SecurityMonitor::_eventTypeToString(SecurityEventType type)
{
    switch (type) {
        case SEC_AUTH_FAILURE: return "AUTH_FAILURE";
        case SEC_RATE_LIMIT_EXCEEDED: return "RATE_LIMIT_EXCEEDED";
        case SEC_INVALID_PACKET: return "INVALID_PACKET";
        case SEC_PROTOCOL_VIOLATION: return "PROTOCOL_VIOLATION";
        case SEC_IDENTITY_COLLISION: return "IDENTITY_COLLISION";
        case SEC_EXCESSIVE_HELLO: return "EXCESSIVE_HELLO";
        case SEC_EXCESSIVE_ECHO: return "EXCESSIVE_ECHO";
        case SEC_EXCESSIVE_WHOIS: return "EXCESSIVE_WHOIS";
        case SEC_SUSPICIOUS_PATTERN: return "SUSPICIOUS_PATTERN";
        default: return "UNKNOWN";
    }
}

const char* SecurityMonitor::_threatLevelToString(ThreatLevel level)
{
    switch (level) {
        case THREAT_LOW: return "LOW";
        case THREAT_MEDIUM: return "MEDIUM";
        case THREAT_HIGH: return "HIGH";
        case THREAT_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

} // namespace ZeroTier
