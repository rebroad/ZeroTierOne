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

#ifndef ZT_SECURITYMONITOR_HPP
#define ZT_SECURITYMONITOR_HPP

#include <map>
#include <unordered_map>
#include <string>
#include <vector>
#include <memory>

#include "Constants.hpp"
#include "InetAddress.hpp"
#include "Address.hpp"
#include "Mutex.hpp"
#include "Hashtable.hpp"

namespace ZeroTier {

class RuntimeEnvironment;

/**
 * Security monitoring and DoS detection system
 *
 * Tracks suspicious activities, rate limit violations, and potential attacks
 * from internet sources. Provides logging and metrics for security analysis.
 */
class SecurityMonitor
{
public:
    /**
     * Types of security events we track
     */
    enum SecurityEventType {
        SEC_AUTH_FAILURE = 1,           // Authentication/MAC failures
        SEC_RATE_LIMIT_EXCEEDED = 2,    // Rate limiting triggered
        SEC_INVALID_PACKET = 3,         // Malformed or invalid packets
        SEC_PROTOCOL_VIOLATION = 4,     // Protocol rule violations
        SEC_IDENTITY_COLLISION = 5,     // Identity collision attempts
        SEC_EXCESSIVE_HELLO = 6,        // Too many HELLO packets
        SEC_EXCESSIVE_ECHO = 7,         // Echo request flooding
        SEC_EXCESSIVE_WHOIS = 8,        // WHOIS request flooding
        SEC_SUSPICIOUS_PATTERN = 9      // Anomalous traffic patterns
    };

    /**
     * Security threat levels
     */
    enum ThreatLevel {
        THREAT_LOW = 1,      // Minor violations, normal rate limiting
        THREAT_MEDIUM = 2,   // Repeated violations, possible probing
        THREAT_HIGH = 3,     // Clear attack patterns, sustained abuse
        THREAT_CRITICAL = 4  // Severe attacks, immediate action needed
    };

    /**
     * Statistics for a single IP address
     */
    struct IPStats {
        uint64_t totalPackets;
        uint64_t authFailures;
        uint64_t rateLimitViolations;
        uint64_t invalidPackets;
        uint64_t protocolViolations;
        uint64_t lastActivity;
        uint64_t firstSeen;
        ThreatLevel currentThreatLevel;

        IPStats() : totalPackets(0), authFailures(0), rateLimitViolations(0),
                   invalidPackets(0), protocolViolations(0), lastActivity(0),
                   firstSeen(0), currentThreatLevel(THREAT_LOW) {}
    };

    /**
     * Security event record
     */
    struct SecurityEvent {
        uint64_t timestamp;
        InetAddress sourceIP;
        Address sourceZTAddr;
        SecurityEventType eventType;
        ThreatLevel threatLevel;
        std::string description;
        std::string packetInfo;

        SecurityEvent(uint64_t ts, const InetAddress& ip, const Address& zt,
                     SecurityEventType type, ThreatLevel level, const std::string& desc) :
            timestamp(ts), sourceIP(ip), sourceZTAddr(zt), eventType(type),
            threatLevel(level), description(desc) {}
    };

private:
    const RuntimeEnvironment *RR;

    // IP-based tracking (for internet sources)
    std::unordered_map<std::string, IPStats> _ipStats;

    // ZeroTier address-based tracking (for known peers)
    Hashtable<Address, IPStats> _ztAddrStats;

    // Recent security events (circular buffer)
    std::vector<SecurityEvent> _recentEvents;
    size_t _eventBufferPos;
    static const size_t MAX_RECENT_EVENTS = 1000;

    // Thresholds for threat detection
    static const uint64_t AUTH_FAILURE_THRESHOLD_LOW = 5;    // per hour
    static const uint64_t AUTH_FAILURE_THRESHOLD_HIGH = 20;  // per hour
    static const uint64_t RATE_LIMIT_THRESHOLD_LOW = 10;     // per hour
    static const uint64_t RATE_LIMIT_THRESHOLD_HIGH = 50;    // per hour
    static const uint64_t INVALID_PACKET_THRESHOLD_LOW = 10; // per hour
    static const uint64_t INVALID_PACKET_THRESHOLD_HIGH = 50; // per hour

    // Time windows for analysis
    static constexpr uint64_t THREAT_ANALYSIS_WINDOW = 3600000; // 1 hour in ms
    static constexpr uint64_t CLEANUP_INTERVAL = 86400000;      // 24 hours in ms

    uint64_t _lastCleanup;

    Mutex _lock;

public:
    SecurityMonitor(const RuntimeEnvironment *renv);
    ~SecurityMonitor();

    /**
     * Record a security event from an internet source
     *
     * @param tPtr Thread pointer
     * @param sourceIP Source IP address
     * @param sourceZT Source ZeroTier address (may be null)
     * @param eventType Type of security event
     * @param description Human-readable description
     * @param packetInfo Additional packet information
     */
    void recordSecurityEvent(void *tPtr, const InetAddress &sourceIP,
                           const Address &sourceZT, SecurityEventType eventType,
                           const char *description, const char *packetInfo = nullptr);

    /**
     * Check if an IP address should be considered suspicious
     *
     * @param sourceIP IP address to check
     * @return Current threat level for this IP
     */
    ThreatLevel getThreatLevel(const InetAddress &sourceIP);

    /**
     * Get statistics for an IP address
     *
     * @param sourceIP IP address to query
     * @return Pointer to stats or nullptr if not found
     */
    const IPStats* getIPStats(const InetAddress &sourceIP);

    /**
     * Get recent security events
     *
     * @param maxEvents Maximum number of events to return
     * @return Vector of recent security events
     */
    std::vector<SecurityEvent> getRecentEvents(size_t maxEvents = 100);

    /**
     * Export security statistics in Prometheus format
     *
     * @return Prometheus-formatted metrics string
     */
    std::string exportPrometheusMetrics();

    /**
     * Periodic maintenance - cleanup old entries, analyze patterns
     *
     * @param tPtr Thread pointer
     * @param now Current timestamp
     */
    void doPeriodicMaintenance(void *tPtr, uint64_t now);

private:
    /**
     * Update threat level based on current statistics
     *
     * @param stats IP statistics to analyze
     * @param now Current timestamp
     * @return Updated threat level
     */
    ThreatLevel _calculateThreatLevel(IPStats &stats, uint64_t now);

    /**
     * Log security event to system logs
     *
     * @param event Security event to log
     */
    void _logSecurityEvent(const SecurityEvent &event);

    /**
     * Clean up old statistics entries
     *
     * @param now Current timestamp
     */
    void _cleanupOldEntries(uint64_t now);

    /**
     * Get string representation of event type
     */
    const char* _eventTypeToString(SecurityEventType type);

    /**
     * Get string representation of threat level
     */
    const char* _threatLevelToString(ThreatLevel level);
};

} // namespace ZeroTier

#endif // ZT_SECURITYMONITOR_HPP
