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

#include "Constants.hpp"
#include "InetAddress.hpp"
#include "Address.hpp"
#include "Mutex.hpp"

namespace ZeroTier {

class RuntimeEnvironment;

/**
 * Security monitoring system - minimal implementation for debugging
 */
class SecurityMonitor
{
public:
    enum SecurityEventType {
        SEC_AUTH_FAILURE = 1,
        SEC_RATE_LIMIT_EXCEEDED = 2,
        SEC_INVALID_PACKET = 3,
        SEC_PROTOCOL_VIOLATION = 4
    };

    enum ThreatLevel {
        THREAT_LOW = 1,
        THREAT_MEDIUM = 2,
        THREAT_HIGH = 3,
        THREAT_CRITICAL = 4
    };

private:
    const RuntimeEnvironment *RR;
    Mutex _lock;

public:
    SecurityMonitor(const RuntimeEnvironment *renv);
    ~SecurityMonitor();

    // Minimal interface for testing
    void recordSecurityEvent(void *tPtr, const InetAddress &sourceIP,
                           const Address &sourceZT, SecurityEventType eventType,
                           const char *description, const char *packetInfo = nullptr);

    void doPeriodicMaintenance(void *tPtr, uint64_t now);
};

} // namespace ZeroTier

#endif // ZT_SECURITYMONITOR_HPP
