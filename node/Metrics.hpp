/*
 * Copyright (c)2013-2023 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2026-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
#ifndef METRICS_H_
#define METRICS_H_

#include <prometheus/simpleapi.h>
#include <prometheus/histogram.h>

namespace prometheus {
    namespace simpleapi {
        extern std::shared_ptr<Registry> registry_ptr;
    }
}

namespace ZeroTier {
    namespace Metrics {

        // ========================================================================
        // PACKET TYPE METRICS
        // ========================================================================
        // Tracks ZeroTier protocol packet types (HELLO, OK, FRAME, etc.) by direction
        // Labels: packet_type={nop,error,ack,qos,hello,ok,whois,etc}, direction={rx,tx}
        // Purpose: Monitor which ZeroTier protocol messages are being exchanged
        extern prometheus::simpleapi::counter_family_t packets;

        // Incoming ZeroTier protocol packets by type
        extern prometheus::simpleapi::counter_metric_t pkt_nop_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_in;
        extern prometheus::simpleapi::counter_metric_t pkt_ack_in;
        extern prometheus::simpleapi::counter_metric_t pkt_qos_in;
        extern prometheus::simpleapi::counter_metric_t pkt_hello_in;
        extern prometheus::simpleapi::counter_metric_t pkt_ok_in;
        extern prometheus::simpleapi::counter_metric_t pkt_whois_in;
        extern prometheus::simpleapi::counter_metric_t pkt_rendezvous_in;
        extern prometheus::simpleapi::counter_metric_t pkt_frame_in;
        extern prometheus::simpleapi::counter_metric_t pkt_ext_frame_in;
        extern prometheus::simpleapi::counter_metric_t pkt_echo_in;
        extern prometheus::simpleapi::counter_metric_t pkt_multicast_like_in;
        extern prometheus::simpleapi::counter_metric_t pkt_network_credentials_in;
        extern prometheus::simpleapi::counter_metric_t pkt_network_config_request_in;
        extern prometheus::simpleapi::counter_metric_t pkt_network_config_in;
        extern prometheus::simpleapi::counter_metric_t pkt_multicast_gather_in;
        extern prometheus::simpleapi::counter_metric_t pkt_multicast_frame_in;
        extern prometheus::simpleapi::counter_metric_t pkt_push_direct_paths_in;
        extern prometheus::simpleapi::counter_metric_t pkt_user_message_in;
        extern prometheus::simpleapi::counter_metric_t pkt_remote_trace_in;
        extern prometheus::simpleapi::counter_metric_t pkt_path_negotiation_request_in;

        // Outgoing ZeroTier protocol packets by type
        extern prometheus::simpleapi::counter_metric_t pkt_nop_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_out;
        extern prometheus::simpleapi::counter_metric_t pkt_ack_out;
        extern prometheus::simpleapi::counter_metric_t pkt_qos_out;
        extern prometheus::simpleapi::counter_metric_t pkt_hello_out;
        extern prometheus::simpleapi::counter_metric_t pkt_ok_out;
        extern prometheus::simpleapi::counter_metric_t pkt_whois_out;
        extern prometheus::simpleapi::counter_metric_t pkt_rendezvous_out;
        extern prometheus::simpleapi::counter_metric_t pkt_frame_out;
        extern prometheus::simpleapi::counter_metric_t pkt_ext_frame_out;
        extern prometheus::simpleapi::counter_metric_t pkt_echo_out;
        extern prometheus::simpleapi::counter_metric_t pkt_multicast_like_out;
        extern prometheus::simpleapi::counter_metric_t pkt_network_credentials_out;
        extern prometheus::simpleapi::counter_metric_t pkt_network_config_request_out;
        extern prometheus::simpleapi::counter_metric_t pkt_network_config_out;
        extern prometheus::simpleapi::counter_metric_t pkt_multicast_gather_out;
        extern prometheus::simpleapi::counter_metric_t pkt_multicast_frame_out;
        extern prometheus::simpleapi::counter_metric_t pkt_push_direct_paths_out;
        extern prometheus::simpleapi::counter_metric_t pkt_user_message_out;
        extern prometheus::simpleapi::counter_metric_t pkt_remote_trace_out;
        extern prometheus::simpleapi::counter_metric_t pkt_path_negotiation_request_out;

        // ========================================================================
        // PROTOCOL ERROR METRICS
        // ========================================================================
        // Tracks ZeroTier protocol-level errors by type and direction
        // Labels: error_type={obj_not_found,unsupported_operation,etc}, direction={rx,tx}
        // Purpose: Monitor protocol errors and authentication failures
        extern prometheus::simpleapi::counter_family_t packet_errors;

        // Incoming protocol errors
        extern prometheus::simpleapi::counter_metric_t pkt_error_obj_not_found_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_unsupported_op_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_identity_collision_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_need_membership_cert_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_network_access_denied_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_unwanted_multicast_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_authentication_required_in;
        extern prometheus::simpleapi::counter_metric_t pkt_error_internal_server_error_in;

        // Outgoing protocol errors
        extern prometheus::simpleapi::counter_metric_t pkt_error_obj_not_found_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_unsupported_op_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_identity_collision_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_need_membership_cert_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_network_access_denied_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_unwanted_multicast_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_authentication_required_out;
        extern prometheus::simpleapi::counter_metric_t pkt_error_internal_server_error_out;

        // ========================================================================
        // PHYSICAL TRANSPORT METRICS
        // ========================================================================
        // Tracks raw UDP/TCP bytes sent/received at the physical transport layer
        // Labels: protocol={udp,tcp}, direction={rx,tx}
        // Purpose: Monitor total bandwidth usage by transport protocol
        // NOTE: This tracks actual bytes on the wire, not ZeroTier packet content
        extern prometheus::simpleapi::counter_family_t data;
        extern prometheus::simpleapi::counter_metric_t udp_send;
        extern prometheus::simpleapi::counter_metric_t udp_recv;
        extern prometheus::simpleapi::counter_metric_t tcp_send;
        extern prometheus::simpleapi::counter_metric_t tcp_recv;

        // ========================================================================
        // WIRE PACKET PROCESSING METRICS (DETAILED PEER TRACKING)
        // ========================================================================
        // Tracks wire packet processing results with detailed peer information
        // Labels: peer_zt_addr={ztaddr}, peer_ip={ip}, direction={rx}, result={ok,error}
        // Purpose: Detailed tracking of packet processing success/failure by peer
        // NOTE: This is different from 'peer_packets' - this tracks raw wire packets
        // before/after processing, while peer_packets tracks successful protocol exchanges
        extern prometheus::simpleapi::counter_family_t wire_packets;
        extern prometheus::simpleapi::counter_family_t wire_packet_bytes;

        // ========================================================================
        // NETWORK METRICS
        // ========================================================================
        // Tracks network-level statistics and multicast subscriptions
        extern prometheus::simpleapi::gauge_metric_t   network_num_joined;          // Number of networks joined
        extern prometheus::simpleapi::gauge_family_t   network_num_multicast_groups; // Multicast groups per network
        extern prometheus::simpleapi::counter_family_t network_packets;             // Packets per network

#ifndef ZT_NO_PEER_METRICS
        // ========================================================================
        // PER-PEER METRICS
        // ========================================================================
        // Tracks statistics for individual peers in the network

        // Peer latency histogram - tracks round-trip times to peers
        // Labels: node_id={peer_zt_address}
        // Purpose: Monitor network quality and peer connectivity
        extern prometheus::CustomFamily<prometheus::Histogram<uint64_t>> &peer_latency;

        // Number of active/dead paths to each peer
        // Labels: node_id={peer_zt_address}, status={alive,dead}
        // Purpose: Monitor path redundancy and connectivity health
        extern prometheus::simpleapi::gauge_family_t   peer_path_count;

        // Successful packet exchanges with peers (after processing)
        // Labels: direction={rx,tx}, node_id={peer_zt_address}
        // Purpose: Monitor successful communication with specific peers
        // NOTE: This counts successful ZeroTier protocol exchanges, incremented
        // in Peer::received() and Peer::recordOutgoingPacket() after processing
        extern prometheus::simpleapi::counter_family_t peer_packets;

        // Packet processing errors from peers
        // Labels: node_id={peer_zt_address}
        // Purpose: Monitor peers sending malformed or invalid packets
        extern prometheus::simpleapi::counter_family_t peer_packet_errors;
#endif

        // ========================================================================
        // CONTROLLER METRICS
        // ========================================================================
        // Metrics for ZeroTier network controller functionality
        extern prometheus::simpleapi::gauge_metric_t   network_count;
        extern prometheus::simpleapi::gauge_metric_t   member_count;
        extern prometheus::simpleapi::counter_metric_t network_changes;
        extern prometheus::simpleapi::counter_metric_t member_changes;
        extern prometheus::simpleapi::counter_metric_t member_auths;
        extern prometheus::simpleapi::counter_metric_t member_deauths;

        extern prometheus::simpleapi::gauge_metric_t network_config_request_queue_size;
        extern prometheus::simpleapi::counter_metric_t sso_expiration_checks;
        extern prometheus::simpleapi::counter_metric_t sso_member_deauth;
        extern prometheus::simpleapi::counter_metric_t network_config_request;
        extern prometheus::simpleapi::gauge_metric_t network_config_request_threads;

        extern prometheus::simpleapi::counter_metric_t db_get_network;
        extern prometheus::simpleapi::counter_metric_t db_get_network_and_member;
        extern prometheus::simpleapi::counter_metric_t db_get_network_and_member_and_summary;
        extern prometheus::simpleapi::counter_metric_t db_get_member_list;
        extern prometheus::simpleapi::counter_metric_t db_get_network_list;
        extern prometheus::simpleapi::counter_metric_t db_member_change;
        extern prometheus::simpleapi::counter_metric_t db_network_change;


#ifdef ZT_CONTROLLER_USE_LIBPQ
        // Central Controller Database Metrics
        extern prometheus::simpleapi::counter_metric_t pgsql_mem_notification;
        extern prometheus::simpleapi::counter_metric_t pgsql_net_notification;
        extern prometheus::simpleapi::counter_metric_t pgsql_node_checkin;
        extern prometheus::simpleapi::counter_metric_t pgsql_commit_ticks;
        extern prometheus::simpleapi::counter_metric_t db_get_sso_info;

        extern prometheus::simpleapi::counter_metric_t redis_mem_notification;
        extern prometheus::simpleapi::counter_metric_t redis_net_notification;
        extern prometheus::simpleapi::counter_metric_t redis_node_checkin;

        // Central DB Pool Metrics
        extern prometheus::simpleapi::counter_metric_t conn_counter;
        extern prometheus::simpleapi::counter_metric_t max_pool_size;
        extern prometheus::simpleapi::counter_metric_t min_pool_size;
        extern prometheus::simpleapi::gauge_metric_t   pool_avail;
        extern prometheus::simpleapi::gauge_metric_t   pool_in_use;
        extern prometheus::simpleapi::counter_metric_t pool_errors;
#endif
    } // namespace Metrics
}// namespace ZeroTier

#endif // METRICS_H_
