/**
 * @file
 *
 * @copyright (c) 2024 Cisco Systems, Inc. All rights reserved
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * This library is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation; either version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License or the LICENSE file for more details.
 */

#pragma once

#include "vmlinux_custom.h"

#include <bpf/bpf_core_read.h>

#include "bpf/network.h"
#include "defines.h"
#include "file_path_util.h"

static_inline u64 socket_id(const struct sock *sock)
{
    return (u64)sock;
}

static_inline uint16_t socket_protocol(const struct sock *sk)
{
    if (bpf_core_field_exists(((struct sock___old *)(NULL))->__sk_flags_offset)) {
        uint16_t protocol = 0;
        struct sock___old *old_sock = (struct sock___old *)sk;
        bpf_core_read(&protocol, 1, (void *)(&old_sock->sk_gso_max_segs) - 3);
        return protocol;
    }

    return BPF_CORE_READ(sk, sk_protocol);
}

static_inline uint16_t socket_type(const struct sock *sk)
{
    if (bpf_core_field_exists(((struct sock___old *)(NULL))->__sk_flags_offset)) {
        uint16_t type = 0;
        struct sock___old *old_sock = (struct sock___old *)sk;
        bpf_core_read(&type, 1, (void *)(&old_sock->sk_gso_max_segs) - 2);
        return type;
    }

    return BPF_CORE_READ(sk, sk_type);
}

static_inline void populate_local_ipv4(struct sockaddr_in *addr_out, struct sock *sock)
{
    const struct inet_sock *inet = inet_sk(sock);

    addr_out->sin_family = AF_INET;
    addr_out->sin_addr.s_addr = BPF_CORE_READ(inet, sk.__sk_common.skc_rcv_saddr);
    addr_out->sin_port = BPF_CORE_READ(inet, inet_sport);
}

static_inline void populate_local_ipv6(struct sockaddr_in6 *addr_out, struct sock *sock)
{
    const struct inet_sock *inet = inet_sk(sock);

    addr_out->sin6_family = AF_INET6;
    addr_out->sin6_flowinfo = 0;
    addr_out->sin6_addr = BPF_CORE_READ(sock, __sk_common.skc_v6_rcv_saddr);
    addr_out->sin6_scope_id = 0;
    addr_out->sin6_port = BPF_CORE_READ(inet, inet_sport);
}

static_inline void populate_remote_ipv4(struct sockaddr_in *addr_out, struct sock *sock)
{
    const struct inet_sock *inet = inet_sk(sock);

    addr_out->sin_family = AF_INET;
    addr_out->sin_addr.s_addr = BPF_CORE_READ(inet, sk.__sk_common.skc_daddr);
    addr_out->sin_port = BPF_CORE_READ(inet, sk.__sk_common.skc_dport);
}

static_inline void populate_remote_ipv6(struct sockaddr_in6 *addr_out, struct sock *sock)
{
    const struct inet_sock *inet = inet_sk(sock);

    addr_out->sin6_family = AF_INET6;
    addr_out->sin6_flowinfo = 0;
    addr_out->sin6_addr = BPF_CORE_READ(sock, __sk_common.skc_v6_daddr);
    addr_out->sin6_scope_id = 0;
    addr_out->sin6_port = BPF_CORE_READ(inet, sk.__sk_common.skc_dport);
}

static_inline bool is_loopback_ipv4(const struct sockaddr_in *addr)
{
    return (ipv4_addr_any(&addr->sin_addr) || ipv4_addr_loopback(&addr->sin_addr));
}

static_inline bool is_loopback_ipv6(const struct sockaddr_in6 *addr)
{
    return (ipv6_addr_loopback(&addr->sin6_addr) || ipv6_addr_any(&addr->sin6_addr));
}

static_inline void populate_local_ipv4_buf(struct bpf_network_event_buf *buf,
                                           size_t *offset,
                                           struct sock *sock)
{
    buf->local_addr_attributes.offset = *offset;
    struct sockaddr_in *local_addr = (struct sockaddr_in *)&buf->data[*offset];
    const size_t size = sizeof(*local_addr);
    buf->local_addr_attributes.size = size;
    *offset += size;

    populate_local_ipv4(local_addr, sock);
    buf->local_addr_attributes.is_loopback = false;
}

static_inline void populate_ipv4_buf(struct bpf_network_event_buf *buf, size_t *offset, struct sock *sock)
{
    populate_local_ipv4_buf(buf, offset, sock);

    buf->remote_addr_attributes.offset = *offset;
    struct sockaddr_in *remote_addr = (struct sockaddr_in *)&buf->data[*offset];
    const size_t size = sizeof(*remote_addr);
    buf->local_addr_attributes.size = size;
    *offset += size;

    populate_remote_ipv4(remote_addr, sock);
    buf->remote_addr_attributes.is_loopback = is_loopback_ipv4(remote_addr);
}

static_inline void populate_local_ipv6_buf(struct bpf_network_event_buf *buf,
                                           size_t *offset,
                                           struct sock *sock)
{
    buf->local_addr_attributes.offset = *offset;
    struct sockaddr_in6 *local_addr = (struct sockaddr_in6 *)&buf->data[*offset];
    const size_t size = sizeof(*local_addr);
    buf->local_addr_attributes.size = size;
    *offset += size;

    populate_local_ipv6(local_addr, sock);
    buf->local_addr_attributes.is_loopback = false;
}

static_inline void populate_ipv6_buf(struct bpf_network_event_buf *buf, size_t *offset, struct sock *sock)
{
    populate_local_ipv6_buf(buf, offset, sock);

    buf->remote_addr_attributes.offset = *offset;
    struct sockaddr_in6 *remote_addr = (struct sockaddr_in6 *)&buf->data[*offset];
    const size_t size = sizeof(*remote_addr);
    buf->remote_addr_attributes.size = size;
    *offset += size;

    populate_remote_ipv6(remote_addr, sock);
    buf->remote_addr_attributes.is_loopback = is_loopback_ipv6(remote_addr);
}

static_inline void populate_ipv4_msg_buf(struct bpf_network_event_buf *buf,
                                         size_t *offset,
                                         struct sock *sock,
                                         struct msghdr *msg)
{
    populate_local_ipv4_buf(buf, offset, sock);

    buf->remote_addr_attributes.offset = *offset;
    struct sockaddr_in *remote_addr = (struct sockaddr_in *)&buf->data[*offset];
    const size_t size = sizeof(*remote_addr);
    buf->remote_addr_attributes.size = size;
    *offset += size;

    if (BPF_CORE_READ(msg, msg_name) && (BPF_CORE_READ(msg, msg_namelen) == size)) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        bpf_core_read(remote_addr, size, msg_name);
    } else {
        populate_remote_ipv4(remote_addr, sock);
    }
    buf->remote_addr_attributes.is_loopback = is_loopback_ipv4(remote_addr);
}

static_inline void populate_ipv6_msg_buf(struct bpf_network_event_buf *buf,
                                         size_t *offset,
                                         struct sock *sock,
                                         struct msghdr *msg)
{
    populate_local_ipv6_buf(buf, offset, sock);

    buf->remote_addr_attributes.offset = *offset;
    struct sockaddr_in6 *remote_addr = (struct sockaddr_in6 *)&buf->data[*offset];
    const size_t size = sizeof(*remote_addr);
    buf->remote_addr_attributes.size = size;
    *offset += size;

    if (BPF_CORE_READ(msg, msg_name) && (BPF_CORE_READ(msg, msg_namelen) == size)) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        bpf_core_read(remote_addr, size, msg_name);
    } else {
        populate_remote_ipv6(remote_addr, sock);
    }
    buf->remote_addr_attributes.is_loopback = is_loopback_ipv6(remote_addr);
}

static_inline bool sockaddr_in_equal(const struct sockaddr_in *addr1, const struct sockaddr_in *addr2)
{
    return (addr1->sin_port == addr2->sin_port) && (addr1->sin_addr.s_addr == addr2->sin_addr.s_addr);
}

static_inline bool sockaddr_in6_equal(const struct sockaddr_in6 *addr1, const struct sockaddr_in6 *addr2)
{
    return ((addr1->sin6_port == addr2->sin6_port) &&
            (addr1->sin6_addr.in6_u.u6_addr32[0] == addr2->sin6_addr.in6_u.u6_addr32[0]) &&
            (addr1->sin6_addr.in6_u.u6_addr32[1] == addr2->sin6_addr.in6_u.u6_addr32[1]) &&
            (addr1->sin6_addr.in6_u.u6_addr32[2] == addr2->sin6_addr.in6_u.u6_addr32[2]) &&
            (addr1->sin6_addr.in6_u.u6_addr32[3] == addr2->sin6_addr.in6_u.u6_addr32[3]));
}

static_inline bool sockaddr_equal(const struct sockaddr *addr1, const struct sockaddr *addr2)
{
    if (addr1->sa_family == AF_INET && addr1->sa_family == addr2->sa_family) {
        return sockaddr_in_equal((const struct sockaddr_in *)addr1, (const struct sockaddr_in *)addr2);
    } else if (addr1->sa_family == AF_INET6 && addr1->sa_family == addr2->sa_family) {
        return sockaddr_in6_equal((const struct sockaddr_in6 *)addr1, (const struct sockaddr_in6 *)addr2);
    }
    return false;
}

static_inline bool is_supported_protocol(struct sock *sk)
{
    const u16 protocol = socket_protocol(sk);
    switch (protocol) {
        case IPPROTO_IP: // Dummy protocol for TCP. Can be valid, need to check sock family and type.
        case IPPROTO_IPV6:
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            break;
        default:
            return false; // Not supported.
    }
    return true;
}

static_inline bool is_monitored_socket_type(struct sock *sk)
{
    const u16 type = socket_type(sk);
    switch (type) {
        case SOCK_STREAM: // stream (connection) socket
        case SOCK_DGRAM:  // datagram (conn.less) socket
            break;
        default:
            return false; // Not supported.
    }
    return true;
}

static_inline bool is_monitored_socket_family(struct sock *sk)
{
    const sa_family_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
    switch (family) {
        case AF_INET:
        case AF_INET6:
            break;
        default:
            return false; // Not supported.
    }
    return true;
}

static_inline bool should_filter_sock(struct sock *sk)
{
    if (!is_supported_protocol(sk)) {
        return true;
    }

    if (!is_monitored_socket_type(sk)) {
        return true;
    }

    if (!is_monitored_socket_family(sk)) {
        return true;
    }
    return false;
}
