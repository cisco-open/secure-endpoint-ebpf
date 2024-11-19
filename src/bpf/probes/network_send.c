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

#include "vmlinux_custom.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf/network.h"
#include "defines.h"
#include "events.h"
#include "file_common_util.h"
#include "network_util.h"
#include "process_util.h"
#include "socket_cache.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_network_send_event);
} heap_network_send_event SEC(".maps");

static_inline void populate_send_addr_ipv4(struct bpf_network_send_event *event,
                                           size_t *offset,
                                           struct sock *sock,
                                           struct msghdr *msg)
{
    event->buf.local_addr_attributes.offset = *offset;
    struct sockaddr_in *local_addr = (struct sockaddr_in *)&event->buf.data[*offset];
    const size_t addr_size = sizeof(*local_addr);
    event->buf.local_addr_attributes.size = addr_size;
    *offset += addr_size;

    event->buf.remote_addr_attributes.offset = *offset;
    struct sockaddr_in *remote_addr = (struct sockaddr_in *)&event->buf.data[*offset];
    event->buf.remote_addr_attributes.size = addr_size;
    *offset += addr_size;

    populate_local_ipv4(local_addr, sock);
    if (BPF_CORE_READ(msg, msg_name) && (BPF_CORE_READ(msg, msg_namelen) == addr_size)) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        bpf_core_read(remote_addr, addr_size, msg_name);
    } else {
        populate_remote_ipv4(remote_addr, sock);
    }
    event->buf.local_addr_attributes.is_loopback = false;
    event->buf.remote_addr_attributes.is_loopback = is_loopback_ipv4(remote_addr);
}

static_inline void populate_send_addr_ipv6(struct bpf_network_send_event *event,
                                           size_t *offset,
                                           struct sock *sock,
                                           struct msghdr *msg)
{
    event->buf.local_addr_attributes.offset = *offset;
    struct sockaddr_in6 *local_addr = (struct sockaddr_in6 *)&event->buf.data[*offset];
    const size_t addr_size = sizeof(*local_addr);
    event->buf.local_addr_attributes.size = addr_size;
    *offset += addr_size;

    event->buf.remote_addr_attributes.offset = *offset;
    struct sockaddr_in6 *remote_addr = (struct sockaddr_in6 *)&event->buf.data[*offset];
    event->buf.remote_addr_attributes.size = addr_size;
    *offset += addr_size;

    populate_local_ipv6(local_addr, sock);
    if (BPF_CORE_READ(msg, msg_name) && (BPF_CORE_READ(msg, msg_namelen) == addr_size)) {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        bpf_core_read(remote_addr, addr_size, msg_name);
    } else {
        populate_remote_ipv6(remote_addr, sock);
    }
    event->buf.local_addr_attributes.is_loopback = false;
    event->buf.remote_addr_attributes.is_loopback = is_loopback_ipv6(remote_addr);
}

#define PAYLOAD_COPY_BUF_SIZE (PAYLOAD_MAX_SIZE << 1)
#define LIMIT_PAYLOAD_SIZE(x) ((x) & (PAYLOAD_MAX_SIZE - 1))

static_inline bool filter_sockaddr(const struct bpf_network_send_event *event)
{
    if (event->buf.remote_addr_attributes.is_loopback) {
        return true;
    }

    const struct socket_cache_entry *entry = socket_cache_create_entry(
        (const struct sockaddr *)&event->buf.data[event->buf.remote_addr_attributes.offset],
        event->buf.remote_addr_attributes.size);
    if (!entry) {
        return false;
    }

    const u64 socket_id = event->socket.sock_id;
    const struct socket_cache_entry *socket = socket_cache_find_entry(socket_id, entry);
    if (socket) {
        return socket->bytes_sent >= PAYLOAD_MAX_SIZE;
    }

    socket_cache_update(socket_id, entry);
    return false;
}

struct payload_buf {
    uint8_t data[PAYLOAD_COPY_BUF_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct payload_buf);
} heap_payload_buf SEC(".maps");

#define MAX_IOVEC_ITERS 10
static_inline size_t copy_from_iovec(char *buf, size_t buf_size, const struct iovec *iov, size_t offset)
{
    size_t length = 0u;
#pragma unroll MAX_IOVEC_ITERS
    for (int i = 0; i < MAX_IOVEC_ITERS; ++i) {
        length = BPF_CORE_READ(iov, iov_len);
        if (offset < length) {
            break;
        }
        offset -= length;
        iov++;
    }

    if (offset >= length) {
        return 0u;
    }

    u32 zero = 0;
    struct payload_buf *tmp_buf = bpf_map_lookup_elem(&heap_payload_buf, &zero);
    if (!tmp_buf) {
        return 0;
    }

    size_t buf_offset = 0;
#pragma unroll MAX_IOVEC_ITERS
    for (int i = 0; i < MAX_IOVEC_ITERS; ++i) {
        if (buf_size == 0) {
            break;
        }

        void *base = BPF_CORE_READ(iov, iov_base) + offset;
        u32 read_size = BPF_CORE_READ(iov, iov_len) - offset;
        offset = 0;

        if (read_size == 0) {
            break;
        } else if (read_size > buf_size) {
            buf_size = LIMIT_PAYLOAD_SIZE(buf_size); // Satisfy Verifier
            read_size = buf_size;
        }
        read_size = LIMIT_PAYLOAD_SIZE(read_size);   // Satisfy Verifier
        buf_offset = LIMIT_PAYLOAD_SIZE(buf_offset); // Satisfy Verifier

        bpf_probe_read_user(&tmp_buf->data[buf_offset], read_size, base);

        buf_offset += read_size;
        buf_offset = LIMIT_PAYLOAD_SIZE(buf_offset); // Satisfy Verifier
        buf_size -= read_size;
        buf_size = LIMIT_PAYLOAD_SIZE(buf_size); // Satisfy Verifier

        iov++;
    }
    bpf_probe_read_kernel(buf, buf_offset, tmp_buf->data);

    return buf_offset;
}

static_inline size_t copy_msg_payload(char *buf, size_t buf_size, struct msghdr *msg)
{
    const struct iov_iter *iter = __builtin_preserve_access_index(&msg->msg_iter);
    if ((iov_iter_rw(iter) != WRITE) || !user_backed_iter(iter)) {
        return 0;
    }

    return copy_from_iovec(buf, buf_size, iter_iov(iter), BPF_CORE_READ(iter, iov_offset));
}

static_inline size_t parse_msg(struct bpf_network_send_event *event,
                               size_t *offset,
                               struct msghdr *msg,
                               size_t msg_size)
{
    struct socket_cache_entry *socket = socket_cache_find(event->socket.sock_id);
    if (!socket) {
        return 0;
    }

    const size_t bytes_sent = socket->bytes_sent;
    event->buf.payload.seq = bytes_sent;
    event->buf.payload.buf_offset = *offset;

    char *buf = &event->buf.data[event->buf.payload.buf_offset];
    const size_t available_size = PAYLOAD_MAX_SIZE - bytes_sent - 1;
    const size_t read_size = (msg_size < available_size) ? msg_size : available_size;

    const size_t payload_size = copy_msg_payload(buf, read_size, msg);
    event->buf.payload.size = payload_size;
    socket->bytes_sent += event->buf.payload.size;
    *offset += event->buf.payload.size;

    return payload_size;
}

SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(kprobe_security_socket_send, struct socket *socket, struct msghdr *msg, int msg_size)
{
    const u32 zero = 0;
    struct bpf_network_send_event *event = bpf_map_lookup_elem(&heap_network_send_event, &zero);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!is_monitored_network_drive_exes(task,
                                         &event->buf.exe_path_attributes.flags,
                                         &event->buf.parent_exe_path_attributes.flags)) {
        return 0;
    }

    if (exclude_tgid(task)) {
        return 0;
    }

    struct sock *sk = BPF_CORE_READ(socket, sk);
    if (!sk || should_filter_sock(sk)) {
        return 0;
    }

    struct sock *sock = BPF_CORE_READ(socket, sk);
    if (!sock) {
        return 0;
    }

    event->socket.sock_id = socket_id(sock);
    event->socket.protocol = socket_protocol(sock);

    event->common.operation = bpf_operation_network_send;
    event->common.ktime = bpf_ktime_get_ns();
    event->current.pid = BPF_CORE_READ(task, tgid);
    populate_process(&event->current, task);
    event->parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    populate_process(&event->parent, BPF_CORE_READ(task, real_parent));

    const sa_family_t family = BPF_CORE_READ(sock, __sk_common.skc_family);
    size_t offset = 0;
    if (family == AF_INET) {
        populate_send_addr_ipv4(event, &offset, sock, msg);
    } else if (family == AF_INET6) {
        populate_send_addr_ipv6(event, &offset, sock, msg);
    } else {
        return 0;
    }

    if (filter_sockaddr(event)) {
        return 0;
    }

    if (event->socket.protocol == IPPROTO_TCP) {
        if (msg_size <= 0) {
            return 0;
        }
        if (parse_msg(event, &offset, msg, (size_t)msg_size) == 0) {
            return 0;
        }
    }

    populate_event_parent_and_child_exe(&event->buf.parent_exe_path_attributes,
                                        &event->buf.exe_path_attributes,
                                        event->buf.data,
                                        &offset);
    if (offset > sizeof(event->buf.data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    const size_t size = sizeof(*event) - sizeof(event->buf.data) + offset;
    event->common.size = size;
    submit_event(ctx, event, size);

    return 0;
}
