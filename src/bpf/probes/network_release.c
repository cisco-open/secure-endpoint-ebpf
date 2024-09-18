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
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf/network.h"
#include "defines.h"
#include "events.h"
#include "file_common_util.h"
#include "network_util.h"
#include "process_util.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_network_release_event);
} heap_network_release_event SEC(".maps");

static_inline struct bpf_network_release_event *populate_common_network_release_event(struct sock *sock,
                                                                                      size_t *offset)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!is_monitored_network_drive_exes(task)) {
        return 0;
    }

    if (exclude_tgid(task)) {
        return NULL;
    }

    if (should_filter_sock(sock)) {
        return NULL;
    }

    const u32 zero = 0;
    struct bpf_network_release_event *event = bpf_map_lookup_elem(&heap_network_release_event, &zero);
    if (!event) {
        return NULL;
    }
    event->common.operation = bpf_operation_network_release;
    event->common.ktime = bpf_ktime_get_ns();
    event->current.pid = BPF_CORE_READ(task, tgid);
    populate_process(&event->current, task);
    event->parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    populate_process(&event->parent, BPF_CORE_READ(task, real_parent));

    event->socket.sock_id = socket_id(sock);
    event->socket.protocol = socket_protocol(sock);

    populate_event_parent_and_child_exe(&event->buf.parent_exe_path_attributes,
                                        &event->buf.exe_path_attributes,
                                        event->buf.data,
                                        offset);
    if (*offset > sizeof(event->buf.data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    return event;
}

static_inline int send_network_release_event(void *ctx,
                                             struct bpf_network_release_event *event,
                                             uint32_t buffer_size)
{
    const size_t size = sizeof(*event) - sizeof(event->buf.data) + buffer_size;
    event->common.size = size;
    submit_event(ctx, event, size);

    return 0;
}

SEC("kprobe/inet_release")
int BPF_KPROBE(kprobe_inet_release, struct socket *socket)
{
    struct sock *sock = BPF_CORE_READ(socket, sk);
    size_t buffer_size = 0;
    struct bpf_network_release_event *event = populate_common_network_release_event(sock, &buffer_size);
    if (!event) {
        return 0;
    }

    populate_ipv4_buf(&event->buf, &buffer_size, sock);

    return send_network_release_event(ctx, event, buffer_size);
}

SEC("kprobe/inet6_release")
int BPF_KPROBE(kprobe_inet6_release, struct socket *socket)
{
    struct sock *sock = BPF_CORE_READ(socket, sk);
    size_t buffer_size = 0;
    struct bpf_network_release_event *event = populate_common_network_release_event(sock, &buffer_size);
    if (!event) {
        return 0;
    }

    populate_ipv6_buf(&event->buf, &buffer_size, sock);

    return send_network_release_event(ctx, event, buffer_size);
}
