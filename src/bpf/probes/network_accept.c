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
    __type(value, struct bpf_network_accept_event);
} heap_network_accept_event SEC(".maps");

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept)
{
    const u32 zero = 0;
    struct bpf_network_accept_event *event = bpf_map_lookup_elem(&heap_network_accept_event, &zero);
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

    struct sock *sk = (struct sock *)PT_REGS_RC_CORE(ctx);
    if (!sk || should_filter_sock(sk)) {
        return 0;
    }

    event->common.operation = bpf_operation_network_accept;
    event->common.ktime = bpf_ktime_get_ns();
    event->current.pid = BPF_CORE_READ(task, tgid);
    populate_process(&event->current, task);
    event->parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    populate_process(&event->parent, BPF_CORE_READ(task, real_parent));

    size_t offset = 0;

    populate_event_parent_and_child_exe(&event->buf.parent_exe_path_attributes,
                                        &event->buf.exe_path_attributes,
                                        event->buf.data,
                                        &offset);
    if (offset > sizeof(event->buf.data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    event->socket.sock_id = socket_id(sk);

    const sa_family_t family = BPF_CORE_READ(sk, __sk_common.skc_family);
    size_t address_size = 0;

    event->buf.local_addr_attributes.offset = offset;
    if (family == AF_INET) {
        populate_ipv4_buf(&event->buf, &offset, sk);
    } else if (family == AF_INET6) {
        populate_ipv6_buf(&event->buf, &offset, sk);
    } else {
        return 0;
    }

    if (event->buf.remote_addr_attributes.is_loopback) {
        return 0;
    }

    const size_t size = sizeof(*event) - sizeof(event->buf.data) + offset;
    event->common.size = size;
    submit_event(ctx, event, size);

    return 0;
}
