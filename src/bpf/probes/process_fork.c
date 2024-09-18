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

#include "bpf/process.h"
#include "events.h"
#include "process_util.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_process_fork_event);
} heap_process_fork_event SEC(".maps");

static_inline bool is_new_thread_group(struct task_struct *task)
{
    const u32 tgid = BPF_CORE_READ(task, tgid);
    const u32 pid = BPF_CORE_READ(task, pid);
    return pid == tgid;
}

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(event_wake_up_new_task, struct task_struct *task)
{
    if (is_kthread(task)) {
        // Don't monitor kernel threads
        return 0;
    }

    if (!is_new_thread_group(task)) {
        // Only monitor new thread groups
        return 0;
    }

    const u32 zero = 0;
    struct bpf_process_fork_event *event = bpf_map_lookup_elem(&heap_process_fork_event, &zero);
    if (!event) {
        return 0;
    }

    const size_t size = sizeof(*event);
    event->common.operation = bpf_operation_process_fork;
    event->common.size = size;
    event->common.ktime = bpf_ktime_get_ns();
    event->current.pid = BPF_CORE_READ(task, tgid);
    populate_process(&event->current, task);
    event->parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    populate_process(&event->parent, BPF_CORE_READ(task, real_parent));

    submit_event(ctx, event, size);

    return 0;
}
