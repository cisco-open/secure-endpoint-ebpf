/**
 * @file
 * @copyright (c) 2020-2024 Cisco Systems, Inc. All rights reserved
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
#include "bpf/file.h"
#include "events.h"
#include "file_access_util.h"
#include "file_common_util.h"
#include "process_util.h"

char LICENSE[] SEC("license") = "GPL";
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_file_close_write_event);
} heap_file_close_write_event SEC(".maps");

static bool is_file_open_for_write(fmode_t fmode)
{
    return fmode & FMODE_WRITE;
}

SEC("kprobe/__fput")
int BPF_KPROBE(kprobe_fput_probe, struct file *file)
{
    fmode_t fmode = BPF_CORE_READ(file, f_mode);
    if (!is_file_open_for_write(fmode)) {
        return 0;
    }

    const u32 zero = 0;
    struct bpf_file_close_write_event *event = bpf_map_lookup_elem(&heap_file_close_write_event, &zero);
    if (!event) {
        return 0;
    }

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (should_filter_accessed_file(task, dentry, bpf_operation_file_close_write, &event->buf)) {
        return 0;
    }

    event->common.operation = bpf_operation_file_close_write;
    event->common.ktime = bpf_ktime_get_ns();
    event->current.pid = BPF_CORE_READ(task, tgid);
    populate_process(&event->current, task);
    event->parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    populate_process(&event->parent, BPF_CORE_READ(task, real_parent));

    const size_t buffer_size = populate_file_event_buffer_from_file(&event->buf, task, file);
    const size_t size = sizeof(*event) - sizeof(event->buf.data) + buffer_size;
    if (size > sizeof(*event)) { // Satisfy verifier
        return 0;
    }

    event->common.size = size;
    submit_event(ctx, event, size);

    return 0;
}
