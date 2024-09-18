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

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf/process.h"
#include "events.h"
#include "file_common_util.h"
#include "file_path_util.h"
#include "mount_include_map.h"
#include "process_util.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_process_exec_event);
} heap_process_exec_event SEC(".maps");

static_inline size_t populate_process_args(char *buffer, size_t size, const struct task_struct *task)
{
    const unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
    const unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);
    if (!arg_start || !arg_end || arg_start >= arg_end) {
        return 0;
    }

    const size_t args_size = arg_end - arg_start;
    if (args_size > size) {
        /** If args size is larger than available size, then defer retrieving args to user space.
         * This ensures that command line args are not truncated/incomplete.
         */
        return 0;
    }

    if (bpf_probe_read_user(buffer, args_size, (const void *)arg_start) != 0) {
        return 0;
    }

    return args_size;
}

static_inline size_t populate_process_env(char *buffer, size_t size, const struct task_struct *task)
{
    const unsigned long env_start = BPF_CORE_READ(task, mm, env_start);
    const unsigned long env_end = BPF_CORE_READ(task, mm, env_end);
    if (!env_start || !env_end || env_start >= env_end) {
        return 0;
    }

    const size_t env_size = env_end - env_start;
    if (env_size > size) {
        /** If env size is larger than available size, then defer retrieving env to user space.
         * This ensures that process environment is not truncated/incomplete.
         */
        return 0;
    }

    if (bpf_probe_read_user(buffer, env_size, (const void *)env_start) != 0) {
        return 0;
    }

    return env_size;
}

SEC("kprobe/proc_exec_connector")
int BPF_KPROBE(event_proc_exec_connector_probe, struct task_struct *task)
{
    const u32 zero = 0;
    struct bpf_process_exec_event *event = bpf_map_lookup_elem(&heap_process_exec_event, &zero);
    if (!event) {
        return 0;
    }

    if (!is_monitored_network_drive_exes(task)) {
        return 0;
    }

    event->common.operation = bpf_operation_process_exec;
    event->common.ktime = bpf_ktime_get_ns();
    event->current.pid = BPF_CORE_READ(task, tgid);
    populate_process(&event->current, task);
    event->parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    populate_process(&event->parent, BPF_CORE_READ(task, real_parent));

    const size_t buf_data_size = sizeof(event->buf.data);
    size_t offset = 0;

    populate_event_parent_and_child_exe(&event->buf.parent_exe_path_attributes,
                                        &event->buf.exe_path_attributes,
                                        event->buf.data,
                                        &offset);
    if (offset > sizeof(event->buf.data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    event->buf.args_attributes.args_offset = offset;
    event->buf.args_attributes.args_size =
        populate_process_args(&event->buf.data[offset], MAX_ARGS_BUF_SIZE, task);
    offset += event->buf.args_attributes.args_size;

    if (offset > buf_data_size - MAX_ENV_BUF_SIZE) { // Satisfy verifier
        return 0;
    }
    event->buf.env_attributes.env_offset = offset;
    event->buf.env_attributes.env_size =
        populate_process_env(&event->buf.data[offset], MAX_ENV_BUF_SIZE, task);
    offset += event->buf.env_attributes.env_size;

    const size_t size = sizeof(*event) - buf_data_size + offset;
    if (size > sizeof(*event)) { // Satisfy verifier
        return 0;
    }
    event->common.size = size;

    submit_event(ctx, event, size);
    return 0;
}
