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
#include "file_common_util.h"
#include "mount_include_map.h"
#include "process_util.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct bpf_file_create_event);
} heap_file_create_event SEC(".maps");

static_inline int send_file_create_event(void *ctx, const struct inode *inode, const struct dentry *dentry)
{
    const u32 zero = 0;
    struct bpf_file_create_event *event = bpf_map_lookup_elem(&heap_file_create_event, &zero);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!is_monitored_network_drive_file(inode, &event->buf.file_path_attributes.flags) ||
        !is_monitored_network_drive_exes(task,
                                         &event->buf.exe_path_attributes.flags,
                                         &event->buf.parent_exe_path_attributes.flags)) {
        return 0;
    }

    if (exclude_tgid(task)) {
        return 0;
    }

    event->common.operation = bpf_operation_file_create;
    event->common.ktime = bpf_ktime_get_ns();
    event->current.pid = BPF_CORE_READ(task, tgid);
    populate_process(&event->current, task);
    event->parent.pid = BPF_CORE_READ(task, real_parent, tgid);
    populate_process(&event->parent, BPF_CORE_READ(task, real_parent));

    const size_t buffer_size = populate_file_create_event_buffer(&event->buf, task, dentry);
    const size_t size = sizeof(*event) - sizeof(event->buf.data) + buffer_size;
    if (size > sizeof(*event)) { // Satisfy verifier
        return 0;
    }

    event->common.size = size;
    submit_event(ctx, event, size);

    return 0;
}

SEC("kprobe/security_inode_create")
int BPF_KPROBE(kprobe_security_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    return send_file_create_event(ctx, dir, dentry);
}

SEC("kprobe/security_inode_mknod")
int BPF_KPROBE(kprobe_security_inode_mknod, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    return send_file_create_event(ctx, dir, dentry);
}

SEC("kprobe/security_inode_link")
int BPF_KPROBE(kprobe_security_inode_link,
               struct dentry *old_dentry,
               struct inode *dir,
               struct dentry *new_dentry)
{
    return send_file_create_event(ctx, dir, new_dentry);
}

SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(kprobe_security_inode_symlink, struct inode *dir, struct dentry *dentry)
{
    return send_file_create_event(ctx, dir, dentry);
}
