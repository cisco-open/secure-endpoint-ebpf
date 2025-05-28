/**
 * @file
 *
 * @copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
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

#include "file_id.h"
#include "tpv_maps.h"
#include "process_util.h"

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(tpv_task_alloc, struct task_struct *task)
{
    if (is_kthread(task)) {
        // Don't monitor kernel threads
        return 0;
    }

    if (!is_new_thread_group(task)) {
        // Only monitor new thread groups
        return 0;
    }

    pid_t pid = BPF_CORE_READ(task, tgid);
    if (is_pid_trusted(pid)) {
        // Exit early if pid is trusted.
        return 0;
    }

    pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
    file_id_t *file_id = get_trusted_file_id(ppid);
    if (file_id) {
        // Parent is trusted so child should also be trusted.
        add_trusted_pid(pid, file_id);
        return 0;
    } 
    
    const struct file *file = BPF_CORE_READ(task, mm, exe_file);
    const struct path *path = __builtin_preserve_access_index(&file->f_path);
    const struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
    get_file_id_in_place(file_id, inode);
    if (file_id && is_file_trusted(file_id)) {
        // If path is trusted then child should be trusted.
        add_trusted_pid(pid, file_id);
    }

    return 0;
}

SEC("kprobe/acct_process")
int BPF_KPROBE(tpv_task_free)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        return 0;
    }

    if (is_kthread(task)) {
        // Don't monitor kernel threads
        return 0;
    }
    
    pid_t pid = BPF_CORE_READ(task, tgid);
    file_id_t *file_id = get_trusted_file_id(pid);
    if (!file_id) {
        // Exit early if pid is not trusted.
        return 0;
    }

    remove_trusted_pid(pid, file_id);
    return 0;
}
