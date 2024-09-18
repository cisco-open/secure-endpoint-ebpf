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

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "defines.h"
#include "pid_exclusion_map.h"

static_inline bool is_kthread(const struct task_struct *task)
{
    const unsigned int flags = BPF_CORE_READ(task, flags);
    return flags & PF_KTHREAD;
}

static_inline bool exclude_tgid(const struct task_struct *task)
{
    pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);
    bool *apply_to_child = bpf_map_lookup_elem(&excluded_pids, &ppid);
    if (apply_to_child && *apply_to_child) {
        return true;
    }
    pid_t pid = BPF_CORE_READ(task, tgid);
    return bpf_map_lookup_elem(&excluded_pids, &pid);
}

static_inline pid_t task_pid(const struct task_struct *task, enum pid_type type)
{
    struct pid *pid;
    if (bpf_core_field_exists(task->signal->pids)) {
        pid = BPF_CORE_READ(task, signal, pids[type]);
    } else {
        struct task_struct___older_v50 *old_task = (struct task_struct___older_v50 *)task;
        pid = BPF_CORE_READ(old_task, pids[type].pid);
    }
    const unsigned int level = BPF_CORE_READ(pid, level);
    return BPF_CORE_READ(pid, numbers[level].nr);
}

static_inline void populate_process(struct bpf_process *proc, const struct task_struct *task)
{
    if (bpf_core_enum_value_exists(enum pid_type, PIDTYPE_TGID)) {
        proc->nspid = task_pid(task, bpf_core_enum_value(enum pid_type, PIDTYPE_TGID));
    } else {
        proc->nspid = task_pid(task, bpf_core_enum_value(enum pid_type, PIDTYPE_PID));
    }
    proc->pgid = task_pid(task, bpf_core_enum_value(enum pid_type, PIDTYPE_PGID));
    proc->sid = task_pid(task, bpf_core_enum_value(enum pid_type, PIDTYPE_SID));

    proc->user.ruid = BPF_CORE_READ(task, cred, uid.val);
    proc->user.euid = BPF_CORE_READ(task, cred, euid.val);
    proc->user.gid = BPF_CORE_READ(task, cred, gid.val);
    proc->user.egid = BPF_CORE_READ(task, cred, egid.val);
}
