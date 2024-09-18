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

#pragma once

#include "vmlinux_custom.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <linux/magic.h>

#include "bpf/file.h"
#include "mount_include_map.h"
#include "process_util.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct file_access_id);
} heap_file_access_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct file_pid_access_id);
} heap_file_pid_access_id SEC(".maps");

/**
 * Declare file_access_times map to be linked to userspace FileAccessTimeMaps in the BTF AMF implementation.
 * It stores the access time keyed on the file access id.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);
    __type(key, struct file_access_id);
    __type(value, struct file_access_time);
} file_access_times SEC(".maps");

/**
 * Declare file_access_times_by_pid map to be linked to userspace FileAccessTimeMaps in the BTF AMF
 * implementation. It stores the access time keyed on the file access id.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);
    __type(key, struct file_pid_access_id);
    __type(value, struct file_access_time);
} file_access_times_by_pid SEC(".maps");

static_inline void remove_all_accessed_file(struct file_access_id *file_access_id)
{
    file_access_id->operation = bpf_operation_file_close_write;
    bpf_map_delete_elem(&file_access_times, file_access_id);
    file_access_id->operation = bpf_operation_file_read;
    bpf_map_delete_elem(&file_access_times, file_access_id);
    file_access_id->operation = bpf_operation_file_write;
    bpf_map_delete_elem(&file_access_times, file_access_id);
}

static_inline bool is_from_special_filesystem_type(long unsigned int magic)
{
    switch (magic) {
        case ANON_INODE_FS_MAGIC:
#ifdef BINDERFS_SUPER_MAGIC
        case BINDERFS_SUPER_MAGIC:
#endif /* BINDERFS_SUPER_MAGIC */
#ifdef BPF_FS_MAGIC
        case BPF_FS_MAGIC:
#endif /* BPF_FS_MAGIC */
#ifdef CGROUP2_SUPER_MAGIC
        case CGROUP2_SUPER_MAGIC:
#endif /* CGROUP2_SUPER_MAGIC */
        case CGROUP_SUPER_MAGIC:
        case DEBUGFS_MAGIC:
        case DEVPTS_SUPER_MAGIC:
        case FUTEXFS_SUPER_MAGIC:
#ifdef NSFS_MAGIC
        case NSFS_MAGIC:
#endif /* NSFS_MAGIC */
        case PROC_SUPER_MAGIC:
        case SELINUX_MAGIC:
#ifdef SMACK_MAGIC
        case SMACK_MAGIC:
#endif /* SMACK_MAGIC */
        case SOCKFS_MAGIC:
        case SYSFS_MAGIC:
#ifdef TRACEFS_MAGIC
        case TRACEFS_MAGIC:
#endif /* TRACEFS_MAGIC */
            return true;
    }

    return false;
}

static_inline bool is_from_monitored_filesystem_type(long unsigned int magic)
{
    return !is_from_special_filesystem_type(magic);
}

static_inline bool is_monitored_file_type_with_path(const uint32_t mode)
{
    /* The following should always have a file path associated with them */
    return (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode));
}

static_inline bool is_monitored_file_type(const uint32_t mode)
{
    return (is_monitored_file_type_with_path(mode) || S_ISFIFO(mode) || S_ISSOCK(mode));
}

static_inline bool is_monitored(const struct dentry *dentry)
{
    const struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    const long unsigned int magic = BPF_CORE_READ(inode, i_sb, s_magic);
    if (!is_from_monitored_filesystem_type(magic)) {
        return false;
    }

    const umode_t mode = BPF_CORE_READ(inode, i_mode);
    if (!is_monitored_file_type(mode)) {
        return false;
    }

    return true;
}

static_inline bool is_monitored_with_path(const struct dentry *dentry)
{
    const struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    const long unsigned int magic = BPF_CORE_READ(inode, i_sb, s_magic);
    if (!is_from_monitored_filesystem_type(magic)) {
        return false;
    }

    const umode_t mode = BPF_CORE_READ(inode, i_mode);
    if (!is_monitored_file_type_with_path(mode)) {
        return false;
    }

    return true;
}

static_inline struct file_access_id *gen_file_access_id(const struct task_struct *task,
                                                        const struct dentry *dentry,
                                                        uint8_t operation)
{
    const u32 zero = 0;
    struct file_access_id *file_access_id = bpf_map_lookup_elem(&heap_file_access_id, &zero);
    if (!file_access_id) {
        return NULL;
    }

    const struct inode *file_inode = BPF_CORE_READ(dentry, d_inode);

    file_access_id->file_inode = BPF_CORE_READ(file_inode, i_ino);
    file_access_id->device = BPF_CORE_READ(file_inode, i_sb, s_dev);
    file_access_id->hash = BPF_CORE_READ(dentry, d_name.hash);
    file_access_id->operation = operation;

    return file_access_id;
}

static_inline struct file_pid_access_id *gen_file_pid_access_id(struct file_access_id *file_access_id,
                                                                const struct task_struct *task)
{
    const u32 zero = 0;
    struct file_pid_access_id *file_pid_access_id = bpf_map_lookup_elem(&heap_file_pid_access_id, &zero);
    if (!file_pid_access_id) {
        return NULL;
    }

    const struct file *exe_file = BPF_CORE_READ(task, mm, exe_file);
    const struct path *exe_path = __builtin_preserve_access_index(&exe_file->f_path);
    const struct inode *exe_inode = BPF_CORE_READ(exe_path, dentry, d_inode);

    file_pid_access_id->id.file_inode = file_access_id->file_inode;
    file_pid_access_id->id.device = file_access_id->device;
    file_pid_access_id->id.operation = file_access_id->operation;
    file_pid_access_id->exe_inode = BPF_CORE_READ(exe_inode, i_ino);
    file_pid_access_id->tgid = BPF_CORE_READ(task, tgid);

    return file_pid_access_id;
}

static_inline bool init_access_time(const struct file_access_id *file_access_id, u64 current_time_ns)
{
    struct file_access_time access_time;
    access_time.time_ns = current_time_ns;
    return bpf_map_update_elem(&file_access_times, file_access_id, &access_time, BPF_NOEXIST) == 0;
}

static_inline bool init_pid_access_time(const struct file_pid_access_id *file_pid_access_id,
                                        u64 current_time_ns)
{
    struct file_access_time access_time;
    access_time.time_ns = current_time_ns;
    return bpf_map_update_elem(&file_access_times_by_pid, file_pid_access_id, &access_time, BPF_NOEXIST) ==
           0;
}

static_inline bool resend_delay_elapsed(struct file_access_time *access_time, u64 current_time_ns)
{
    static const u64 resend_delay_s = 10;
    static const u64 resend_delay_ns = resend_delay_s * (u64)1e9;

    if (current_time_ns < (access_time->time_ns + resend_delay_ns)) {
        return false;
    }

    access_time->time_ns = current_time_ns;
    return true;
}

static_inline bool has_recently_accessed_file(const struct task_struct *task,
                                              const struct dentry *dentry,
                                              uint8_t operation)
{
    struct file_access_id *file_access_id = gen_file_access_id(task, dentry, operation);
    if (!file_access_id) {
        return false;
    }

    const u64 current_time_ns = bpf_ktime_get_ns();
    if (init_access_time(file_access_id, current_time_ns)) {
        struct file_pid_access_id *file_pid_access_id = gen_file_pid_access_id(file_access_id, task);
        if (!file_pid_access_id) {
            return false;
        }
        if (init_pid_access_time(file_pid_access_id, current_time_ns)) {
            return false;
        }
        return false;
    }

    struct file_access_time *access_time = bpf_map_lookup_elem(&file_access_times, file_access_id);
    if (!access_time) {
        return false;
    }
    if (!resend_delay_elapsed(access_time, current_time_ns)) {
        struct file_pid_access_id *file_pid_access_id = gen_file_pid_access_id(file_access_id, task);
        if (!file_pid_access_id) {
            return false;
        }
        if (init_pid_access_time(file_pid_access_id, current_time_ns)) {
            return false;
        }
        access_time = bpf_map_lookup_elem(&file_access_times_by_pid, file_pid_access_id);
        if (!access_time) {
            return false;
        }
        return !resend_delay_elapsed(access_time, current_time_ns);
    }
    return false;
}

static_inline bool should_filter_accessed_file(const struct task_struct *task,
                                               const struct dentry *dentry,
                                               uint8_t operation)
{
    if (!is_monitored_with_path(dentry)) {
        return true;
    }

    if (exclude_tgid(task)) {
        return true;
    }

    if (has_recently_accessed_file(task, dentry, operation)) {
        return true;
    }

    const struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!is_monitored_network_drive_file(inode) || !is_monitored_network_drive_exes(task)) {
        return true;
    }

    return false;
}
