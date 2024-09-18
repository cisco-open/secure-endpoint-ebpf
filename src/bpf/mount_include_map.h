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

#include <bpf/bpf_helpers.h>

/**
 * Declare remote_mounts map to be linked to userspace MonitorMountsMap in the BTF AMF implementation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, bool);
} remote_mounts SEC(".maps");

volatile bool network_drive_scanning = false;

static_inline bool is_from_remote_filesystem(long unsigned int magic)
{
    switch (magic) {
        case NFS_SUPER_MAGIC:
        case SMB_SUPER_MAGIC:
        case CIFS_SUPER_MAGIC:
            return true;
    }
    return false;
}

static_inline bool is_monitored_network_drive_file(const struct inode *inode)
{
    const long unsigned int magic = BPF_CORE_READ(inode, i_sb, s_magic);
    if (!is_from_remote_filesystem(magic)) {
        return true;
    }

    const u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    const bool *scannable_remote_mount = bpf_map_lookup_elem(&remote_mounts, &dev);
    if (scannable_remote_mount) {
        // false == remote nfs hard mount, true == scannable remote mount
        if (*scannable_remote_mount == false || !network_drive_scanning) {
            return false;
        }
    }
    return true;
}

static_inline bool is_monitored_network_drive_exe(const struct inode *inode)
{
    const long unsigned int magic = BPF_CORE_READ(inode, i_sb, s_magic);
    if (!is_from_remote_filesystem(magic)) {
        return true;
    }

    const u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    const bool *scannable_remote_mount = bpf_map_lookup_elem(&remote_mounts, &dev);

    // false == remote nfs hard mount, true == scannable remote mount
    return !(scannable_remote_mount && *scannable_remote_mount == false);
}

static_inline bool is_monitored_network_drive_exes(const struct task_struct *task)
{
    const struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_inode);
    const struct inode *parent_inode =
        BPF_CORE_READ(task, real_parent, mm, exe_file, f_path.dentry, d_inode);

    return is_monitored_network_drive_exe(inode) && is_monitored_network_drive_exe(parent_inode);
}