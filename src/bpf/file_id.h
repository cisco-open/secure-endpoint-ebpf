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

#include "bpf/file.h"
#include "file_util.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, file_id_t);
} file_id_map SEC(".maps");

static_inline void get_file_id_in_place(file_id_t *file_id, const struct inode *inode)
{
    if (inode && file_id) {
        dev_t s_dev = BPF_CORE_READ(inode, i_sb, s_dev);
        file_id->device.dev_major = MAJOR(s_dev);
        file_id->device.dev_minor = MINOR(s_dev);
        file_id->inode = BPF_CORE_READ(inode, i_ino);
        file_id->ctime = get_ctime_nanosec_from_inode(inode);
    }
}

static_inline file_id_t *get_file_id(const struct inode *inode)
{
    u32 zero = 0;
    file_id_t *file_id = bpf_map_lookup_elem(&file_id_map, &zero);
    get_file_id_in_place(file_id, inode);
    return file_id;
}
