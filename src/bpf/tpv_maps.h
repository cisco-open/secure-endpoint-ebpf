/**
 * @file
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

#include "bpf/tpv.h"

/**
 * Declare maps to be linked to userspace equivalent in EbpfBtf namespace.
 * All values are overridden in userspace.
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, file_id_t);
    __uint(max_entries, 1);
} cse_tpv_pids_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, bool);
    __uint(max_entries, 1);
} cse_tpv_files_map_inner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, file_id_t);
    __uint(max_entries, 1);
    __array(values, cse_tpv_files_map_inner);
} cse_tpv_files_map SEC(".maps");

static_inline bool is_pid_trusted(pid_t pid)
{
    return bpf_map_lookup_elem(&cse_tpv_pids_map, &pid);
}

static_inline bool is_file_trusted(file_id_t *file_id)
{
    return bpf_map_lookup_elem(&cse_tpv_files_map, file_id);
}

static_inline file_id_t *get_trusted_file_id(pid_t pid)
{
    return bpf_map_lookup_elem(&cse_tpv_pids_map, &pid);
}

static_inline void add_trusted_pid(pid_t pid, file_id_t *file_id)
{
    void *inner_map = bpf_map_lookup_elem(&cse_tpv_files_map, file_id);
    if (!inner_map) {
        return;
    }

    bool unapplicable = false;
    bpf_map_update_elem(inner_map, &pid, &unapplicable, BPF_NOEXIST);
    bpf_map_update_elem(&cse_tpv_pids_map, &pid, file_id, BPF_NOEXIST);
}

static_inline void remove_trusted_pid(pid_t pid, file_id_t *file_id)
{
    void *inner_map = bpf_map_lookup_elem(&cse_tpv_files_map, file_id);
    if (!inner_map) {
        return;
    }

    bpf_map_delete_elem(inner_map, &pid);
    bpf_map_delete_elem(&cse_tpv_pids_map, &pid);
}
