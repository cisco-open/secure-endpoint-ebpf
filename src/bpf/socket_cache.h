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

#include "network_util.h"

struct socket_cache_entry {
    struct sockaddr_storage remote_addr;
    size_t bytes_sent;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct socket_cache_entry);
} heap_socket_cache_entry SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct socket_cache_entry);
} socket_cache SEC(".maps");

static_inline struct socket_cache_entry *socket_cache_create_entry(const struct sockaddr *remote,
                                                                   size_t remote_size)
{
    const u32 zero = 0;
    struct socket_cache_entry *socket = bpf_map_lookup_elem(&heap_socket_cache_entry, &zero);
    if (!socket) {
        return NULL;
    }

    if (remote_size > sizeof(socket->remote_addr)) { // Satisfy verifier
        return NULL;
    }

    bpf_probe_read_kernel(&socket->remote_addr, remote_size, remote);
    return socket;
}

static_inline struct socket_cache_entry *socket_cache_find(u64 sock_id)
{
    return bpf_map_lookup_elem(&socket_cache, &sock_id);
}

static_inline struct socket_cache_entry *socket_cache_find_entry(u64 sock_id,
                                                                 const struct socket_cache_entry *entry)
{
    struct socket_cache_entry *found = socket_cache_find(sock_id);
    if (!found) {
        return NULL;
    }

    if (sockaddr_equal((const struct sockaddr *)&entry->remote_addr,
                       (const struct sockaddr *)&found->remote_addr)) {
        return found;
    }

    return NULL;
}

static_inline void socket_cache_update(u64 sock_id, const struct socket_cache_entry *entry)
{
    bpf_map_update_elem(&socket_cache, &sock_id, entry, BPF_ANY);
}
