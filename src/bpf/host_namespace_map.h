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
 * Declare host_namespace map to be linked to userspace HostNamespaceMap in the BTF AMF implementation.
 * In this case, host namespace is defined to be the namespace that the ampdaemon is within.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, u32);
} host_namespace SEC(".maps");

static_inline bool is_host_namespace(const struct path *path)
{
    const struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    const struct mount *mnt = container_of(vfsmnt, struct mount, mnt);

    const unsigned int mount_ns_inum = BPF_CORE_READ(mnt, mnt_ns, ns.inum);

    const int init_pid = 1;
    const uint32_t *host_ns_inum = bpf_map_lookup_elem(&host_namespace, &init_pid);

    return (host_ns_inum && *host_ns_inum == mount_ns_inum);
}
