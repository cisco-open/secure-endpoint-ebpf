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
 * Declare excluded_pids map to be linked to userspace ProcessExclusionMap in the BTF AMF implementation.
 * Since bpf_map__reuse_fd is used, this map is actually empty and ends up linking to a userspace map.
 * https://code.engine.sourcefire.com/Cloud/secure-endpoint-ebpf/pull/39#discussion_r271251
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, bool);
} excluded_pids SEC(".maps");
