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

#pragma once

#include <bpf/bpf_helpers.h>

#include "vmlinux_custom.h"

#include "bpf/network_control.h"

/**
 * Declare allowed_ipv4 map to be linked to userspace AllowedIpv4Map in the Linux
 * NodeIsolation implementation.
 */

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    // Below are overwritten in userspace
    __type(value, struct ports_filter);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 1);
} allowed_ipv4 SEC(".maps");
