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
#include "defines.h"

static_inline uint64_t get_time_nanosec_timespec(struct timespec64 *ts)
{
    time64_t sec = BPF_CORE_READ(ts, tv_sec);

    if (sec < 0) {
        return 0;
    }

    long ns = BPF_CORE_READ(ts, tv_nsec);
    ns = ns < 0 ? 0 : ns;

    return (sec * (uint64_t)1e9) + ns;
}

static_inline uint64_t get_ctime_nanosec_from_inode(const struct inode *inode)
{
    struct timespec64 ts;
    if (bpf_core_field_exists(inode->__i_ctime)) { // Version >= 6.6
        ts = BPF_CORE_READ(inode, __i_ctime);
    } else {
        struct inode___older_v66 *old_inode = (void *)inode;
        ts = BPF_CORE_READ(old_inode, i_ctime);
    }
    return get_time_nanosec_timespec(&ts);
}
