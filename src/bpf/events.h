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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} events SEC(".maps");

const volatile bool using_ringbuf = true;

static_inline void submit_event(void *ctx, void *data, size_t size)
{
    if (using_ringbuf) {
        bpf_ringbuf_output(&events, data, size, BPF_RB_FORCE_WAKEUP);
    } else {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, size);
    }
}
