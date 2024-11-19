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

#include <linux/limits.h>

#define MAX_PATH_COMPONENTS 256

enum bpf_operation {
    bpf_operation_process_fork,
    bpf_operation_process_exit,
    bpf_operation_process_exec,

    bpf_operation_file_create,
    bpf_operation_file_rename,
    bpf_operation_file_write,
    bpf_operation_file_read,
    bpf_operation_file_close_write,
    bpf_operation_file_delete,

    bpf_operation_network_accept,
    bpf_operation_network_connect,
    bpf_operation_network_listen,
    bpf_operation_network_receive,
    bpf_operation_network_release,
    bpf_operation_network_send,
};

struct bpf_common {
    uint8_t operation;
    uint8_t pad[3];
    uint32_t size;
    uint64_t ktime;
};

struct bpf_mount {
    uint32_t dev_major;
    uint32_t dev_minor;
};

typedef struct bpf_file_path_flags {
    uint16_t path_includes_mnt : 1;
    uint16_t path_truncated : 1;
    uint16_t path_malformed : 1;
    uint16_t path_from_specialfs : 1;
    uint16_t path_scannable : 1;
    uint16_t : 11; // fill to 16 bits
} bpf_file_path_flags_t;

typedef struct bpf_file_path_attributes {
    struct bpf_mount mount;
    bpf_file_path_flags_t flags;
    uint16_t path_offset;
    uint8_t pad[4];
} bpf_file_path_attributes_t;
