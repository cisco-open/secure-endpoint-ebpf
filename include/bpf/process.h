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

#include "bpf/common.h"

/** Arbitrary limit for the maximum commandline argument characters.
 *  The actual maximum argument size for execve is ARG_MAX == 131072
 *  which is much larger than the max perf buffer size of 32KB. So, we
 *  set a limit for the amount of commandline argument characters
 *  that we want to attempt to grab from kernel-space that fits
 *  in the perf buffer size constraints.
 */
#define MAX_ARGS_BUF_SIZE 8192
#define MAX_ENV_BUF_SIZE 8192

struct bpf_user {
    uint32_t ruid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
};

struct bpf_process {
    int32_t pid;
    int32_t nspid;
    int32_t pgid;
    int32_t sid;
    struct bpf_user user;
};

struct bpf_args_attributes {
    uint16_t args_offset;
    uint16_t args_size;
};

struct bpf_env_attributes {
    uint16_t env_offset;
    uint16_t env_size;
};

struct bpf_process_fork_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
};

struct bpf_process_exit_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    int32_t exit_code;
};

#define BPF_PROCESS_EXEC_EVENT_BUF_DATA_SIZE ((PATH_MAX * 2) + MAX_ARGS_BUF_SIZE + MAX_ENV_BUF_SIZE)
struct bpf_process_exec_event_buf {
    bpf_file_path_attributes_t parent_exe_path_attributes;
    bpf_file_path_attributes_t exe_path_attributes;
    struct bpf_args_attributes args_attributes;
    struct bpf_env_attributes env_attributes;
    char data[BPF_PROCESS_EXEC_EVENT_BUF_DATA_SIZE];
};

struct bpf_process_exec_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_process_exec_event_buf buf;
};
