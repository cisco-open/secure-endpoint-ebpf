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
#include "bpf/process.h"

#define BPF_FILE_EVENT_BUF_DATA_SIZE (PATH_MAX * 3)
struct bpf_file_event_buf {
    bpf_file_path_attributes_t parent_exe_path_attributes;
    bpf_file_path_attributes_t exe_path_attributes;
    bpf_file_path_attributes_t file_path_attributes;
    uint32_t mode;
    uint8_t pad[4];
    char data[BPF_FILE_EVENT_BUF_DATA_SIZE];
};

struct bpf_file_create_event_buf {
    bpf_file_path_attributes_t parent_exe_path_attributes;
    bpf_file_path_attributes_t exe_path_attributes;
    bpf_file_path_attributes_t file_path_attributes;
    char data[BPF_FILE_EVENT_BUF_DATA_SIZE];
};

#define BPF_FILE_RENAME_EVENT_BUF_DATA_SIZE (PATH_MAX * 4)
struct bpf_file_rename_event_buf {
    bpf_file_path_attributes_t parent_exe_path_attributes;
    bpf_file_path_attributes_t exe_path_attributes;
    bpf_file_path_attributes_t file_path_attributes;
    bpf_file_path_attributes_t old_file_path_attributes;
    uint32_t mode;
    uint8_t pad[4];
    char data[BPF_FILE_RENAME_EVENT_BUF_DATA_SIZE];
};

struct bpf_file_create_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_file_create_event_buf buf;
};

struct bpf_file_rename_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_file_rename_event_buf buf;
};

struct bpf_file_write_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_file_event_buf buf;
};

struct bpf_file_read_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_file_event_buf buf;
};

struct bpf_file_close_write_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_file_event_buf buf;
};

struct bpf_file_delete_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_file_event_buf buf;
};

struct file_access_id {
    uint64_t file_inode;
    uint64_t device;
    uint32_t hash;
    uint8_t operation;
};

struct file_pid_access_id {
    pid_t tgid;
    uint64_t exe_inode;
    struct file_access_id id;
};

struct file_access_time {
    uint64_t time_ns;
};

typedef struct file_id {
    struct bpf_mount device;
    uint64_t ctime;
    uint64_t inode;
} file_id_t;

typedef struct file_path_buffer {
    bpf_file_path_attributes_t attributes;
    char data[PATH_MAX];
} file_path_buffer_t;