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

#define SOCKADDR_MAX_SIZE 128
#define PAYLOAD_MAX_SIZE (1 << 14)

struct bpf_network_socket {
    uint64_t sock_id;
    uint16_t protocol;
};

struct bpf_network_tcp_socket {
    uint64_t sock_id;
};

struct bpf_sockaddr_attributes {
    uint32_t offset;
    uint16_t size;
    uint8_t is_loopback : 1;
    uint8_t pad[1];
};

#define BPF_NETWORK_EVENT_BUF_DATA_SIZE ((PATH_MAX * 2) + (SOCKADDR_MAX_SIZE * 2))
struct bpf_network_event_buf {
    bpf_file_path_attributes_t parent_exe_path_attributes;
    bpf_file_path_attributes_t exe_path_attributes;
    struct bpf_sockaddr_attributes local_addr_attributes;
    struct bpf_sockaddr_attributes remote_addr_attributes;
    uint8_t pad[4];
    char data[BPF_NETWORK_EVENT_BUF_DATA_SIZE];
};

struct bpf_network_connect_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_network_socket socket;
    struct bpf_network_event_buf buf;
};

struct bpf_network_accept_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_network_tcp_socket socket;
    struct bpf_network_event_buf buf;
};

struct bpf_network_release_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_network_socket socket;
    struct bpf_network_event_buf buf;
};

struct bpf_network_receive_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_network_socket socket;
    struct bpf_network_event_buf buf;
};

#define BPF_NETWORK_LISTEN_EVENT_BUF_DATA_SIZE ((PATH_MAX * 2) + SOCKADDR_MAX_SIZE)
struct bpf_network_listen_event_buf {
    bpf_file_path_attributes_t parent_exe_path_attributes;
    bpf_file_path_attributes_t exe_path_attributes;
    struct bpf_sockaddr_attributes local_addr_attributes;
    uint8_t pad[6];
    char data[BPF_NETWORK_LISTEN_EVENT_BUF_DATA_SIZE];
};

struct bpf_network_listen_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_network_tcp_socket socket;
    struct bpf_network_listen_event_buf buf;
};

struct bpf_network_payload {
    uint32_t buf_offset;
    uint32_t size;
    uint32_t seq;
};

#define BPF_NETWORK_SEND_EVENT_BUF_DATA_SIZE ((PATH_MAX * 2) + (SOCKADDR_MAX_SIZE * 2) + PAYLOAD_MAX_SIZE)
struct bpf_network_send_event_buf {
    bpf_file_path_attributes_t parent_exe_path_attributes;
    bpf_file_path_attributes_t exe_path_attributes;
    struct bpf_sockaddr_attributes local_addr_attributes;
    struct bpf_sockaddr_attributes remote_addr_attributes;
    struct bpf_network_payload payload;
    char data[BPF_NETWORK_SEND_EVENT_BUF_DATA_SIZE];
};

struct bpf_network_send_event {
    struct bpf_common common;
    struct bpf_process current;
    struct bpf_process parent;
    struct bpf_network_socket socket;
    struct bpf_network_send_event_buf buf;
};
