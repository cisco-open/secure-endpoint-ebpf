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
#include "tpv_maps.h"

#define CONCURRENT_ALLOWED_IP_ADDRESSES 100
typedef bool unapplicable_t;

enum direction { EGRESS, INGRESS };

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in6_addr);
    __type(value, unapplicable_t);
    __uint(max_entries, CONCURRENT_ALLOWED_IP_ADDRESSES);
} allowed_ingress_only_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct in_addr);
    __type(value, unapplicable_t);
    __uint(max_entries, CONCURRENT_ALLOWED_IP_ADDRESSES);
} allowed_ingress_only_ipv4 SEC(".maps");

static_inline bool is_process_allowed()
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int32_t pid = BPF_CORE_READ(task, tgid);
    int32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    return is_pid_trusted(ppid) || is_pid_trusted(pid);
}

static_inline bool lookup_ingress_only_ipv4_address_allowed(struct iphdr *iph, enum direction direction)
{
    if (direction != INGRESS) {
        // Only allow ingress packets to lookup in ingress only map.
        return false;
    }

    struct in_addr key = { .s_addr = iph->saddr };
    return bpf_map_lookup_elem(&allowed_ingress_only_ipv4, &key);
}

static_inline bool lookup_ingress_only_ipv6_address_allowed(struct ipv6hdr *iph, enum direction direction)
{
    if (direction != INGRESS) {
        // Only allow ingress packets to lookup in ingress only map.
        return false;
    }

    struct in6_addr key;
    bpf_core_read(&key, sizeof(key), &iph->saddr);
    return bpf_map_lookup_elem(&allowed_ingress_only_ipv6, &key);
}

static_inline void insert_ingress_only_ipv4_address_allowed(struct iphdr *iph, enum direction direction)
{
    if (direction != EGRESS) {
        // Only allow EGRESS packets to add to ingress only map.
        return;
    }

    unapplicable_t value = false;
    struct in_addr key = { .s_addr = iph->daddr };
    bpf_map_update_elem(&allowed_ingress_only_ipv4, &key, &value, BPF_NOEXIST);
}

static_inline void insert_ingress_only_ipv6_address_allowed(struct ipv6hdr *iph, enum direction direction)
{
    if (direction != EGRESS) {
        // Only allow EGRESS packets to add to ingress only map.
        return;
    }

    unapplicable_t value = false;
    struct in6_addr key;
    bpf_core_read(&key, sizeof(key), &iph->daddr);
    bpf_map_update_elem(&allowed_ingress_only_ipv6, &key, &value, BPF_NOEXIST);
}

static_inline void add_to_ingress_only_allow_list(struct __sk_buff *skb, enum direction direction)
{
    switch (skb->protocol) {
        case bpf_htons(ETH_P_IP): {
            struct iphdr iph;
            if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0) {
                return;
            }
            insert_ingress_only_ipv4_address_allowed(&iph, direction);
            break;
        }
        case bpf_htons(ETH_P_IPV6): {
            struct ipv6hdr iph6;
            if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph6, sizeof(iph6)) < 0) {
                return;
            }
            insert_ingress_only_ipv6_address_allowed(&iph6, direction);
            break;
        }
        default:
            return;
    }
}