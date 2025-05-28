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

#include <bpf/bpf_endian.h>

#include "vmlinux_custom.h"

#include "allowed_ipv4_map.h"
#include "allowed_ipv6_map.h"
#include "allowed_process_util.h"
#include "bpf/network_control.h"

char LICENSE[] SEC("license") = "GPL";

volatile bool dns_allowed = false;
volatile bool dhcp_allowed = false;

static_inline void *lookup_ipv4_address_allowed(struct iphdr *iph, enum direction direction)
{
    struct ipv4_lpm_key key;
    key.prefixlen = IPV4_MAX_SIZE;
    switch (direction) {
        case EGRESS:
            key.addr.s_addr = iph->daddr;
            break;
        case INGRESS:
            key.addr.s_addr = iph->saddr;
            break;
    }

    return bpf_map_lookup_elem(&allowed_ipv4, &key);
}

static_inline void *lookup_ipv6_address_allowed(struct ipv6hdr *iph, enum direction direction)
{
    struct ipv6_lpm_key key;
    key.prefixlen = IPV6_MAX_SIZE;
    switch (direction) {
        case EGRESS:
            bpf_core_read(&key.addr, sizeof(key.addr), &iph->daddr);
            break;
        case INGRESS:
            bpf_core_read(&key.addr, sizeof(key.addr), &iph->saddr);
            break;
    }

    return bpf_map_lookup_elem(&allowed_ipv6, &key);
}

static_inline bool is_ip_address_unrestricted_by_port(struct ports_filter *ports_filter)
{
    return (ports_filter && ports_filter->count == 0);
}

static_inline bool check_dns_port(struct udphdr *uiph,
                                  struct tcphdr *tcph,
                                  enum direction direction,
                                  struct ports_filter *ports_filter)
{
    bool correct_direction_port = false;
    if (uiph != NULL) {
        switch (direction) {
            case INGRESS:
                if (uiph->source == bpf_htons(DNS_PORT)) {
                    correct_direction_port = true;
                }
                break;
            case EGRESS:
                if (uiph->dest == bpf_htons(DNS_PORT)) {
                    correct_direction_port = true;
                }
                break;
        }
    } else if (tcph != NULL) {
        switch (direction) {
            case INGRESS:
                if (tcph->source == bpf_htons(DNS_PORT)) {
                    correct_direction_port = true;
                }
                break;
            case EGRESS:
                if (tcph->dest == bpf_htons(DNS_PORT)) {
                    correct_direction_port = true;
                }
                break;
        }
    }

    if (correct_direction_port && ports_filter != NULL) {
        for (int i = 0; i < ports_filter->count && i < MAX_PORT_FILTER; i++) {
            if (ports_filter->ports[i] == DNS_PORT) {
                return true;
            }
        }
    }

    return false;
}

static_inline bool check_dhcp_port(struct __sk_buff *skb, struct udphdr *uiph, enum direction direction)
{
    switch (direction) { // Only allow client side to function
        case INGRESS:
            if ((skb->protocol == bpf_htons(ETH_P_IP) && uiph->source == bpf_htons(DHCP_CLIENT_PORT)) ||
                (skb->protocol == bpf_htons(ETH_P_IPV6) && uiph->source == bpf_htons(DHCPV6_CLIENT_PORT))) {
                return true;
            }
            break;
        case EGRESS:
            if ((skb->protocol == bpf_htons(ETH_P_IP) && uiph->dest == bpf_htons(DHCP_SERVER_PORT)) ||
                (skb->protocol == bpf_htons(ETH_P_IPV6) && uiph->dest == bpf_htons(DHCPV6_SERVER_PORT))) {
                return true;
            }
            break;
    }

    return false;
}

static_inline bool is_udp_application_allowed(struct __sk_buff *skb,
                                              struct udphdr *uiph,
                                              enum direction direction,
                                              struct ports_filter *ports_filter)
{
    if (dns_allowed) {
        return check_dns_port(uiph, NULL, direction, ports_filter);
    } else if (dhcp_allowed) {
        return check_dhcp_port(skb, uiph, direction);
    }

    return false;
}

static_inline bool is_tcp_application_allowed(struct tcphdr *tcph,
                                              enum direction direction,
                                              struct ports_filter *ports_filter)
{
    if (dns_allowed) {
        return check_dns_port(NULL, tcph, direction, ports_filter);
    }

    return false;
}

static_inline bool are_ports_allowed(struct __sk_buff *skb,
                                     enum direction direction,
                                     size_t transport_offset,
                                     uint16_t transport_protocol,
                                     struct ports_filter *ports_filter)
{
    if (!dhcp_allowed && !dns_allowed) {
        return false;
    }

    if (transport_protocol == IPPROTO_UDP) {
        struct udphdr uiph;
        if (bpf_skb_load_bytes(skb, transport_offset, &uiph, sizeof(uiph)) < 0) {
            return false;
        }
        return is_udp_application_allowed(skb, &uiph, direction, ports_filter);
    } else if (dns_allowed && transport_protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        if (bpf_skb_load_bytes(skb, transport_offset, &tcph, sizeof(tcph)) < 0) {
            return false;
        }
        return is_tcp_application_allowed(&tcph, direction, ports_filter);
    }
    return false;
}

static_inline bool is_packet_allowed(struct __sk_buff *skb, enum direction direction)
{
    size_t transport_offset = 0;
    uint16_t transport_protocol = 0;
    struct ports_filter *ports_filter = NULL;

    switch (skb->protocol) {
        case bpf_htons(ETH_P_IP): {
            struct iphdr iph;
            if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0) {
                return false;
            }

            if (lookup_ingress_only_ipv4_address_allowed(&iph, direction)) {
                return true;
            }
            ports_filter = lookup_ipv4_address_allowed(&iph, direction);
            if (is_ip_address_unrestricted_by_port(ports_filter)) {
                return true;
            }
            transport_offset = ETH_HLEN + sizeof(iph);
            transport_protocol = iph.protocol;
            break;
        }
        case bpf_htons(ETH_P_IPV6):
        {
            struct ipv6hdr iph6;
            if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph6, sizeof(iph6)) < 0) {
                return false;
            }
            if (lookup_ingress_only_ipv6_address_allowed(&iph6, direction)) {
                return true;
            }
            ports_filter = lookup_ipv6_address_allowed(&iph6, direction);
            if (is_ip_address_unrestricted_by_port(ports_filter)) {
                return true;
            }
            transport_offset = ETH_HLEN + sizeof(iph6);
            transport_protocol = iph6.nexthdr;
            break;
        }
        case bpf_htons(ETH_P_ARP):
            // ARP cache is globally accessible, it can be updated and used by any process
            // Therefore we allow all ARP packets. Security impact of this should be minimal.
            return true;
        default:
            return false;
    }

    if (are_ports_allowed(skb, direction, transport_offset, transport_protocol, ports_filter)) {
        return true;
    }

    return false;
}

static_inline int endpoint_isolation_evaluation(struct __sk_buff *skb, enum direction direction)
{
    if (is_process_allowed()) {
        add_to_ingress_only_allow_list(skb, direction);
        return TC_ACT_OK;
    } else if (is_packet_allowed(skb, direction)) {
        return TC_ACT_OK;
    }
    return TC_ACT_SHOT;
}

SEC("tc")
int cls_egress(struct __sk_buff *skb)
{
    return endpoint_isolation_evaluation(skb, EGRESS);
}

SEC("tc")
int cls_ingress(struct __sk_buff *skb)
{
    return endpoint_isolation_evaluation(skb, INGRESS);
}
