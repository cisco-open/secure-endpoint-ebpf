/**
 * @file
 *
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

#define IPV4_MAX_SIZE 32
#define IPV6_MAX_SIZE 128

// Protocols Ports
#define DNS_PORT 53
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547

#define MAX_PORT_FILTER 5

struct ports_filter {
    uint16_t count;
    uint16_t ports[MAX_PORT_FILTER];
};

struct ipv4_lpm_key {
    uint32_t prefixlen;  // Order matters, prefix length must come first
    struct in_addr addr; // in_addr is in network order
};

struct ipv6_lpm_key {
    uint32_t prefixlen;
    struct in6_addr addr;
};
