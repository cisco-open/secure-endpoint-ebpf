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

#include "bpf/common.h"
#include "bpf/file.h"

// Represents the map_fd on input but map_id on output.
typedef int inner_map_fd_id_t;

#define TPV_MAX_TRUSTED_PROCESS_COUNT 128
#define TPV_PIDS_PER_TRUSTED_PROCESS_COUNT 516

