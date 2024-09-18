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
#include "bpf/file.h"
#include "file_path_util.h"
#include "process_util.h"

static_inline void populate_event_parent_and_child_exe(
    bpf_file_path_attributes_t *parent_exe_path_attributes,
    bpf_file_path_attributes_t *exe_path_attributes,
    char *data,
    size_t *offset)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (*offset > sizeof(data) - PATH_MAX) { // Satisfy verifier
        return;
    }

    exe_path_attributes->path_offset = *offset;
    file_path_reference_t file_path_ref = {
        .attributes = exe_path_attributes,
        .data = &data[*offset],
        .data_size = PATH_MAX,
    };
    const size_t exe_length = populate_file_path_from_task(&file_path_ref, task);
    *offset += (exe_length > 0) ? exe_length : 1 /* Null terminator */;

    parent_exe_path_attributes->path_offset = *offset;
    file_path_reference_t parent_exe_path_ref = {
        .attributes = parent_exe_path_attributes,
        .data = &data[*offset],
        .data_size = PATH_MAX,
    };

    struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
    const size_t parent_exe_length = populate_file_path_from_task(&parent_exe_path_ref, parent_task);
    *offset += (parent_exe_length > 0) ? parent_exe_length : 1 /* Null terminator */;
}

static_inline size_t populate_file_create_event_buffer(struct bpf_file_create_event_buf *buffer,
                                                       const struct task_struct *task,
                                                       const struct dentry *dentry)
{
    size_t offset = 0;
    populate_event_parent_and_child_exe(&buffer->parent_exe_path_attributes,
                                        &buffer->exe_path_attributes,
                                        buffer->data,
                                        &offset);

    if (offset > sizeof(buffer->data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    buffer->file_path_attributes.path_offset = offset;
    file_path_reference_t file_path_ref = {
        .attributes = &buffer->file_path_attributes,
        .data = &buffer->data[offset],
        .data_size = PATH_MAX,
    };

    const size_t length = get_path_str_from_dentry(&file_path_ref, dentry);
    offset += (length > 0) ? length : 1 /* Null terminator */;

    return (offset > sizeof(buffer->data)) ? 0 : offset; // Satisfy verifier
}

static_inline size_t populate_file_event_buffer_from_path(struct bpf_file_event_buf *buffer,
                                                          const struct task_struct *task,
                                                          const struct path *path)
{
    size_t offset = 0;
    populate_event_parent_and_child_exe(&buffer->parent_exe_path_attributes,
                                        &buffer->exe_path_attributes,
                                        buffer->data,
                                        &offset);

    if (offset > sizeof(buffer->data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    buffer->file_path_attributes.path_offset = offset;
    file_path_reference_t file_path_ref = {
        .attributes = &buffer->file_path_attributes,
        .data = &buffer->data[offset],
        .data_size = PATH_MAX,
    };

    const size_t length = populate_file_path_from_path(&file_path_ref, path);
    offset += (length > 0) ? length : 1 /* Null terminator */;

    const struct inode *file_inode = BPF_CORE_READ(path, dentry, d_inode);
    buffer->mode = BPF_CORE_READ(file_inode, i_mode);

    return (offset > sizeof(buffer->data)) ? 0 : offset; // Satisfy verifier
}

static_inline size_t populate_file_event_buffer_from_file(struct bpf_file_event_buf *buffer,
                                                          const struct task_struct *task,
                                                          const struct file *file)
{
    const struct path *path = __builtin_preserve_access_index(&file->f_path);
    return populate_file_event_buffer_from_path(buffer, task, path);
}

static_inline size_t populate_file_event_buffer_from_dentry(struct bpf_file_event_buf *buffer,
                                                            const struct task_struct *task,
                                                            const struct dentry *dentry)
{
    size_t offset = 0;
    populate_event_parent_and_child_exe(&buffer->parent_exe_path_attributes,
                                        &buffer->exe_path_attributes,
                                        buffer->data,
                                        &offset);

    if (offset > sizeof(buffer->data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    buffer->file_path_attributes.path_offset = offset;
    file_path_reference_t file_path_ref = {
        .attributes = &buffer->file_path_attributes,
        .data = &buffer->data[offset],
        .data_size = PATH_MAX,
    };

    const size_t length = populate_file_path_from_dentry(&file_path_ref, dentry);
    offset += (length > 0) ? length : 1 /* Null terminator */;

    const struct inode *file_inode = BPF_CORE_READ(dentry, d_inode);
    buffer->mode = BPF_CORE_READ(file_inode, i_mode);

    return (offset > sizeof(buffer->data)) ? 0 : offset; // Satisfy verifier
}

static_inline size_t populate_file_rename_event_buffer(struct bpf_file_rename_event_buf *buffer,
                                                       const struct task_struct *task,
                                                       const struct dentry *old_dentry,
                                                       const struct dentry *new_dentry)
{
    size_t offset = 0;
    populate_event_parent_and_child_exe(&buffer->parent_exe_path_attributes,
                                        &buffer->exe_path_attributes,
                                        buffer->data,
                                        &offset);

    if (offset > sizeof(buffer->data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    buffer->old_file_path_attributes.path_offset = offset;
    file_path_reference_t old_file_path_ref = {
        .attributes = &buffer->old_file_path_attributes,
        .data = &buffer->data[offset],
        .data_size = PATH_MAX,
    };

    const size_t old_length = populate_file_path_from_dentry(&old_file_path_ref, old_dentry);
    offset += (old_length > 0) ? old_length : 1 /* Null terminator */;
    if (offset > sizeof(buffer->data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    buffer->file_path_attributes.path_offset = offset;
    file_path_reference_t file_path_ref = {
        .attributes = &buffer->file_path_attributes,
        .data = &buffer->data[offset],
        .data_size = PATH_MAX,
    };

    const size_t new_length = update_file_path_from_dentry(&file_path_ref, new_dentry);
    offset += (new_length > 0) ? new_length : 1 /* Null terminator */;
    if (offset > sizeof(buffer->data) - PATH_MAX) { // Satisfy verifier
        return 0;
    }

    const struct inode *file_inode = BPF_CORE_READ(old_dentry, d_inode);
    buffer->mode = BPF_CORE_READ(file_inode, i_mode);

    return (offset > sizeof(buffer->data)) ? 0 : offset; // Satisfy verifier
}
