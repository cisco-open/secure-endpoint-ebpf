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

#include "vmlinux_custom.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>
#include "bpf/common.h"
#include "defines.h"
#include "file_access_util.h"
#include "file_id.h"
#include "host_namespace_map.h"

#define MAX_PERCPU_FILE_PATH_ARRAY_SIZE (PATH_MAX << 1)
#define HALF_PERCPU_FILE_PATH_ARRAY_SIZE (MAX_PERCPU_FILE_PATH_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_FILE_PATH_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_FILE_PATH_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_FILE_PATH_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_FILE_PATH_ARRAY_SIZE - 1))

#define LIMIT_PATH_SIZE(x) ((x) & (PATH_MAX - 1))

typedef struct unrolled_path_buffer {
    uint8_t data[MAX_PERCPU_FILE_PATH_ARRAY_SIZE];
} unrolled_path_buffer_t;

typedef struct file_path_reference {
    bpf_file_path_attributes_t *attributes;
    char *data;
    uint16_t data_size;
} file_path_reference_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, unrolled_path_buffer_t);
} unrolled_path_map SEC(".maps");

struct heap_file_path {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, file_path_buffer_t);
} heap_file_path SEC(".maps");

/**
 * Declare file_path_cache_map to be linked to userspace FilePathCacheMap in the BTF AMF implementation.
 * It stores the file path keyed on the file id.
 */
struct file_path_cache_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);
    __type(key, file_id_t);
    __type(value, file_path_buffer_t);
} file_path_cache_map SEC(".maps");

static_inline void init_bpf_file_path_attributes(bpf_file_path_attributes_t *attributes)
{
    __builtin_memset(&attributes->flags, 0, sizeof(attributes->flags));
}

static_inline void populate_path_from_specialfs(bpf_file_path_flags_t *flags, const struct inode *inode)
{
    const long unsigned int magic = BPF_CORE_READ(inode, i_sb, s_magic);
    flags->path_from_specialfs = is_from_special_filesystem_type(magic);
}

static_inline void populate_path_from_remotefs(bpf_file_path_flags_t *flags, const struct inode *inode)
{
    const long unsigned int magic = BPF_CORE_READ(inode, i_sb, s_magic);
    flags->path_from_remotefs = is_from_remote_filesystem(magic);
}

static_inline void populate_file_mount(struct bpf_mount *mount, const struct inode *inode)
{
    dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
    mount->dev_major = MAJOR(dev);
    mount->dev_minor = MINOR(dev);
}

static_inline unrolled_path_buffer_t *get_unrolled_path_buffer()
{
    u32 zero = 0;
    return (unrolled_path_buffer_t *)bpf_map_lookup_elem(&unrolled_path_map, &zero);
}

static_inline bool is_root_dentry(const struct dentry *dentry)
{
    const struct dentry *d_parent = BPF_CORE_READ(dentry, d_parent);
    return (dentry == d_parent);
}

static_inline size_t prepend_slash(unrolled_path_buffer_t *buffer, size_t offset)
{
    offset -= 1;
    offset = LIMIT_HALF_PERCPU_FILE_PATH_ARRAY_SIZE(offset); // Satisfy verifier.
    buffer->data[offset] = '/';
    return offset;
}

static_inline size_t shift_offset(size_t offset, size_t length)
{
    offset -= length;
    offset = LIMIT_HALF_PERCPU_FILE_PATH_ARRAY_SIZE(offset); // Satisfy verifier.
    return offset;
}

static_inline size_t prepend_dentry(unrolled_path_buffer_t *buffer,
                                    size_t offset,
                                    const struct dentry *dentry)
{
    const size_t length = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len)) + 1; // Add 1 for slash
    if (length >= offset) {
        return 0;
    }

    volatile size_t new_offset = shift_offset(offset, length); // Satisfy verifier.
    const char *name = (const char *)BPF_CORE_READ(dentry, d_name.name);
    // Satisfy verifier.
    if (bpf_probe_read_kernel_str(&(buffer->data[LIMIT_HALF_PERCPU_FILE_PATH_ARRAY_SIZE(new_offset)]),
                                  length,
                                  name) <= 0) {
        return 0;
    }
    prepend_slash(buffer, offset);
    return LIMIT_HALF_PERCPU_FILE_PATH_ARRAY_SIZE(new_offset); // Satisfy verifier.
}

static_inline size_t get_path_str_from_path(file_path_reference_t *file_path_ref, const struct path *path)
{
    init_bpf_file_path_attributes(file_path_ref->attributes);

    // mnt path will be resolved from struct path.
    file_path_ref->attributes->flags.path_includes_mnt = true;

    unrolled_path_buffer_t *buffer = get_unrolled_path_buffer();
    if (!buffer) {
        return 0;
    }

    const struct dentry *dentry = BPF_CORE_READ(path, dentry);
    const struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    const struct mount *mnt = container_of(vfsmnt, struct mount, mnt);
    const struct mount *mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

    size_t offset = HALF_PERCPU_FILE_PATH_ARRAY_SIZE;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {

        const struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
        const struct dentry *dentry_parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == mnt_root || is_root_dentry(dentry)) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root, escaped?
                break;
            }

            // Global root?
            if (mnt != mnt_parent) {
                dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                mnt = BPF_CORE_READ(mnt, mnt_parent);
                mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
                vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
                continue;
            }

            // Global root! Path has been fully parsed.
            break;
        }

        offset = prepend_dentry(buffer, offset, dentry);
        if (offset == 0) {
            // No more space in the buffer
            break;
        }

        dentry = dentry_parent;
    }

    if (mnt != mnt_parent) {
        file_path_ref->attributes->flags.path_truncated = true;
        file_path_ref->attributes->flags.path_malformed = true;
    }

    if (offset != 0) {
        offset = prepend_slash(buffer, offset);
    }
    // Null terminate the path string.
    buffer->data[HALF_PERCPU_FILE_PATH_ARRAY_SIZE - 1] = '\0';

    const long length =
        bpf_probe_read_kernel_str(file_path_ref->data, file_path_ref->data_size, &buffer->data[offset]);

    const struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
    populate_path_from_specialfs(&file_path_ref->attributes->flags, inode);
    populate_path_from_remotefs(&file_path_ref->attributes->flags, inode);

    return (length < 0) ? 0 : length;
}

static_inline size_t get_path_str_from_dentry(file_path_reference_t *file_path_ref,
                                              const struct dentry *dentry)
{
    init_bpf_file_path_attributes(file_path_ref->attributes);

    unrolled_path_buffer_t *buffer = get_unrolled_path_buffer();
    if (!buffer) {
        return 0;
    }

    size_t offset = HALF_PERCPU_FILE_PATH_ARRAY_SIZE;
#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        const struct dentry *dentry_parent = BPF_CORE_READ(dentry, d_parent);
        if (is_root_dentry(dentry)) {
            break;
        }

        offset = prepend_dentry(buffer, offset, dentry);
        if (offset == 0) {
            // No more space in the buffer
            break;
        }
        dentry = dentry_parent;
    }

    if (!is_root_dentry(dentry)) {
        file_path_ref->attributes->flags.path_truncated = true;
        file_path_ref->attributes->flags.path_malformed = true;
    }

    if (offset != 0) {
        offset = prepend_slash(buffer, offset);
    }
    // Null terminate the path string.
    buffer->data[HALF_PERCPU_FILE_PATH_ARRAY_SIZE - 1] = '\0';

    const long length =
        bpf_probe_read_kernel_str(file_path_ref->data, file_path_ref->data_size, &buffer->data[offset]);

    const struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    populate_path_from_specialfs(&file_path_ref->attributes->flags, inode);
    populate_path_from_remotefs(&file_path_ref->attributes->flags, inode);
    populate_file_mount(&file_path_ref->attributes->mount, inode);

    return (length < 0) ? 0 : length;
}

static_inline size_t get_file_path_from_cache(file_path_reference_t *file_path_ref,
                                              const file_id_t *file_id)
{
    file_path_buffer_t *buffer = bpf_map_lookup_elem(&file_path_cache_map, file_id);
    if (!buffer) {
        return 0;
    }
    /* Avoid copying out offset from old event that created the entry */
    file_path_ref->attributes->flags = buffer->attributes.flags;
    file_path_ref->attributes->mount = buffer->attributes.mount;
    const long length =
        bpf_probe_read_kernel_str(file_path_ref->data, file_path_ref->data_size, &buffer->data);
    return (length < 0) ? 0 : length;
}

static_inline void update_file_path_cache(const file_id_t *file_id, file_path_reference_t *file_path_ref)
{
    u32 zero = 0;
    file_path_buffer_t *buffer = bpf_map_lookup_elem(&heap_file_path, &zero);
    if (!buffer) {
        return;
    }
    buffer->attributes = *file_path_ref->attributes;
    bpf_probe_read_kernel_str(&buffer->data, file_path_ref->data_size, file_path_ref->data);
    bpf_map_update_elem(&file_path_cache_map, file_id, buffer, BPF_ANY);
}

static_inline size_t populate_file_path_from_dentry(file_path_reference_t *file_path_ref,
                                                    const struct dentry *dentry)
{
    size_t file_path_len;
    const struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    const file_id_t *file_id = get_file_id(inode);
    if (!file_id) {
        return 0;
    }

    file_path_len = get_file_path_from_cache(file_path_ref, file_id);
    if (file_path_len != 0) {
        return file_path_len;
    }

    file_path_len = get_path_str_from_dentry(file_path_ref, dentry);
    if (file_path_len != 0) {
        update_file_path_cache(file_id, file_path_ref);
    }
    return file_path_len;
}

static_inline size_t update_file_path_from_dentry(file_path_reference_t *file_path_ref,
                                                  const struct dentry *dentry)
{
    size_t file_path_len;
    const struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    const file_id_t *file_id = get_file_id(inode);
    if (!file_id) {
        return 0;
    }

    file_path_len = get_path_str_from_dentry(file_path_ref, dentry);
    if (file_path_len != 0) {
        update_file_path_cache(file_id, file_path_ref);
    }
    return file_path_len;
}

static_inline size_t populate_file_path_from_path(file_path_reference_t *file_path_ref,
                                                  const struct path *path)
{
    if (!is_host_namespace(path)) {
        const struct dentry *dentry = BPF_CORE_READ(path, dentry);
        return populate_file_path_from_dentry(file_path_ref, dentry);
    }

    size_t file_path_len;
    const struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
    const file_id_t *file_id = get_file_id(inode);
    if (!file_id) {
        return 0;
    }

    file_path_len = get_file_path_from_cache(file_path_ref, file_id);
    if (file_path_len != 0) {
        return file_path_len;
    }

    file_path_len = get_path_str_from_path(file_path_ref, path);
    if (file_path_len != 0) {
        update_file_path_cache(file_id, file_path_ref);
    }
    return file_path_len;
}

static_inline size_t populate_file_path_from_file(file_path_reference_t *file_path_ref,
                                                  const struct file *file)
{
    const struct path *path = __builtin_preserve_access_index(&file->f_path);
    return populate_file_path_from_path(file_path_ref, path);
}

static_inline size_t populate_file_path_from_task(file_path_reference_t *file_path_ref,
                                                  const struct task_struct *task)
{
    const struct file *file = BPF_CORE_READ(task, mm, exe_file);
    return populate_file_path_from_file(file_path_ref, file);
}
