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

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


#include "defines.h"

#define CIFS_SUPER_MAGIC 0xFF534D42

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/* generic data direction definitions */
#define READ 0
#define WRITE 1

/* file is open for reading */
#define FMODE_READ ((fmode_t)0x1)
/* file is open for writing */
#define FMODE_WRITE ((fmode_t)0x2)
/* file is seekable */
#define FMODE_LSEEK ((fmode_t)0x4)
/* file can be accessed using pread */
#define FMODE_PREAD ((fmode_t)0x8)
/* file can be accessed using pwrite */
#define FMODE_PWRITE ((fmode_t)0x10)
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC ((fmode_t)0x20)
/* 32bit hashes as llseek() offset (for directories) */
#define FMODE_32BITHASH ((fmode_t)0x200)
/* 64bit hashes as llseek() offset (for directories) */
#define FMODE_64BITHASH ((fmode_t)0x400)
/* File is stream-like */
#define FMODE_STREAM ((fmode_t)0x200000)

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

// (struct kernfs_node *)->id was union kernfs_node_id before 5.5
union kernfs_node_id {
    struct {
        u32 ino;
        u32 generation;
    };
    u64 id;
};

struct kernfs_node___older_v55 {
    const char *name;
    union kernfs_node_id id;
};

struct kernfs_node___rh8 {
    const char *name;
    union {
        u64 id;
        struct {
            union kernfs_node_id id;
        } rh_kabi_hidden_172;
        union {
        };
    };
};

// commit bf9765145b85 ("sock: Make sk_protocol a 16-bit value")

// clang-format off
struct sock___old {
    struct sock_common __sk_common;
    unsigned int __sk_flags_offset[0];
    unsigned int sk_padding : 1, 
                 sk_kern_sock : 1,
                 sk_no_check_tx : 1,
                 sk_no_check_rx : 1,
                 sk_userlocks : 4,
                 sk_protocol : 8,
                 sk_type : 16;
    u16 sk_gso_max_segs;
};
// clang-format on

// support bpf_core_type_exists((task struct)->pids) for kernels < 5.0

struct pid_link {
    struct hlist_node node;
    struct pid *pid;
};

struct task_struct___older_v50 {
    struct pid_link pids[PIDTYPE_MAX];
};

struct trace_probe___v53 {
    struct trace_event_call call;
};

// kernel >= 6.1 kernel_cap_t type change

struct kernel_cap_struct___older {
    __u32 cap[2];
};

typedef struct kernel_cap_struct___older kernel_cap_t___older;

// struct module //

struct module_layout {
    void *base;
};

struct module___older_v64 {
    struct module_layout core_layout;
};

// kernel >= v6.6 inode i_ctime field change
struct inode___older_v66 {
    struct timespec64 i_ctime;
};

#define PF_INET 2   /* IP protocol family.  */
#define PF_INET6 10 /* IP version 6.  */
#define AF_INET PF_INET
#define AF_INET6 PF_INET6

#define sockaddr_storage __kernel_sockaddr_storage

static_inline struct inet_sock *inet_sk(struct sock *sk)
{
    return (struct inet_sock *)sk;
}

#define INADDR_ANY ((uint32_t)0x00000000)

static_inline bool ipv4_addr_any(const struct in_addr *a)
{
    return a->s_addr == INADDR_ANY;
}

static_inline bool ipv4_addr_loopback(const struct in_addr *a)
{
    return ((long int)a->s_addr & 0xff000000) == 0x7f000000;
}

static_inline bool ipv6_addr_any(const struct in6_addr *a)
{
    return (a->in6_u.u6_addr32[0] | a->in6_u.u6_addr32[1] | a->in6_u.u6_addr32[2] |
            a->in6_u.u6_addr32[3]) == 0;
}

static_inline bool ipv6_addr_loopback(const struct in6_addr *a)
{
    return (a->in6_u.u6_addr32[0] | a->in6_u.u6_addr32[1] | a->in6_u.u6_addr32[2] |
            (a->in6_u.u6_addr32[3] ^ bpf_htonl(1))) == 0;
}

struct iov_iter___old {
    int type;
    union {
        const struct iovec *iov;
        void *ubuf;
    };
} __attribute__((preserve_access_index));

static_inline enum iter_type iov_iter_type(const struct iov_iter *i)
{
    if (bpf_core_field_exists(i->iter_type)) {
        return BPF_CORE_READ(i, iter_type);
    }

    struct iov_iter___old *i__old = (struct iov_iter___old *)i;
    return (BPF_CORE_READ(i__old, type) & ~(READ | WRITE));
}

static_inline bool iter_is_ubuf(const struct iov_iter *i)
{
    if (bpf_core_enum_value_exists(enum iter_type, ITER_UBUF)) {
        return iov_iter_type(i) == bpf_core_enum_value(enum iter_type, ITER_UBUF);
    }

    return false;
}

static_inline bool iter_is_iovec(const struct iov_iter *i)
{
    return iov_iter_type(i) == bpf_core_enum_value(enum iter_type, ITER_IOVEC);
}

static_inline unsigned char iov_iter_rw(const struct iov_iter *i)
{
    if (bpf_core_field_exists(i->data_source)) {
        return BPF_CORE_READ(i, data_source) ? WRITE : READ;
    }
    struct iov_iter___old *i__old = (struct iov_iter___old *)i;
    return (BPF_CORE_READ(i__old, type) & (READ | WRITE));
}

static inline bool user_backed_iter(const struct iov_iter *i)
{
    return iter_is_ubuf(i) || iter_is_iovec(i);
}

static_inline const struct iovec *iter_iov(const struct iov_iter *i)
{
    if (iter_is_ubuf(i)) {
        if (bpf_core_field_exists(i->__ubuf_iovec)) {
            return __builtin_preserve_access_index(&i->__ubuf_iovec);
        }

        struct iov_iter___old *i__old = (struct iov_iter___old *)i;
        return (const struct iovec *)BPF_CORE_READ(i__old, ubuf);
    }

    if (bpf_core_field_exists(i->__iov)) {
        return BPF_CORE_READ(i, __iov);
    }

    struct iov_iter___old *i__old = (struct iov_iter___old *)i;
    return BPF_CORE_READ(i__old, iov);
}

struct renamedata___old {
    struct user_namespace *old_mnt_userns;
} __attribute__((preserve_access_index));

static_inline bool using_mnt_usernamespace()
{
    return bpf_core_field_exists(struct renamedata___old, old_mnt_userns);
}

static_inline bool using_mnt_idmap()
{
    return bpf_core_field_exists(struct renamedata, old_mnt_idmap);
}
