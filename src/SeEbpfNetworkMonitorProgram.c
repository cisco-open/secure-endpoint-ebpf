/**
 * @file
 * @copyright (c) 2020-2023 Cisco Systems, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 * This library is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation; either version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License or the LICENSE file for more details.
 *
 * @details
 * bpf program:
 *
 * - Does not support dirfds opened via name_to_handle_at/open_by_handle_at
 * - Missing some renames due to the ordering of fork events
 *
 */


#include <linux/in.h>
#include <linux/in6.h>
#include <linux/uio.h>
#include <linux/limits.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <uapi/linux/fcntl.h>
#include <uapi/linux/ptrace.h>

/* RHEL macros */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif
#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(0, 0)
#endif

/* MUST be a power of 2 */
#define AMPNF_TCP_SEND_LIMIT 16384

/* Max pids on a 32-bit linux system */
#define EXCLUDED_PIDS_MAX 31248

typedef enum {
    ebpf_network_kernel_event_type_connect,
    ebpf_network_kernel_event_type_accept,
    ebpf_network_kernel_event_type_send,
    ebpf_network_kernel_event_type_receive,
    ebpf_network_kernel_event_type_release,
    ebpf_network_kernel_event_type_listen,
} ebpf_network_kernel_event_type_t;

typedef struct ebpf_user_info {
    uid_t ruid;
    uid_t euid;
    gid_t gid;
} ebpf_event_user_t;

typedef struct ebpf_network_kernel_event {
    ebpf_network_kernel_event_type_t event_type;
    uint64_t sk_id;
    struct sockaddr_in6 local;
    struct sockaddr_in6 remote;
    unsigned char protocol;
    pid_t pid;
    ebpf_event_user_t user;
    ebpf_event_user_t parent_user;
    char comm[16];
    uint32_t payload_seq;
    uint32_t payload_size;
    uint64_t timestamp_ns;
} ebpf_network_kernel_event_t;

typedef struct ebpf_network_payload_kernel_event {
    ebpf_network_kernel_event_t event;
    unsigned char payload[AMPNF_TCP_SEND_LIMIT];
} ebpf_network_payload_kernel_event_t;

/* Use an BPF map as the stack is too small to hold ebpf_network_payload_kernel_event_t */
BPF_ARRAY(zeroed_payload_event_arr, ebpf_network_payload_kernel_event_t, 1);

/* kern_payload_events about to be sent, keyed on thread ID */
BPF_HASH(payload_events, u32, ebpf_network_payload_kernel_event_t);

typedef struct ampnf_sock_buf {
    struct inet_sock inet_sk;
    struct ipv6_pinfo pinet6;
} ampnf_sock_buf_t;

typedef enum ampnf_known_sock_type {
    AMPNF_TYPE_NONE = 0,
    AMPNF_TYPE_TCP_CLI,
    AMPNF_TYPE_TCP_SRV,
    AMPNF_TYPE_UDP
} ampnf_known_sock_type_t;

typedef struct ampnf_known_sock {
    ampnf_known_sock_type_t type;
    /* Socket ID for userland */
    uint64_t sk_id;
    /* Remote/local - useful for UDP */
    struct sockaddr_in6 last_local;
    struct sockaddr_in6 last_remote;
    /* Bytes sent - useful for TCP */
    uint32_t bytes_sent;
} ampnf_known_sock_t;

/* Use an BPF map as the stack is too small to hold an ampnf_sock_buf_t */
BPF_ARRAY(zeroed_sock_buf_arr, ampnf_sock_buf_t, 1);

/* Use a BPF map so we can track the latest known sock ID and increment it
 * atomically */
BPF_ARRAY(known_sock_template_arr, ampnf_known_sock_t, 1);

/* _getsockinfo in progress, keyed on thread ID */
BPF_HASH(sock_bufs, u32, ampnf_sock_buf_t);

/* Known sockets, keyed on struct sock* */
BPF_HASH(known_socks, u64, ampnf_known_sock_t);

BPF_TABLE("extern", pid_t, u32, excluded_pids, EXCLUDED_PIDS_MAX);

BPF_PERF_OUTPUT(events);

/* Adapted from inet6_getname() from net/ipv6/af_inet6.c */
static int _do_inet6_getname(struct sock *sk, struct ipv6_pinfo *np, struct sockaddr *uaddr, int peer)
{
    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)uaddr;
    struct inet_sock *inet = inet_sk(sk);

    sin->sin6_family = AF_INET6;
    if (peer) {
        if (!inet->inet_dport)
            return -ENOTCONN;
        if (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) && peer == 1)
            return -ENOTCONN;
        sin->sin6_port = inet->inet_dport;
        sin->sin6_addr = sk->sk_v6_daddr;
    } else {
        if (ipv6_addr_any(&sk->sk_v6_rcv_saddr))
            sin->sin6_addr = np->saddr;
        else
            sin->sin6_addr = sk->sk_v6_rcv_saddr;

        sin->sin6_port = inet->inet_sport;
    }
    return sizeof(*sin);
}

/* Adapted from inet_getname() from net/ipv4/af_inet.c */
static int _do_inet_getname(struct sock *sk, struct sockaddr *uaddr, int peer)
{
    struct inet_sock *inet = inet_sk(sk);
    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;

    sin->sin_family = AF_INET;
    if (peer) {
        if (!inet->inet_dport || (((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_SYN_SENT)) && peer == 1))
            return -ENOTCONN;
        sin->sin_port = inet->inet_dport;
        sin->sin_addr.s_addr = inet->inet_daddr;
    } else {
        __be32 addr = inet->inet_rcv_saddr;
        if (!addr)
            addr = inet->inet_saddr;
        sin->sin_port = inet->inet_sport;
        sin->sin_addr.s_addr = addr;
    }
    return sizeof(*sin);
}

static void _getlocalsockinfo(struct sock *sk, struct sockaddr_in6 *local_name)
{
    ampnf_sock_buf_t *sock_buf;
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = tgid_pid & 0xffffffff;
    int idx = 0;
    ampnf_sock_buf_t *zeroed_sock_buf;

    zeroed_sock_buf = zeroed_sock_buf_arr.lookup(&idx);
    /* BPF enforces that we check if zeroed_sock_buf is NULL */
    if (!zeroed_sock_buf) {
        goto done;
    }

    sock_bufs.insert(&pid, zeroed_sock_buf);
    sock_buf = sock_bufs.lookup(&pid);
    if (!sock_buf) {
        goto done;
    }

    if (bpf_probe_read(&sock_buf->inet_sk, sizeof(struct inet_sock), sk)) {
        goto done;
    }

    if (sock_buf->inet_sk.pinet6) {
        if (bpf_probe_read(&sock_buf->pinet6, sizeof(struct ipv6_pinfo), sock_buf->inet_sk.pinet6)) {
            goto done;
        }
    }

    if (sock_buf->inet_sk.sk.sk_family == PF_INET) {
        (void)_do_inet_getname(&sock_buf->inet_sk.sk, (struct sockaddr *)local_name, 0);
    } else if (sock_buf->inet_sk.sk.sk_family == PF_INET6) {
        (void)_do_inet6_getname(&sock_buf->inet_sk.sk, &sock_buf->pinet6, (struct sockaddr *)local_name, 0);
    }
done:
    sock_bufs.delete(&pid);

    return;
}

static int _getsockinfo(struct sock *sk,
                        struct sockaddr_in6 *sock_name,
                        struct sockaddr_in6 *peer_name,
                        unsigned char *protocol,
                        int *connected)
{
    int ret = -EINVAL;
    int err;
    int rc;
    ampnf_sock_buf_t *sock_buf;
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = tgid_pid & 0xffffffff;

    /* Stack size is limited, so we cannot store a struct sock on the stack. */
    int idx = 0;
    ampnf_sock_buf_t *zeroed_sock_buf = zeroed_sock_buf_arr.lookup(&idx);
    /* BPF enforces that we check if zeroed_sock_buf is NULL */
    if (!zeroed_sock_buf) {
        goto done;
    }
    sock_bufs.insert(&pid, zeroed_sock_buf);
    sock_buf = sock_bufs.lookup(&pid);
    if (!sock_buf) {
        goto done;
    }
    if (bpf_probe_read(&sock_buf->inet_sk, sizeof(struct inet_sock), sk)) {
        goto done;
    }
    if (sock_buf->inet_sk.pinet6) {
        if (bpf_probe_read(&sock_buf->pinet6, sizeof(struct ipv6_pinfo), sock_buf->inet_sk.pinet6)) {
            goto done;
        }
    }

    if (sock_buf->inet_sk.sk.sk_protocol != IPPROTO_TCP &&
        sock_buf->inet_sk.sk.sk_protocol != IPPROTO_UDP) {
        /* socket is not TCPv4, UDPv4, TCPv6 or UDPv6 */
        ret = -EINVAL;
        goto done;
    }
    *protocol = sock_buf->inet_sk.sk.sk_protocol;

    if (sock_buf->inet_sk.sk.sk_family == PF_INET) {
        rc = _do_inet_getname(&sock_buf->inet_sk.sk, (struct sockaddr *)sock_name, 0);
        if (rc < 0) {
            ret = rc;
            goto done;
        }
        rc = _do_inet_getname(&sock_buf->inet_sk.sk, (struct sockaddr *)peer_name, 1);
    } else if (sock_buf->inet_sk.sk.sk_family == PF_INET6) {
        rc = _do_inet6_getname(&sock_buf->inet_sk.sk, &sock_buf->pinet6, (struct sockaddr *)sock_name, 0);
        if (rc < 0) {
            ret = rc;
            goto done;
        }
        rc = _do_inet6_getname(&sock_buf->inet_sk.sk, &sock_buf->pinet6, (struct sockaddr *)peer_name, 1);
    } else {
        /* non-inet socket */
        goto done;
    }
    if (rc == -ENOTCONN) {
        *connected = 0;
    } else if (rc < 0) {
        ret = rc;
        goto done;
    } else {
        *connected = 1;
    }

    ret = 0;
done:
    sock_bufs.delete(&pid);
    return ret;
}

/* TCP connect/accept: create && overwrite
 * TCP send: !create && !overwrite
 * UDP send/recv: create && !overwrite
 * release: !create && !overwrite
 */
static ampnf_known_sock_t *_get_known_sock(struct sock *sock,
                                           bool create,
                                           bool overwrite,
                                           ampnf_known_sock_type_t sock_type)
{
    struct sock *sock_ref = sock;
    int idx = 0;
    uint64_t sk_id;
    ampnf_known_sock_t *known_sock_template;
    ampnf_known_sock_t *known_sock = known_socks.lookup((u64 *)&sock_ref);
    if ((!known_sock && create) || (known_sock && overwrite)) {
        known_sock_template = known_sock_template_arr.lookup(&idx);
        /* BPF enforces that we check if known_sock_template is NULL */
        if (known_sock_template) {
            /* atomic add */
            /** @todo TODO: XXX this is not really atomic! */
            {
                // Does not work: sk_id = __sync_add_and_fetch(&known_sock_template->sk_id, 1);
                (void)__sync_add_and_fetch(&known_sock_template->sk_id, 1);
                sk_id = known_sock_template->sk_id;
            }
            if (!known_sock) {
                if (!known_socks.insert((u64 *)&sock_ref, known_sock_template)) {
                    /* Inserted */
                    known_sock = known_socks.lookup((u64 *)&sock_ref);
                    if (known_sock) {
                        known_sock->sk_id = sk_id;
                        known_sock->type = sock_type;
                    }
                } else {
                    /* Already existed? */
                    known_sock = known_socks.lookup((u64 *)&sock_ref);
                }
            } else {
                /* Update */
                known_sock->sk_id = sk_id;
                known_sock->type = sock_type;
            }
        }
    }
    return known_sock;
}

static bool _addrs_equal(const struct sockaddr *first, const struct sockaddr *second)
{
    bool equal = false;
    const struct sockaddr_in *first_in, *second_in;
    const struct sockaddr_in6 *first_in6, *second_in6;
    if ((first->sa_family == AF_INET) && (second->sa_family == AF_INET)) {
        first_in = (const struct sockaddr_in *)first;
        second_in = (const struct sockaddr_in *)second;
        if ((first_in->sin_port == second_in->sin_port) &&
            (first_in->sin_addr.s_addr == second_in->sin_addr.s_addr)) {
            equal = true;
        }
    } else if ((first->sa_family == AF_INET6) && (second->sa_family == AF_INET6)) {
        first_in6 = (const struct sockaddr_in6 *)first;
        second_in6 = (const struct sockaddr_in6 *)second;
        if ((first_in6->sin6_port == second_in6->sin6_port) &&
            (first_in6->sin6_addr.s6_addr32[0] == second_in6->sin6_addr.s6_addr32[0]) &&
            (first_in6->sin6_addr.s6_addr32[1] == second_in6->sin6_addr.s6_addr32[1]) &&
            (first_in6->sin6_addr.s6_addr32[2] == second_in6->sin6_addr.s6_addr32[2]) &&
            (first_in6->sin6_addr.s6_addr32[3] == second_in6->sin6_addr.s6_addr32[3])) {
            equal = true;
        }
    }
    return equal;
}

static bool _is_loopback(const struct sockaddr *addr)
{
    bool is_loopback = false;
    struct in6_addr zero_addr_in6 = { { { 0 } } };
    struct in6_addr loopback_addr_in6 = { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    /* Match first 12 bytes: */
    struct in6_addr ipv4_net_in6 = { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } } };
#define IS_IN_LOOPBACK(addr_in) IN_LOOPBACK(ntohl((addr_in)->sin_addr.s_addr))
#define IS_IN_ZERO(addr_in) (ntohl((addr_in)->sin_addr.s_addr) == INADDR_ANY)
#define IS_IN6_LOOPBACK(addr_in6) \
    ((((addr_in6)->sin6_addr.s6_addr32[0] == loopback_addr_in6.s6_addr32[0]) && \
      ((addr_in6)->sin6_addr.s6_addr32[1] == loopback_addr_in6.s6_addr32[1]) && \
      ((addr_in6)->sin6_addr.s6_addr32[2] == loopback_addr_in6.s6_addr32[2]) && \
      ((addr_in6)->sin6_addr.s6_addr32[3] == loopback_addr_in6.s6_addr32[3])) || \
     (((addr_in6)->sin6_addr.s6_addr32[0] == ipv4_net_in6.s6_addr32[0]) && \
      ((addr_in6)->sin6_addr.s6_addr32[1] == ipv4_net_in6.s6_addr32[1]) && \
      ((addr_in6)->sin6_addr.s6_addr32[2] == ipv4_net_in6.s6_addr32[2]) && \
      IN_LOOPBACK(ntohl((addr_in6)->sin6_addr.s6_addr32[3]))))
#define IS_IN6_ZERO(addr_in6) \
    ((((addr_in6)->sin6_addr.s6_addr32[0] == zero_addr_in6.s6_addr32[0]) && \
      ((addr_in6)->sin6_addr.s6_addr32[1] == zero_addr_in6.s6_addr32[1]) && \
      ((addr_in6)->sin6_addr.s6_addr32[2] == zero_addr_in6.s6_addr32[2]) && \
      ((addr_in6)->sin6_addr.s6_addr32[3] == zero_addr_in6.s6_addr32[3])) || \
     (((addr_in6)->sin6_addr.s6_addr32[0] == ipv4_net_in6.s6_addr32[0]) && \
      ((addr_in6)->sin6_addr.s6_addr32[1] == ipv4_net_in6.s6_addr32[1]) && \
      ((addr_in6)->sin6_addr.s6_addr32[2] == ipv4_net_in6.s6_addr32[2]) && \
      ntohl((addr_in6)->sin6_addr.s6_addr32[3]) == INADDR_ANY))

    if (addr->sa_family == AF_INET) {
        is_loopback = (IS_IN_LOOPBACK(((const struct sockaddr_in *)addr)) ||
                       IS_IN_ZERO(((const struct sockaddr_in *)addr)));
    } else if (addr->sa_family == AF_INET6) {
        is_loopback = (IS_IN6_LOOPBACK(((const struct sockaddr_in6 *)addr)) ||
                       IS_IN6_ZERO(((const struct sockaddr_in6 *)addr)));
    }

    return is_loopback;
}

/* BPF can't do open-ended loops. */
#define MAX_IOVEC_ITERS 10

/* Adapted from memcpy_fromiovecend in kernel 3.10 */
static int _memcpy_fromiovecend(unsigned char *kdata, const struct iovec *iov, int offset, int len)
{
    struct iovec iov_buf;
    int i;
    int ret = 0;

    /* Skip over the finished iovecs */
#pragma unroll MAX_IOVEC_ITERS
    for (i = 0; i < MAX_IOVEC_ITERS; i++) {
        if (bpf_probe_read(&iov_buf, sizeof(iov_buf), iov)) {
            break;
        }
        if (offset >= iov_buf.iov_len) {
            offset -= iov_buf.iov_len;
            iov++;
        } else {
            break;
        }
    }
    if (offset >= iov_buf.iov_len) {
        return 0;
    }

    /** @todo TODO: the &= trick doesn't work when MAX_IOVEC_ITERS > 1 */
#pragma unroll MAX_IOVEC_ITERS
    for (i = 0; i < 1; i++) {
        if (len > 0) {
            if (bpf_probe_read(&iov_buf, sizeof(iov_buf), iov)) {
                break;
            }

            u8 __user *base = iov_buf.iov_base + offset;
            int copy = min_t(unsigned int, len, iov_buf.iov_len - offset);

            offset = 0;
            /* The &= is here to convince BPF we're not doing an unbounded read.
             * For this to work, AMPNF_TCP_SEND_LIMIT MUST be a power of 2. */
            copy &= (AMPNF_TCP_SEND_LIMIT - 1);
            if (bpf_probe_read(kdata, copy, base)) {
                break;
            }
            len -= copy;
            ret += copy;
            kdata += copy;
            iov++;
        } else {
            break;
        }
    }
    return ret;
}

static bool _populate_process_info(ebpf_network_kernel_event_t *event)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 pid = tgid_pid >> 32;

    pid_t *exclude_pid = excluded_pids.lookup(&pid);
    if (exclude_pid) {
        return false;
    }
    event->pid = pid;

    // Although cred and real_cred are available in task.
    // They seem to contain the same values for uid and euid.
    event->user.ruid = task->cred->uid.val;
    event->user.euid = task->cred->euid.val;
    event->user.gid = task->cred->gid.val;
    event->parent_user.ruid = task->real_parent->cred->uid.val;
    event->parent_user.euid = task->real_parent->cred->euid.val;
    event->parent_user.gid = task->real_parent->cred->gid.val;

    return true;
}

int inet_stream_connect_probe(struct pt_regs *ctx,
                              struct socket *sock,
                              struct sockaddr *uaddr,
                              int addr_len,
                              int flags)
{
    struct socket socket_buf;
    ebpf_network_kernel_event_t event = {
        .event_type = ebpf_network_kernel_event_type_connect,
        .protocol = IPPROTO_TCP,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    if (!_populate_process_info(&event)) {
        return 0;
    }

    if (!bpf_probe_read(&socket_buf, sizeof(socket_buf), sock)) {
        ampnf_known_sock_t *known_sock = _get_known_sock(socket_buf.sk, true, true, AMPNF_TYPE_TCP_CLI);
        if (known_sock) {
            int rc = -EINVAL;
            _getlocalsockinfo(socket_buf.sk, &event.local);
            if (addr_len == sizeof(struct sockaddr_in)) {
                rc = bpf_probe_read(&event.remote, sizeof(struct sockaddr_in), uaddr);
            } else if (addr_len == sizeof(struct sockaddr_in6)) {
                rc = bpf_probe_read(&event.remote, sizeof(struct sockaddr_in6), uaddr);
            }
            if ((rc == 0) && (!_is_loopback((struct sockaddr *)&event.remote))) {
                event.sk_id = known_sock->sk_id;
                bpf_get_current_comm(&event.comm, sizeof(event.comm));
                events.perf_submit(ctx, &event, sizeof(event));
            } else {
                known_socks.delete((u64 *)&socket_buf.sk);
            }
        }
    }
    return 0;
}

struct sock *inet_csk_accept_retprobe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    ebpf_network_kernel_event_t event = {
        .event_type = ebpf_network_kernel_event_type_accept,
        .timestamp_ns = bpf_ktime_get_ns(),
    };
    if (!_populate_process_info(&event)) {
        return 0;
    }

    ampnf_known_sock_t *known_sock = _get_known_sock(sk, true, true, AMPNF_TYPE_TCP_SRV);
    if (known_sock) {
        int connected;
        if ((!_getsockinfo(sk, &event.local, &event.remote, &event.protocol, &connected)) &&
            (!_is_loopback((struct sockaddr *)&event.remote))) {
            event.sk_id = known_sock->sk_id;
            bpf_get_current_comm(&event.comm, sizeof(event.comm));
            events.perf_submit(ctx, &event, sizeof(event));
        } else {
            known_socks.delete((u64 *)&sk);
        }
    }
    return 0;
}

static void _process_tcp_sendmsg(struct pt_regs *ctx,
                                 struct sock *sk,
                                 struct msghdr *msg,
                                 size_t size,
                                 u64 timestamp_ns)
{
    ampnf_known_sock_t *known_sock = _get_known_sock(sk, false, false, AMPNF_TYPE_NONE);

    if (known_sock && known_sock->type == AMPNF_TYPE_TCP_CLI) {
        int idx = 0;
        ebpf_network_payload_kernel_event_t *zeroed_payload_event = zeroed_payload_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_payload_event is NULL */
        if (zeroed_payload_event) {
            u64 tgid_pid = bpf_get_current_pid_tgid();
            u32 pid = tgid_pid & 0xffffffff;
            payload_events.insert(&pid, zeroed_payload_event);
            ebpf_network_payload_kernel_event_t *payload_event = payload_events.lookup(&pid);
            if (payload_event && _populate_process_info(&payload_event->event)) {
                size_t read_size = 0;
                struct msghdr msg_buf;
                int connected;
                payload_event->event.timestamp_ns = timestamp_ns;
                if ((!_getsockinfo(sk,
                                   &payload_event->event.local,
                                   &payload_event->event.remote,
                                   &payload_event->event.protocol,
                                   &connected)) &&
                    (!bpf_probe_read(&msg_buf, sizeof(msg_buf), msg))) {
                    if (msg_buf.msg_name) {
                        /* If msg_name is not NULL, it overrides the remote addr */
                        if (msg_buf.msg_namelen == sizeof(struct sockaddr_in)) {
                            bpf_probe_read(&payload_event->event.remote,
                                           sizeof(struct sockaddr_in),
                                           msg_buf.msg_name);
                        } else if (msg_buf.msg_namelen == sizeof(struct sockaddr_in6)) {
                            bpf_probe_read(&payload_event->event.remote,
                                           sizeof(struct sockaddr_in6),
                                           msg_buf.msg_name);
                        }
                    }
                    struct iovec iov_buf;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
                    if ((iov_iter_rw(&msg_buf.msg_iter) == WRITE) && user_backed_iter(&msg_buf.msg_iter) &&
                        (!bpf_probe_read(&iov_buf, sizeof(iov_buf), iter_iov(&msg_buf.msg_iter))) &&
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
                    if (msg_buf.msg_iter.data_source && (msg_buf.msg_iter.iter_type == ITER_IOVEC) &&
                        (!bpf_probe_read(&iov_buf, sizeof(iov_buf), msg_buf.msg_iter.iov)) &&
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
                    if ((msg_buf.msg_iter.type == (ITER_IOVEC | WRITE)) &&
                        (!bpf_probe_read(&iov_buf, sizeof(iov_buf), msg_buf.msg_iter.iov)) &&
#else
                    if ((!bpf_probe_read(&iov_buf, sizeof(iov_buf), msg_buf.msg_iov)) &&
#endif
                        (known_sock->bytes_sent < AMPNF_TCP_SEND_LIMIT)) {
                        payload_event->event.payload_seq = known_sock->bytes_sent;
                        read_size = AMPNF_TCP_SEND_LIMIT - known_sock->bytes_sent;
                        if (read_size > size) {
                            read_size = size;
                        }
                        /* Advance by read_size even if we are unable to fully
                         * read this many bytes from the iovec */
                        known_sock->bytes_sent += read_size;
                    }
                }
                if (read_size > 0) {
                    payload_event->event.payload_size = _memcpy_fromiovecend(payload_event->payload,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
                                                                             iter_iov(&msg_buf.msg_iter),
                                                                             msg_buf.msg_iter.iov_offset,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
                                                                             msg_buf.msg_iter.iov,
                                                                             msg_buf.msg_iter.iov_offset,
#else
                                                                             msg_buf.msg_iov,
                                                                             0,
#endif
                                                                             read_size);
                    if (payload_event->event.payload_size > 0) {
                        payload_event->event.event_type = ebpf_network_kernel_event_type_send;
                        payload_event->event.sk_id = known_sock->sk_id;
                        payload_event->event.protocol = IPPROTO_TCP;
                        bpf_get_current_comm(&payload_event->event.comm, sizeof(payload_event->event.comm));
                        read_size = sizeof(payload_event->event) + payload_event->event.payload_size;
                        if (read_size < sizeof(*payload_event)) {
                            events.perf_submit(ctx, payload_event, read_size);
                        }
                    }
                }
            }
            payload_events.delete(&pid);
        }
    }
}

static void _process_udp_sendmsg(struct pt_regs *ctx,
                                 struct sock *sk,
                                 struct msghdr *msg,
                                 size_t size,
                                 u64 timestamp_ns)
{
    ebpf_network_kernel_event_t event = {
        .event_type = ebpf_network_kernel_event_type_send,
        .protocol = IPPROTO_UDP,
        .timestamp_ns = timestamp_ns,
    };
    bool do_send_event = false;

    if (!_populate_process_info(&event)) {
        return;
    }

    ampnf_known_sock_t *known_sock = _get_known_sock(sk, true, false, AMPNF_TYPE_UDP);
    if (known_sock) {
        int connected;
        if (!_getsockinfo(sk, &event.local, &event.remote, &event.protocol, &connected)) {
            struct msghdr msg_buf;
            if ((!bpf_probe_read(&msg_buf, sizeof(msg_buf), msg)) && (msg_buf.msg_name)) {
                /* If msg_name is not NULL, it overrides the remote addr */
                if (msg_buf.msg_namelen == sizeof(struct sockaddr_in)) {
                    bpf_probe_read(&event.remote, sizeof(struct sockaddr_in), msg_buf.msg_name);
                } else if (msg_buf.msg_namelen == sizeof(struct sockaddr_in6)) {
                    bpf_probe_read(&event.remote, sizeof(struct sockaddr_in6), msg_buf.msg_name);
                }
            }
            if (!_is_loopback((struct sockaddr *)&event.remote)) {
                if (!_addrs_equal((struct sockaddr *)&event.local,
                                  (struct sockaddr *)&known_sock->last_local)) {
                    do_send_event = true;
                    known_sock->last_local = event.local;
                }
                if (!_addrs_equal((struct sockaddr *)&event.remote,
                                  (struct sockaddr *)&known_sock->last_remote)) {
                    do_send_event = true;
                    known_sock->last_remote = event.remote;
                }
            }
        }
    }
    if (do_send_event) {
        event.sk_id = known_sock->sk_id;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        events.perf_submit(ctx, &event, sizeof(event));
    }
}

int inet_sendmsg_probe(struct pt_regs *ctx,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
                       struct kiocb *iocb,
#endif
                       struct socket *sock,
                       struct msghdr *msg,
                       size_t size)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    struct socket socket_buf;

    if (!bpf_probe_read(&socket_buf, sizeof(socket_buf), sock)) {
        if (socket_buf.type == SOCK_DGRAM) {
            _process_udp_sendmsg(ctx, socket_buf.sk, msg, size, timestamp_ns);
        } else if (socket_buf.type == SOCK_STREAM) {
            _process_tcp_sendmsg(ctx, socket_buf.sk, msg, size, timestamp_ns);
        }
    }
    return 0;
}

static void _process_recvmsg(struct pt_regs *ctx,
                             struct sock *sk,
                             ampnf_known_sock_type_t sock_type,
                             u64 timestamp_ns)
{
    ebpf_network_kernel_event_t event = {
        .event_type = ebpf_network_kernel_event_type_receive,
        .timestamp_ns = timestamp_ns,
    };

    if (!_populate_process_info(&event)) {
        return;
    }

    ampnf_known_sock_t *known_sock = _get_known_sock(sk, true, false, sock_type);
    if (known_sock) {
        int connected;
        if ((!_getsockinfo(sk, &event.local, &event.remote, &event.protocol, &connected)) &&
            (!_is_loopback((struct sockaddr *)&event.remote))) {
            bool do_send_event = false;

            if (!_addrs_equal((struct sockaddr *)&event.local,
                              (struct sockaddr *)&known_sock->last_local)) {
                do_send_event = true;
                known_sock->last_local = event.local;
            }

            if (!_addrs_equal((struct sockaddr *)&event.remote,
                              (struct sockaddr *)&known_sock->last_remote)) {
                do_send_event = true;
                known_sock->last_remote = event.remote;
            }

            /* For a unique connection, only the first data packet triggers an event. */
            if (do_send_event) {
                event.sk_id = known_sock->sk_id;
                bpf_get_current_comm(&event.comm, sizeof(event.comm));
                events.perf_submit(ctx, &event, sizeof(event));
            }
        }
    }
}

int inet_recvmsg_probe(struct pt_regs *ctx,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
                       struct kiocb *iocb,
#endif
                       struct socket *sock,
                       struct msghdr *msg,
                       size_t size,
                       int flags)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    struct socket socket_buf;

    if (!bpf_probe_read(&socket_buf, sizeof(socket_buf), sock)) {
        if (socket_buf.type == SOCK_DGRAM) {
            _process_recvmsg(ctx, socket_buf.sk, AMPNF_TYPE_UDP, timestamp_ns);
        } else if (socket_buf.type == SOCK_STREAM) {
            _process_recvmsg(ctx, socket_buf.sk, AMPNF_TYPE_TCP_SRV, timestamp_ns);
        }
    }
    return 0;
}

int release_probe(struct pt_regs *ctx, struct socket *sock)
{
    ebpf_network_kernel_event_t event = {
        .event_type = ebpf_network_kernel_event_type_release,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    if (!_populate_process_info(&event)) {
        return 0;
    }

    struct socket socket_buf;
    if (!bpf_probe_read(&socket_buf, sizeof(socket_buf), sock)) {
        ampnf_known_sock_t *known_sock = _get_known_sock(socket_buf.sk, false, false, AMPNF_TYPE_NONE);
        if (known_sock) {
            int connected;
            if (!_getsockinfo(socket_buf.sk, &event.local, &event.remote, &event.protocol, &connected)) {
                event.sk_id = known_sock->sk_id;
                bpf_get_current_comm(&event.comm, sizeof(event.comm));
                events.perf_submit(ctx, &event, sizeof(event));
            }
            known_socks.delete((u64 *)&socket_buf.sk);
        }
    }
    return 0;
}

int inet_listen_probe(struct pt_regs *ctx, struct socket *sock, int backlog)
{
    struct socket socket_buf;
    ebpf_network_kernel_event_t event = {
        .event_type = ebpf_network_kernel_event_type_listen,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    if (!_populate_process_info(&event)) {
        return 0;
    }

    if (!bpf_probe_read(&socket_buf, sizeof(socket_buf), sock)) {
        ampnf_known_sock_t *known_sock = _get_known_sock(socket_buf.sk, true, false, AMPNF_TYPE_TCP_CLI);
        if (known_sock) {
            int connected;
            if (!_getsockinfo(socket_buf.sk, &event.local, &event.remote, &event.protocol, &connected)) {
                event.sk_id = known_sock->sk_id;
                bpf_get_current_comm(&event.comm, sizeof(event.comm));
                events.perf_submit(ctx, &event, sizeof(event));
            }
        }
    }
    return 0;
}
