/**
 * @file
 * @copyright (c) 2020-2023 Cisco Systems, Inc. All rights reserved
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


#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/limits.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <uapi/linux/fcntl.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/ptrace.h>

/* RHEL macros */
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) (((a) << 8) + (b))
#endif
#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE RHEL_RELEASE_VERSION(0, 0)
#endif

/* MAX_PATH_SEGS determines the number of path segments each iteration
 * of the program can resolve. Because we have to unroll loops, increasing
 * MAX_PATH_SEGS increases the BPF program size. This number is set to near
 * the highest possible value: */
#define MAX_PATH_SEGS 72

/* Tail depth determines the maximum number of times the program will tail
 * before jumping to the end program which submits the event. It is set to
 * the maximum possible value. */
#define TAIL_DEPTH 30

/* defining indexes of tailing programs */
#define PATH_LOOP_PROG 0
#define PATH_END_PROG 1
#define RENAME_LOOP_PROG 2
#define RENAME_END_PROG 3

/* NAME_MAX added to pacify verifier in case of 2048 segment path
 * where last path still COULD be 256 chars from the perspective of the
 * verifier. */
#define PATH_ARR_SIZE PATH_MAX + NAME_MAX + 1

/* Increasing the LRU cache size is relatively cheap.
 * Key = 128 bits, Value = 64 bits, Total = 192 bits.
 * 192 bits * 65535 = 1.57 MB */
#define DEFAULT_LRU_CACHE_SIZE 65535
#define DEFAULT_LRU_CACHE_TTL_SECS 30

/* Max pids on a 32-bit linux system */
#define EXCLUDED_PIDS_MAX 31248

typedef enum ebpf_proc_file_fn {
    EBPF_FN_FILE_CREATE,
    EBPF_FN_FILE_RENAME,
    EBPF_FN_FILE_WRITE,
    EBPF_FN_FILE_CLOSE_WRITE,
    EBPF_FN_FILE_UNLINK,
    EBPF_FN_VFS_READ,
    EBPF_FN_DO_MMAP,

    EBPF_FN_PROC_FORK,
    EBPF_FN_PROC_EXEC,
    EBPF_FN_PROC_EXIT,
} ebpf_proc_file_fn_t;

typedef struct ebpf_mount_info {
    unsigned int magic;
    unsigned int mode;
    unsigned int dev_major;
    unsigned int dev_minor;
} ebpf_mount_info_t;

typedef struct ebpf_user {
    uid_t ruid;
    uid_t euid;
    gid_t gid;
} ebpf_event_user_t;

typedef struct ebpf_path_event_info {
    pid_t tgid;
    pid_t ppid;
    ebpf_event_user_t user;
    ebpf_event_user_t parent_user;
    ebpf_proc_file_fn_t fn;
    int dirfd;
    ebpf_mount_info_t mount_info;
    struct dentry *dentry;
    unsigned int path_name_size;
    uint64_t timestamp_ns;
} ebpf_common_event_info_t;

typedef struct ebpf_rename_event_info {
    ebpf_mount_info_t from_mount_info;
    unsigned int from_path_name_size;
} ebpf_rename_event_info_t;

typedef struct ebpf_path_event {
    ebpf_common_event_info_t event_info;
    char path_name[PATH_ARR_SIZE];
} ebpf_path_event_t;

typedef struct ebpf_rename_event {
    ebpf_common_event_info_t path_event_info;
    ebpf_rename_event_info_t event_info;
    char paths[2 * (PATH_ARR_SIZE)];
} ebpf_rename_event_t;

typedef struct ebpf_unique_file_event {
    unsigned long ino;
    pid_t pid;
    unsigned int dev_major;
    unsigned int dev_minor;
} ebpf_unique_file_event_t;

typedef struct dentry_pointer {
    struct dentry *first_dentry;
} dentry_pointer_t;

typedef struct do_mmap_exclusion_key {
    unsigned int dev_major;
    unsigned int dev_minor;
    ino_t ino;
} do_mmap_exclusion_key_t;

/* Use a BPF map as the stack is too small to hold ebpf_path_event_t */
BPF_ARRAY(zeroed_path_event_arr, ebpf_path_event_t, 1);

/* Use a BPF map as the stack is too small to hold ebpf_rename_event_t */
BPF_ARRAY(zeroed_rename_event_arr, ebpf_rename_event_t, 1);

/* Use an LRU hash table so we can minimize read event duplication */
BPF_TABLE("lru_hash", ebpf_unique_file_event_t, u64, recent_read_events, DEFAULT_LRU_CACHE_SIZE);

/* Use an LRU hash table so we can minimize modify event duplication */
BPF_TABLE("lru_hash", ebpf_unique_file_event_t, u64, recent_modify_events, DEFAULT_LRU_CACHE_SIZE);

/* Holds path event from probe to pass to loop/end programs */
BPF_PERCPU_ARRAY(loop_event_p, ebpf_path_event_t, 1);

/* Monitored vfs_rename in progress, keyed on thread ID */
BPF_HASH(vfs_rename_calls, u32, ebpf_rename_event_t);
BPF_PERCPU_ARRAY(rename_ret, int, 1);
BPF_HASH(leaf_dentry, u32, struct dentry_pointer);

/* Monitored proc_*_connector in progress, keyed on thread ID */
BPF_HASH(proc_connector_calls, u32, ebpf_path_event_t);

BPF_TABLE("extern", pid_t, u32, excluded_pids, EXCLUDED_PIDS_MAX);

/* Holds FDs of programs */
BPF_PROG_ARRAY(programs_table, 4);

/* Depth of tailing. This value is used to track how deep into tail calls
 * we are. It must be reset before we start the path-resolving loop programs
 * since it is persistent between probes/programs */
BPF_PERCPU_ARRAY(path_lookup_depth, int, 1);

BPF_TABLE("extern", do_mmap_exclusion_key_t, u32, do_mmap_exclusions, 4);

BPF_PERF_OUTPUT(events);


static bool exclude_tgid(u32 tgid)
{
    return excluded_pids.lookup(&tgid);
}

static bool is_excluded_do_mmap(dev_t dev, ino_t ino)
{
    do_mmap_exclusion_key_t key = { MAJOR(dev), MINOR(dev), ino };
    return do_mmap_exclusions.lookup(&key);
}

static bool _want_inode(struct inode *inode)
{
    unsigned int magic = inode->i_sb->s_magic;
    unsigned int mode = inode->i_mode;
    return (magic != PROC_SUPER_MAGIC && magic != SYSFS_MAGIC && magic != CGROUP_SUPER_MAGIC &&
            (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)));
}

static bool _is_executable_memory_map(unsigned long prot)
{
    return (prot & PROT_EXEC);
}

/* path dentry lookup */
int path_lookup_program(void *ctx)
{
    int idx = 0;
    int new_depth = 1;
    // Check depth of tailing to determine whether end further loop program tails
    // and submit what we have already resolved in the event
    int *depth = (int *)path_lookup_depth.lookup(&idx);
    if (depth != NULL) {
        new_depth = *depth + 1;
        if (*depth >= TAIL_DEPTH) {
            programs_table.call(ctx, PATH_END_PROG);
            return 0;
        }
    }
    path_lookup_depth.update(&idx, &new_depth);

    ebpf_path_event_t *event = (ebpf_path_event_t *)loop_event_p.lookup(&idx);
    if (!event) {
        return 0;
    }

    ebpf_common_event_info_t e_info;
    bpf_probe_read_kernel(&e_info, sizeof(ebpf_common_event_info_t), &event->event_info);

    struct dentry de;
    struct dentry *old = e_info.dentry;
    bpf_probe_read_kernel(&de, sizeof(struct dentry), e_info.dentry);

    int len = 0;
#pragma unroll
    for (int i = 1; i < MAX_PATH_SEGS; i++) {
        struct qstr namestr;
        bpf_probe_read_kernel(&namestr, sizeof(struct qstr), &de.d_name);

        int offset = event->event_info.path_name_size;

        // If next read has the potential to exceed the array size then exit early
        if (offset > PATH_MAX || offset < 0) {
            event->event_info.path_name_size = 0;
            programs_table.call(ctx, PATH_END_PROG);
            return 0;
        }

        int len = bpf_probe_read_str(&event->path_name[offset], NAME_MAX + 1, namestr.name);
        // To detect truncation
        char nullbyte;
        if ((len > 0) && (len == NAME_MAX + 1) &&
            (bpf_probe_read(&nullbyte, 1, &namestr.name[len - 1]) == 0) && (nullbyte != '\0')) {
            // truncated
            len = 0;
        }

        if (len <= 0) {
            event->event_info.path_name_size = 0;
            programs_table.call(ctx, PATH_END_PROG);
            return 0;
        }

        event->event_info.path_name_size += len;

        if (old == de.d_parent) { // reached root directory
            programs_table.call(ctx, PATH_END_PROG);
        }

        old = de.d_parent;
        bpf_probe_read_kernel(&de, sizeof(struct dentry), de.d_parent);
    }

    // Since local variables are lost on a tail, we store the next dentry to be read
    // in the event struct so that the next loop program can continue to loop from
    // the correct location
    event->event_info.dentry = old;

    programs_table.call(ctx, PATH_LOOP_PROG);
    return 0;
}

int rename_lookup_program(void *ctx)
{
    int idx = 0;
    int new_depth = 1;

    // Check whether program called from return probe
    int *is_ret_probe = (int *)rename_ret.lookup(&idx);
    if (is_ret_probe == NULL) {
        return 0;
    }

    // Check depth of tailing to determine whether end further loop program tails
    // and submit what we have already resolved in the event
    int *depth = (int *)path_lookup_depth.lookup(&idx);
    if (depth != NULL) {
        new_depth = *depth + 1;
        if (*depth >= TAIL_DEPTH) {
            if (*is_ret_probe == 1) {
                programs_table.call(ctx, RENAME_END_PROG);
            }
            return 0;
        }
    }
    path_lookup_depth.update(&idx, &new_depth);

    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 kpid = tgid_kpid & 0xffffffff;

    ebpf_rename_event_t *event = (ebpf_rename_event_t *)vfs_rename_calls.lookup(&kpid);
    if (!event) {
        return 0;
    }

    ebpf_common_event_info_t e_info;
    bpf_probe_read_kernel(&e_info, sizeof(ebpf_common_event_info_t), &event->path_event_info);

    struct dentry de;
    struct dentry *old = e_info.dentry;
    bpf_probe_read_kernel(&de, sizeof(struct dentry), e_info.dentry);

    int len = 0;
#pragma unroll
    for (int i = 1; i < MAX_PATH_SEGS; i++) {

        struct qstr namestr;
        bpf_probe_read_kernel(&namestr, sizeof(struct qstr), &de.d_name);
        int offset = event->path_event_info.path_name_size + event->event_info.from_path_name_size;

        // If next read has the potential to exceed the array size then exit early.
        // Since it should not be possible for this to be exceeded except on retprobe
        // we don't have to check *is_ret_probe value
        if (offset > 2 * PATH_MAX + (NAME_MAX + 1) || offset < 0) {
            event->path_event_info.path_name_size = 0;
            programs_table.call(ctx, PATH_END_PROG);
            return 0;
        }

        int len = bpf_probe_read_str(&event->paths[offset], NAME_MAX + 1, namestr.name);
        // To detect truncation
        char nullbyte;
        if ((len > 0) && (len == NAME_MAX + 1) &&
            (bpf_probe_read(&nullbyte, 1, &namestr.name[len - 1]) == 0) && (nullbyte != '\0')) {
            // truncated
            len = 0;
        }

        if (len <= 0) {
            // If on return probe, set path_size to 0 and submit event.
            if (*is_ret_probe == 1) {
                event->path_event_info.path_name_size = 0;
                programs_table.call(ctx, PATH_END_PROG);
            } else {
                // Set from_path_size to 0 but do not submit, wait for retprobe
                event->event_info.from_path_name_size = 0;
            }
            return 0;
        }
        // Separating the below if statements from the above, though it seems redundant,
        // seems to be considered as fewer instructions by the verifier
        if (*is_ret_probe == 0) {
            event->event_info.from_path_name_size += len;
        } else {
            event->path_event_info.path_name_size += len;
        }

        // reached root directory
        if (old == de.d_parent) {
            // If called from return probe then submit event after path is resolved
            if (*is_ret_probe == 1) {
                programs_table.call(ctx, RENAME_END_PROG);
            }
            return 0;
        }

        old = de.d_parent;
        bpf_probe_read_kernel(&de, sizeof(struct dentry), de.d_parent);
    }

    // Storing the next dentry to be read in the event struct for the tailing loop program
    event->path_event_info.dentry = old;

    programs_table.call(ctx, RENAME_LOOP_PROG);
    return 0;
}

static void _send_path_event(struct pt_regs *ctx, struct task_struct *task, ebpf_path_event_t *event)
{
    event->event_info.ppid = task->real_parent->tgid;

    // Although cred and real_cred are available in task.
    // They seem to contain the same values for uid and euid.
    event->event_info.user.ruid = task->cred->uid.val;
    event->event_info.user.euid = task->cred->euid.val;
    event->event_info.user.gid = task->cred->gid.val;
    event->event_info.parent_user.ruid = task->real_parent->cred->uid.val;
    event->event_info.parent_user.euid = task->real_parent->cred->euid.val;
    event->event_info.parent_user.gid = task->real_parent->cred->gid.val;

    /* NULL-out dentry ptr before sending to userland */
    event->event_info.dentry = NULL;
    /* Don't send a full ebpf_path_event_t as that would be
     * wasteful. event_size is dependent upon how much of struct
     * is filled and to be sent. */
    size_t event_size = sizeof(event->event_info) + event->event_info.path_name_size;
    if (event_size < sizeof(*event)) {
        events.perf_submit(ctx, event, event_size);
    }
}

int end_program(void *ctx)
{

    int idx = 0;
    ebpf_path_event_t *event = (ebpf_path_event_t *)loop_event_p.lookup(&idx);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (event) {
        event->event_info.ppid = task->real_parent->tgid;

        // Although cred and real_cred are available in task.
        // They seem to contain the same values for uid and euid.
        event->event_info.user.ruid = task->cred->uid.val;
        event->event_info.user.euid = task->cred->euid.val;
        event->event_info.user.gid = task->cred->gid.val;
        event->event_info.parent_user.ruid = task->real_parent->cred->uid.val;
        event->event_info.parent_user.euid = task->real_parent->cred->euid.val;
        event->event_info.parent_user.gid = task->real_parent->cred->gid.val;

        /* NULL-out dentry ptr before sending to userland */
        event->event_info.dentry = NULL;
        /* Don't send a full ebpf_path_event_t as that would be
         * wasteful. event_size is dependent upon how much of struct
         * is filled and to be sent. */
        size_t event_size = sizeof(event->event_info) + event->event_info.path_name_size;

        if (event_size < sizeof(*event)) {
            events.perf_submit(ctx, event, event_size);
        }

        loop_event_p.delete(&idx);
    }

    return 0;
}

int rename_end_program(void *ctx)
{

    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 kpid = tgid_kpid & 0xffffffff;

    ebpf_rename_event_t *event = (ebpf_rename_event_t *)vfs_rename_calls.lookup(&kpid);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (event) {
        event->path_event_info.ppid = task->real_parent->tgid;

        // Although cred and real_cred are available in task.
        // They seem to contain the same values for uid and euid.
        event->path_event_info.user.ruid = task->cred->uid.val;
        event->path_event_info.user.euid = task->cred->euid.val;
        event->path_event_info.user.gid = task->cred->gid.val;
        event->path_event_info.parent_user.ruid = task->real_parent->cred->uid.val;
        event->path_event_info.parent_user.euid = task->real_parent->cred->euid.val;
        event->path_event_info.parent_user.gid = task->real_parent->cred->gid.val;

        /* NULL-out dentry ptr before sending to userland */
        event->path_event_info.dentry = NULL;
        /* Don't send a full ebpf_path_event_t as that would be
         * wasteful. event_size is dependent upon how much of struct
         * is filled and to be sent. */
        size_t event_size = sizeof(event->path_event_info) + sizeof(event->event_info) +
                            event->event_info.from_path_name_size + event->path_event_info.path_name_size;

        if (event_size < sizeof(*event)) {
            events.perf_submit(ctx, event, event_size);
        }
    }
    leaf_dentry.delete(&kpid);
    vfs_rename_calls.delete(&kpid);

    return 0;
}

static void _set_mount_info(struct inode *inode, ebpf_mount_info_t *mount_info)
{
    dev_t dev = inode->i_sb->s_dev;
    mount_info->magic = inode->i_sb->s_magic;
    mount_info->mode = inode->i_mode;
    mount_info->dev_major = MAJOR(dev);
    mount_info->dev_minor = MINOR(dev);
}

static void _set_dentry_event(struct inode *inode,
                              struct dentry *dentry,
                              ebpf_common_event_info_t *event_info)
{
    event_info->dentry = dentry;
    _set_mount_info(inode, &event_info->mount_info);
}

static void _set_from_mount_info(struct inode *inode, ebpf_rename_event_t *event)
{
    _set_mount_info(inode, &event->event_info.from_mount_info);
}

int proc_fork_connector_probe(struct pt_regs *ctx, struct task_struct *task)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u32 kpid = task->pid;
    u32 tgid = task->tgid;

    /* Only monitor new processes, not new threads */
    if (kpid == tgid) {
        int idx = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            proc_connector_calls.insert(&kpid, zeroed_event);
            event = proc_connector_calls.lookup(&kpid);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.tgid = tgid;
                event->event_info.fn = EBPF_FN_PROC_FORK;
                _send_path_event(ctx, task, event);
            }
            proc_connector_calls.delete(&kpid);
        }
    }

    return 0;
}

int proc_exec_connector_probe(struct pt_regs *ctx, struct task_struct *task)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    struct path *path;
    path = &task->mm->exe_file->f_path;

    if (_want_inode(path->dentry->d_inode)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = task->pid;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_PROC_EXEC;
                event->event_info.tgid = task->tgid;
                _set_dentry_event(path->dentry->d_inode, path->dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }

    return 0;
}

int proc_exit_connector_probe(struct pt_regs *ctx, struct task_struct *task)
{
    u64 timestamp_ns = bpf_ktime_get_ns();

    /* Only monitor process exits, not thread exits */
    if (task->pid == task->tgid) {
        int idx = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = task->pid;

            proc_connector_calls.insert(&kpid, zeroed_event);
            event = proc_connector_calls.lookup(&kpid);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.tgid = task->tgid;
                event->event_info.fn = EBPF_FN_PROC_EXIT;
                _send_path_event(ctx, task, event);
            }
            proc_connector_calls.delete(&kpid);
        }
    }

    return 0;
}

static int _rename_probe_helper(struct pt_regs *ctx,
                                struct inode *old_dir,
                                struct dentry *old_dentry,
                                struct inode *new_dir,
                                struct dentry *new_dentry)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_kpid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    /* Stack size is limited, so we cannot store an ebpf_rename_event_t
     * on the stack.
     * To work around this:
     * 1. Get a pointer to the only element in zeroed_path_event_arr (a zeroed-out
     *    ebpf_rename_event_t)
     * 2. Add a zeroed-out item to the vfs_rename_calls hash table
     * 3. Lookup the item to get a pointer to it
     * 4. Update that item, and use it
     * 5. Later, delete item
     */

    if (_want_inode(new_dir)) {
        int idx = 0;
        int zero = 0;
        ebpf_rename_event_t *zeroed_event = zeroed_rename_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_rename_event_t *event;
            u32 kpid = tgid_kpid & 0xffffffff;
            vfs_rename_calls.insert(&kpid, zeroed_event);
            event = vfs_rename_calls.lookup(&kpid);
            if (event) {
                event->path_event_info.timestamp_ns = timestamp_ns;
                event->path_event_info.fn = EBPF_FN_FILE_RENAME;
                event->path_event_info.tgid = tgid;

                // old_dentry is the filesystem object that is being renamed (reference). By the time the
                // kretprobe fires and assuming vfs_rename succeeded, the data (e.g., name) pointed to by
                // old_dentry would have been altered to refer to the destination.
                _set_dentry_event(new_dir, old_dentry, &event->path_event_info);

                // storing a pointer to a dentry directly (without use of a struct)
                // is not permitted by the verifier
                dentry_pointer_t first_de_pointer;
                first_de_pointer.first_dentry = old_dentry;
                leaf_dentry.update(&kpid, &first_de_pointer);

                _set_from_mount_info(old_dir, event);
                // Signal that we are not in retprobe by writing a 0 into rename_ret
                rename_ret.update(&idx, &zero);
                path_lookup_depth.update(&idx, &zero); // reset tail depth to 0
                programs_table.call(ctx, RENAME_LOOP_PROG);
            }
        }
    }

    return 0;
}

int vfs_rename_retprobe(struct pt_regs *ctx)
{
    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 kpid = tgid_kpid & 0xffffffff;
    ebpf_rename_event_t *event = vfs_rename_calls.lookup(&kpid);
    if (event) {
        if (PT_REGS_RC(ctx) == 0) {
            int idx = 0;
            int zero = 0;
            int one = 1;

            dentry_pointer_t *og_de = (dentry_pointer_t *)leaf_dentry.lookup(&kpid);
            if (og_de != NULL) {
                event->path_event_info.dentry = og_de->first_dentry;
            }
            // Signal that we are in retprobe by setting rename_ret to 1
            rename_ret.update(&idx, &one);
            path_lookup_depth.update(&idx, &zero); // reset tail depth to 0
            programs_table.call(ctx, RENAME_LOOP_PROG);
        }
    }
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
int vfs_rename_probe(struct pt_regs *ctx, struct renamedata *data)
{
    return _rename_probe_helper(ctx, data->old_dir, data->old_dentry, data->new_dir, data->new_dentry);
}
#else
int vfs_rename_probe(struct pt_regs *ctx,
                     struct inode *old_dir,
                     struct dentry *old_dentry,
                     struct inode *new_dir,
                     struct dentry *new_dentry)
{
    return _rename_probe_helper(ctx, old_dir, old_dentry, new_dir, new_dentry);
}
#endif

static bool _has_ttl_expired(u64 current_ts, u64 stored_ts)
{
    u64 delta_secs = ((current_ts - stored_ts) / 1000000000);
    return (delta_secs >= DEFAULT_LRU_CACHE_TTL_SECS);
}

static bool _is_unique_modify_event(ebpf_unique_file_event_t *modify_event)
{
    u64 ts = bpf_ktime_get_ns();
    u64 *val = recent_modify_events.lookup(modify_event);
    if (val) {
        if (_has_ttl_expired(ts, *val)) {
            recent_modify_events.update(modify_event, &ts);
        } else {
            return false;
        }
    } else {
        recent_modify_events.insert(modify_event, &ts);
    }
    return true;
}

static void _populate_unique_file_event(ebpf_unique_file_event_t *event,
                                        unsigned long ino,
                                        pid_t tgid,
                                        dev_t dev)
{
    __builtin_memset(event, 0, sizeof(*event));
    event->ino = ino, event->pid = tgid; /* Ensures multiple process threads count as one process. */
    event->dev_major = MAJOR(dev);
    event->dev_minor = MINOR(dev);
}

int vfs_write_probe(struct pt_regs *ctx, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    struct inode *dir = file->f_inode;
    struct dentry *dentry = file->f_path.dentry;
    dev_t dev = dir->i_sb->s_dev;

    /* Modify events are very noisy so perform some filtering.
     * Drop the event if it isn't "unique". */
    ebpf_unique_file_event_t modify_event;
    _populate_unique_file_event(&modify_event, dir->i_ino, tgid, dev);
    if (!_is_unique_modify_event(&modify_event)) {
        return 0;
    }

    if (_want_inode(dir)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_pid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_FILE_WRITE;
                event->event_info.tgid = tgid;
                _set_dentry_event(dir, dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }

    return 0;
}

int do_truncate_probe(struct pt_regs *ctx,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
                      struct user_namespace *mnt_userns,
#endif
                      struct dentry *dentry,
                      loff_t length,
                      unsigned int time_attrs,
                      struct file *filp)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_kpid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    if (_want_inode(dentry->d_inode)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_kpid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_FILE_WRITE;
                event->event_info.tgid = tgid;
                _set_dentry_event(dentry->d_inode, dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }

    return 0;
}

int vfs_unlink_probe(struct pt_regs *ctx,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
                     struct user_namespace *mnt_userns,
#endif
                     struct inode *dir,
                     struct dentry *dentry,
                     struct inode **delegated_inode)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_kpid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    if (_want_inode(dentry->d_inode)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_kpid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_FILE_UNLINK;
                event->event_info.tgid = tgid;
                _set_dentry_event(dentry->d_inode, dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }

    return 0;
}

/**
 * vfs_open - open the file at the given path
 * @path: path to open
 * @file: newly allocated file with f_flag initialized
 */
int vfs_open_probe(struct pt_regs *ctx, const struct path *path, struct file *file)
{

    // FMODE_CREATED is not available on older kernels.
    // Allow FP file.create events in these instances.
    bool no_fmode_created = false;
#ifndef FMODE_CREATED
#define FMODE_CREATED 0
    no_fmode_created = true;
#endif

    u64 timestamp_ns = bpf_ktime_get_ns();
    if (file->f_mode & FMODE_CREATED || (no_fmode_created && file->f_flags & O_CREAT)) {

        u64 tgid_kpid = bpf_get_current_pid_tgid();
        u32 tgid = tgid_kpid >> 32;
        if (exclude_tgid(tgid)) {
            return 0;
        }

        if (_want_inode(path->dentry->d_inode)) {
            int idx = 0;
            int zero = 0;
            ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
            /* BPF enforces that we check if zeroed_event is NULL */
            if (zeroed_event) {
                ebpf_path_event_t *event;
                u32 kpid = tgid_kpid & 0xffffffff;

                loop_event_p.update(&idx, zeroed_event);
                event = loop_event_p.lookup(&idx);
                if (event) {
                    event->event_info.timestamp_ns = timestamp_ns;
                    event->event_info.fn = EBPF_FN_FILE_CREATE;
                    event->event_info.tgid = tgid;
                    _set_dentry_event(path->dentry->d_inode, path->dentry, &event->event_info);
                    path_lookup_depth.update(&idx, &zero); // reset tail depth
                    programs_table.call(ctx, PATH_LOOP_PROG);
                }
            }
        }
    }

    return 0;
}

/**
 * vfs_symlink - create symlink
 * @mnt_userns:	user namespace of the mount the inode was found from
 * @dir: inode of @dentry
 * @dentry: pointer to dentry of the base directory
 * @oldname: name of the file to link to
 */
int vfs_symlink_probe(struct pt_regs *ctx,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
                      struct user_namespace *mnt_userns,
#endif
                      struct inode *dir,
                      struct dentry *dentry,
                      const char *oldname)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_kpid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    if (_want_inode(dir)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_kpid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_FILE_CREATE;
                event->event_info.tgid = tgid;
                _set_dentry_event(dir, dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }

    return 0;
}

static bool _is_unique_read_event(ebpf_unique_file_event_t *read_event)
{
    u64 ts = bpf_ktime_get_ns();
    u64 *val = recent_read_events.lookup(read_event);
    if (val) {
        if (_has_ttl_expired(ts, *val)) {
            recent_read_events.update(read_event, &ts);
        } else {
            return false;
        }
    } else {
        recent_read_events.insert(read_event, &ts);
    }
    return true;
}

int vfs_read_probe(struct pt_regs *ctx,
                   struct file *file,
                   const char __user *buf,
                   size_t count,
                   loff_t *pos)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    struct inode *dir = file->f_inode;
    struct dentry *dentry = file->f_path.dentry;
    dev_t dev = dir->i_sb->s_dev;

    /* Read events are very noisy so perform some filtering.
     * Drop the event if it isn't "unique". */
    ebpf_unique_file_event_t read_event;
    _populate_unique_file_event(&read_event, dir->i_ino, tgid, dev);
    if (!_is_unique_read_event(&read_event)) {
        return 0;
    }

    if (_want_inode(dir)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_pid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_VFS_READ;
                event->event_info.tgid = tgid;
                _set_dentry_event(dir, dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }

    return 0;
}

int do_mmap_probe(struct pt_regs *ctx,
                  struct file *file,
                  unsigned long addr,
                  unsigned long len,
                  unsigned long prot,
                  unsigned long flags)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    struct inode *dir = file->f_inode;
    struct dentry *dentry = file->f_path.dentry;
    if (is_excluded_do_mmap(dir->i_sb->s_dev, dir->i_ino)) {
        return 0;
    }

    if (_is_executable_memory_map(prot) && _want_inode(dir)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_pid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_DO_MMAP;
                event->event_info.tgid = tgid;
                _set_dentry_event(dir, dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }
    return 0;
}

int vfs_link_probe(struct pt_regs *ctx,
                   struct dentry *old_dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
                   struct user_namespace *mnt_userns,
#endif
                   struct inode *dir,
                   struct dentry *new_dentry,
                   struct inode **delegated_inode)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_kpid >> 32;
    if (exclude_tgid(tgid)) {
        return 0;
    }

    if (_want_inode(dir)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_kpid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_FILE_CREATE;
                event->event_info.tgid = tgid;
                _set_dentry_event(dir, new_dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }

    return 0;
}

int __fput_probe(struct pt_regs *ctx, struct file *file)
{
    u64 timestamp_ns = bpf_ktime_get_ns();
    u64 tgid_kpid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_kpid >> 32;

    if (exclude_tgid(tgid)) {
        return 0;
    }

    const struct path *path = &file->f_path;
    if (file->f_mode & FMODE_WRITE && _want_inode(path->dentry->d_inode)) {
        int idx = 0;
        int zero = 0;
        ebpf_path_event_t *zeroed_event = zeroed_path_event_arr.lookup(&idx);
        /* BPF enforces that we check if zeroed_event is NULL */
        if (zeroed_event) {
            ebpf_path_event_t *event;
            u32 kpid = tgid_kpid & 0xffffffff;

            loop_event_p.update(&idx, zeroed_event);
            event = loop_event_p.lookup(&idx);
            if (event) {
                event->event_info.timestamp_ns = timestamp_ns;
                event->event_info.fn = EBPF_FN_FILE_CLOSE_WRITE;
                event->event_info.tgid = tgid;
                _set_dentry_event(path->dentry->d_inode, path->dentry, &event->event_info);
                path_lookup_depth.update(&idx, &zero); // reset tail depth
                programs_table.call(ctx, PATH_LOOP_PROG);
            }
        }
    }
    return 0;
}