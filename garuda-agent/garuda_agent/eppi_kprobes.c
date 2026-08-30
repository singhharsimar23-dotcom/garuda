/*
 * GARUDA EPPI (Endpoint Process Provenance Identifier) eBPF Kprobes Program
 * Intercepts sys_execve, sys_connect, sys_mmap (PROT_EXEC), and sys_clone/fork
 * Compatible with Linux kernels 5.4, 5.10, 5.15, 6.1, 6.6
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16
#define MAX_ARGV_LEN 64

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_CONNECT = 2,
    EVENT_MMAP_EXEC = 3,
    EVENT_CLONE = 4,
    /*
     * VIBEWARE C2 CHANNEL DETECTION
     * APT36 "vibeware" pivot (Bitdefender, March 2026):
     * C2 channels are Discord, Slack, Supabase, Firebase.
     * These are legitimate services — their presence on a DRDO/NIC host = high anomaly.
     *
     * Detection approach: DNS hostname matching via SNI extraction from TLS ClientHello.
     * In the existing tcp_connect kprobe, AFTER emitting the base CONNECT event,
     * match SNI against vibeware C2 domain patterns.
     *
     * VERIFY: SNI extraction from TLS ClientHello at tcp_connect kprobe level
     * requires reading sk_buff data. This is eBPF-compatible but requires
     * BCC >= 0.26 and kernel >= 5.15. Check target kernel version first.
     *
     * Python-side classification in garuda_agent/eppi.py handles hostname
     * resolution via reverse DNS as the userspace fallback path.
     */
    EVENT_VIBEWARE_C2_DISCORD  = 0x08,  /* CONNECT to discord.com / discordapp.com */
    EVENT_VIBEWARE_C2_SUPABASE = 0x09,  /* CONNECT to *.supabase.co */
    EVENT_VIBEWARE_C2_FIREBASE = 0x0A,  /* CONNECT to *.firebaseio.com */
    EVENT_VIBEWARE_C2_SLACK    = 0x0B,  /* CONNECT to slack.com / files.slack.com */
};

struct eppi_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 event_type;
    u64 timestamp_ns;
    char comm[TASK_COMM_LEN];
    char filename[MAX_ARGV_LEN];
    u32 remote_addr;
    u16 remote_port;
    u16 protocol;
    u64 mmap_addr;
    u64 mmap_len;
    u32 mmap_prot;
    u32 mmap_flags;
    u64 clone_flags;
};

BPF_PERF_OUTPUT(eppi_events);

// 1. Intercept sys_execve (Process Execution & Arguments)
int kprobe__sys_execve(struct pt_regs *ctx,
                       const char __user *filename,
                       const char __user *const __user *argv,
                       const char __user *const __user *envp) {
    struct eppi_event_t evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    evt.pid = id >> 32;
    evt.uid = bpf_get_current_uid_gid();
    evt.gid = bpf_get_current_uid_gid() >> 32;
    evt.event_type = EVENT_EXECVE;
    evt.timestamp_ns = bpf_ktime_get_ns();

    bpf_probe_read_kernel(&evt.ppid, sizeof(evt.ppid), &task->real_parent->tgid);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), filename);

    eppi_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// 2. Intercept sys_connect (Network C2 Sockets)
int kprobe__sys_connect(struct pt_regs *ctx, int fd, struct sockaddr __user *uservaddr, int addrlen) {
    struct eppi_event_t evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    evt.pid = id >> 32;
    evt.event_type = EVENT_CONNECT;
    evt.timestamp_ns = bpf_ktime_get_ns();

    bpf_probe_read_kernel(&evt.ppid, sizeof(evt.ppid), &task->real_parent->tgid);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    struct sockaddr_in sin = {};
    if (addrlen >= sizeof(sin)) {
        bpf_probe_read_user(&sin, sizeof(sin), uservaddr);
        if (sin.sin_family == AF_INET) {
            evt.remote_addr = sin.sin_addr.s_addr;
            evt.remote_port = (sin.sin_port >> 8) | ((sin.sin_port & 0xff) << 8); // ntohs
            evt.protocol = 6; // TCP
        }
    }

    eppi_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// 3. Intercept sys_mmap with PROT_EXEC (Process Hollowing T1055.012 & Dynamic Code Injection T1055.001)
int kprobe__sys_mmap(struct pt_regs *ctx, unsigned long addr, unsigned long len,
                     unsigned long prot, unsigned long flags,
                     unsigned long fd, unsigned long offset) {
    if (!(prot & PROT_EXEC)) {
        return 0;
    }

    struct eppi_event_t evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    evt.pid = id >> 32;
    evt.event_type = EVENT_MMAP_EXEC;
    evt.timestamp_ns = bpf_ktime_get_ns();

    bpf_probe_read_kernel(&evt.ppid, sizeof(evt.ppid), &task->real_parent->tgid);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    evt.mmap_addr = addr;
    evt.mmap_len = len;
    evt.mmap_prot = prot;
    evt.mmap_flags = flags;

    eppi_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// 4. Intercept sys_clone (Process Forking / Spawning)
int kprobe__sys_clone(struct pt_regs *ctx, unsigned long clone_flags) {
    struct eppi_event_t evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u64 id = bpf_get_current_pid_tgid();
    evt.pid = id >> 32;
    evt.event_type = EVENT_CLONE;
    evt.timestamp_ns = bpf_ktime_get_ns();

    bpf_probe_read_kernel(&evt.ppid, sizeof(evt.ppid), &task->real_parent->tgid);
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.clone_flags = clone_flags;

    eppi_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
