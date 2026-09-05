#include <uapi/linux/ptrace.h>
#include <linux/types.h>

#define TASK_COMM_LEN 16

struct flow_event_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  direction;
    u64 bytes;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(flow_events);

// Minimal binary layout of struct sock_common matching Linux 5.x / 6.x kernels
struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        unsigned int skc_hash;
        __u16 skc_u16hashes[2];
    };
    union {
        struct {
            __be16 skc_dport;
            __u16  skc_num;
        };
    };
    unsigned short skc_family;
};

struct sock {
    struct sock_common __sk_common;
};

static __always_inline void submit_flow(
    struct pt_regs *ctx,
    struct sock *sk,
    size_t size,
    u8 proto,
    u8 direction
) {
    if (sk == NULL || size <= 0) {
        return;
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) {
        return; // Ignore kernel idle tasks
    }

    struct flow_event_t evt = {};
    evt.pid = pid;
    evt.proto = proto;
    evt.direction = direction;
    evt.bytes = size;

    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&evt.sport, sizeof(evt.sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&evt.dport, sizeof(evt.dport), &sk->__sk_common.skc_dport);
    evt.dport = __builtin_bswap16(evt.dport);

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    flow_events.perf_submit(ctx, &evt, sizeof(evt));
}

// Intercept TCP Outgoing Data
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, void *msg, size_t size) {
    submit_flow(ctx, sk, size, 6, 0);
    return 0;
}

// Intercept TCP Incoming Data
int trace_tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (copied > 0) {
        submit_flow(ctx, sk, (size_t)copied, 6, 1);
    }
    return 0;
}

// Intercept UDP Outgoing Data
int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, void *msg, size_t len) {
    submit_flow(ctx, sk, len, 17, 0);
    return 0;
}
