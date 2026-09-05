#ifndef __TRACKER_BPF_H__
#define __TRACKER_BPF_H__

#define TASK_COMM_LEN 16

enum traffic_direction_t {
    TRAFFIC_EGRESS = 0,
    TRAFFIC_INGRESS = 1
};

enum proto_type_t {
    PROTO_UNKNOWN = 0,
    PROTO_TCP = 6,
    PROTO_UDP = 17
};

struct flow_key_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  direction;
    u16 _pad;
};

struct flow_val_t {
    u64 bytes;
    u64 packets;
    u64 first_seen_ns;
    u64 last_seen_ns;
    char comm[TASK_COMM_LEN];
};

#endif
