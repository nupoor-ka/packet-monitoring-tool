#ifndef __PACKET_MONITOR_H
#define __PACKET_MONITOR_H

#define TASK_COMM_LEN 16

struct packet_event {
    __u64 timestamp;
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u32 len;
    char comm[TASK_COMM_LEN];
};

#endif /* __PACKET_MONITOR_H */
