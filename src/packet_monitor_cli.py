#!/usr/bin/env python3
from bcc import BPF
import socket
import struct
import argparse
from datetime import datetime

program = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct packet_event {
    u64 timestamp;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 protocol;
    u32 len;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct packet_event data = {};
    
    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Read IP header
    unsigned char *head;
    u16 network_header;
    bpf_probe_read(&head, sizeof(head), &skb->head);
    bpf_probe_read(&network_header, sizeof(network_header), &skb->network_header);
    
    struct iphdr iph;
    bpf_probe_read(&iph, sizeof(iph), head + network_header);
    
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;
    data.len = skb->len;
    
    // Read transport header
    u16 transport_header;
    bpf_probe_read(&transport_header, sizeof(transport_header), &skb->transport_header);
    
    if (data.protocol == IPPROTO_TCP) {
        struct tcphdr tcph;
        bpf_probe_read(&tcph, sizeof(tcph), head + transport_header);
        data.sport = tcph.source;
        data.dport = tcph.dest;
    } else if (data.protocol == IPPROTO_UDP) {
        struct udphdr udph;
        bpf_probe_read(&udph, sizeof(udph), head + transport_header);
        data.sport = udph.source;
        data.dport = udph.dest;
    }
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    src_ip = socket.inet_ntoa(struct.pack("I", event.saddr))
    dst_ip = socket.inet_ntoa(struct.pack("I", event.daddr))
    
    protocol_map = {6: "TCP", 17: "UDP"}
    proto = protocol_map.get(event.protocol, str(event.protocol))
    
    timestamp = datetime.fromtimestamp(event.timestamp / 1e9)
    
    print(f"[{timestamp}] PID: {event.pid}, COMM: {event.comm.decode('utf-8', 'replace')}")
    print(f"  {src_ip}:{socket.ntohs(event.sport)} -> {dst_ip}:{socket.ntohs(event.dport)}")
    print(f"  Protocol: {proto}, Length: {event.len} bytes\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor packet drops using eBPF")
    args = parser.parse_args()
    
    print("Loading eBPF program...")
    b = BPF(text=program)
    
    b["events"].open_perf_buffer(print_event)
    
    print("Monitoring packet drops... Press Ctrl+C to exit.")
    
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting...")
