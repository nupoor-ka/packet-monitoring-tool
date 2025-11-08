#!/usr/bin/env python3
from bcc import BPF
import socket
import struct
import argparse
from datetime import datetime

# Output file
OUTPUT_FILE = "/home/vyomika_vasireddy/packet_drops.log"

# eBPF program
program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>

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

int kprobe__netif_receive_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct packet_event data = {};

    if (!skb)
        return 0;

    // Metadata
    data.timestamp = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // IP header
    struct iphdr iph = {};
    if (bpf_probe_read_kernel(&iph, sizeof(iph), (void *)(skb->head + skb->network_header)))
        return 0;

    data.saddr = iph.saddr;
    data.daddr = iph.daddr;
    data.protocol = iph.protocol;

    // Transport header
    data.sport = 0;
    data.dport = 0;

    if (data.protocol == IPPROTO_TCP) {
        struct tcphdr tcph = {};
        if (bpf_probe_read_kernel(&tcph, sizeof(tcph), (void *)(skb->head + skb->transport_header)) == 0) {
            data.sport = tcph.source;
            data.dport = tcph.dest;
        }
    } else if (data.protocol == IPPROTO_UDP) {
        struct udphdr udph = {};
        if (bpf_probe_read_kernel(&udph, sizeof(udph), (void *)(skb->head + skb->transport_header)) == 0) {
            data.sport = udph.source;
            data.dport = udph.dest;
        }
    }

    data.len = skb->len;

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)

    # Convert IP addresses
    src_ip = socket.inet_ntoa(struct.pack("<I", event.saddr))
    dst_ip = socket.inet_ntoa(struct.pack("<I", event.daddr))

    protocol_map = {6: "TCP", 17: "UDP"}
    proto = protocol_map.get(event.protocol, str(event.protocol))

    timestamp = datetime.fromtimestamp(event.timestamp / 1e9)

    log_line = (
        f"[{timestamp}] PID: {event.pid}, COMM: {event.comm.decode('utf-8', 'replace')}\n"
        f"  {src_ip}:{socket.ntohs(event.sport)} -> {dst_ip}:{socket.ntohs(event.dport)}\n"
        f"  Protocol: {proto}, Length: {event.len} bytes\n\n"
    )

    # Append to file
    with open(OUTPUT_FILE, "a") as f:
        f.write(log_line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor incoming packets using eBPF")
    args = parser.parse_args()

    print(f"Loading eBPF program... Logging to {OUTPUT_FILE}")
    b = BPF(text=program)

    b["events"].open_perf_buffer(print_event)

    print("Monitoring packets... Press Ctrl+C to exit.")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nExiting...")
