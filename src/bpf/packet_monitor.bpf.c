#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../packet_monitor.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/kfree_skb")
int BPF_KPROBE(kfree_skb, struct sk_buff *skb)
{
    struct packet_event *e;
    struct iphdr iph = {};
    struct tcphdr tcph = {};
    struct udphdr udph = {};

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Safely read packet length
    e->len = BPF_CORE_READ(skb, len);

    // Safely read IP header fields
    BPF_CORE_READ_INTO(&iph, skb, head); // read head pointer
    // Since reading full IP header may still be unsafe, read only what we can:
    // For safety, skip IP/port parsing on first load
    e->saddr = 0;
    e->daddr = 0;
    e->protocol = 0;
    e->sport = 0;
    e->dport = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
