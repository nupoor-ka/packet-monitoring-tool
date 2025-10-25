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
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read network header
    iph = (struct iphdr *)(skb->head + skb->network_header);
    BPF_CORE_READ_INTO(&e->saddr, iph, saddr);
    BPF_CORE_READ_INTO(&e->daddr, iph, daddr);
    BPF_CORE_READ_INTO(&e->protocol, iph, protocol);

    // Read transport layer ports
    if (e->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)(skb->head + skb->transport_header);
        BPF_CORE_READ_INTO(&e->sport, tcph, source);
        BPF_CORE_READ_INTO(&e->dport, tcph, dest);
    } else if (e->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)(skb->head + skb->transport_header);
        BPF_CORE_READ_INTO(&e->sport, udph, source);
        BPF_CORE_READ_INTO(&e->dport, udph, dest);
    }

    e->len = BPF_CORE_READ(skb, len);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
