#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "packet_monitor.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct packet_event *e = data;
    struct in_addr saddr, daddr;
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    
    saddr.s_addr = e->saddr;
    daddr.s_addr = e->daddr;
    inet_ntop(AF_INET, &saddr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &daddr, dst_ip, INET_ADDRSTRLEN);
    
    printf("[%llu] PID: %d, COMM: %s\n", e->timestamp, e->pid, e->comm);
    printf("  %s:%d -> %s:%d, Proto: %d, Len: %d\n",
           src_ip, ntohs(e->sport), dst_ip, ntohs(e->dport),
           e->protocol, e->len);
    
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_program *prog;
    int map_fd, prog_fd, err;

    obj = bpf_object__open_file("packet_monitor.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        obj = NULL;
        goto cleanup;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // In libbpf 1.3, there is no bpf_object__attach().
    // We must manually iterate and attach programs.
    bpf_object__for_each_program(prog, obj) {
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "Failed to get program FD\n");
            goto cleanup;
        }

        // Attach to appropriate hook — for example, TC or XDP.
        // Since original code didn’t specify, we just log.
        printf("Program %s loaded with FD %d (manual attach may be needed)\n",
               bpf_program__name(prog), prog_fd);
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find events map\n");
        goto cleanup;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Monitoring packet events... Press Ctrl+C to exit.\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    if (rb)
        ring_buffer__free(rb);
    if (obj)
        bpf_object__close(obj);
    return err < 0 ? 1 : 0;
}