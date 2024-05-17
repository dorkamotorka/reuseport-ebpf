//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 128);
	__type(key, __u32); // Either 0 or 1 in this example
	__type(value, __u64); // Socket FD
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_balancing_targets SEC(".maps");

// This function is called for each incoming packet for the reuseport group, 
// but only get's attached when we run primary program due to our user space logic
SEC("sk_reuseport/selector")
enum sk_action hot_standby_selector(struct sk_reuseport_md *reuse) {
    enum sk_action action;
    __u32 built_in_key = 0, fall_back_key = 1;

    if (reuse->ip_protocol != IPPROTO_TCP) {
        return SK_DROP;
    }

    bpf_printk("Selecting socket...");
    // Invoke kernel helper sk_select_reuseport to select socket by index from reuseport sockarray
    // Select a SO_REUSEPORT socket from a BPF_MAP_TYPE_REUSEPORT_SOCKARRAY map.  
    // It checks the selected socket is matching the incoming request in the socket buffer.
    // In general it should match both sockets if they are present (listening), but the "primary" takes precedence, just because it is the first in the if statement.
    // This is intentional, as we want to have a primary socket and a fallback socket for showcasing the hot standby.
    if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &built_in_key, 0) == 0) {
        bpf_printk("Selected primary socket\n");
        action = SK_PASS;
    } else if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &fall_back_key, 0) == 0) {
        bpf_printk("Selected fallback socket\n");
        action = SK_PASS;
    } else {
        action = SK_DROP;
    }

    return action;
}

char _license[] SEC("license") = "GPL";