//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 128);
	__type(key, __u32); // Either 0 or 1 in this example
	__type(value, __u64); // Socket FD
} tcp_balancing_targets SEC(".maps");


SEC("sk_reuseport/selector")
enum sk_action hot_standby_selector(struct sk_reuseport_md *reuse) {
    enum sk_action action;
    __u32 built_in_key = 0, fall_back_key = 1;

    if (reuse->ip_protocol != IPPROTO_TCP) {
        return SK_DROP;
    }

    // Invoke kernel helper sk_select_reuseport to select socket by index from reuseport sockarray
    if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &built_in_key, 0) == 0) {
        action = SK_PASS;
    } else if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &fall_back_key, 0) == 0) {
        action = SK_PASS;
    } else {
        action = SK_DROP;
    }

    return action;
}

char _license[] SEC("license") = "GPL";