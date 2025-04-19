//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); 
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_count_map SEC(".maps"); 

SEC("socket")
int packet_count(struct __sk_buff *skb) {
    //initial key
    __u32 key = 0;
    __u64 *count;

    //retireve current packet
    count = bpf_map_lookup_elem(&packet_count_map, &key);
    if (count) {
       __sync_fetch_and_add(count, 1); 
    } else {
        long initial_count = 1;
        bpf_map_update_elem(&packet_count_map, &key, &initial_count, BPF_ANY);    
    }
    
    return BPF_OK;
}
char __license[] SEC("license") = "Dual MIT/GPL";
