#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_core_read.h> maybe needed later on?

SEC("lsm/file_open")
int my_lsm_prog(void *ctx) {
    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // type of the bpf map
    __uint(max_entries, 256 * 1024); // Size in bytes
} my_ringbuf SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
