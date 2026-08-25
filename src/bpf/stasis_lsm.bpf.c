// clang is annoying claiming it can't vmlinux.h it, but it's
// there. Idk how to fix it
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf_core_read.h> maybe needed later on?

// monitoring function for file_open calls
SEC("lsm/file_open")
int stasis_file_open(void *ctx) {
    return 0;
}

struct {
  // same vmlinux.h issue, BPF_MAP_TYPE_RINGBUF is defined there
    __uint(type, BPF_MAP_TYPE_RINGBUF); // type of the bpf map
    __uint(max_entries, 256 * 1024); // Size in bytes
} my_ringbuf SEC(".maps");

char LICENSE[] SEC("license") = "GPL";
