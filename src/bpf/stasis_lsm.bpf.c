#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h> maybe needed later on?

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF); // type of the bpf map
  __uint(max_entries, 256 * 1024);    // Size in bytes
} pid_ringbuf SEC(".maps");

// monitoring function for file_open calls
SEC("lsm/file_open")
int stasis_file_open(void *ctx) {
  int *sample;
  int pid;

  // reserve space for a single integer (4 bytes) in the ring buffer
  sample = bpf_ringbuf_reserve(&pid_ringbuf, sizeof(int), 0);
  if (!sample) {
    // Ring buffer is full - drop this event
    return 0;
  }

  // get the current process ID
  // bpf_get_current_pid_tgid() returns (PID << 32) | TGID
  pid = bpf_get_current_pid_tgid() >> 32;

  // write the PID into the reserved space
  *sample = pid;

  // submit the sample to userspace
  bpf_ringbuf_submit(sample, 0);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
