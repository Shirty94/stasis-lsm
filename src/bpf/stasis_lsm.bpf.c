#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf_core_read.h> maybe needed later on?

#define MAX_PATH_LEN 256

struct rb_fopen_sample {
    u32 pid;
    u32 flags; // open flags
    u64 timestamp; // bpf_ktime_get_ns()
    char path[MAX_PATH_LEN]; // full path
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF); // type of the bpf map
  __uint(max_entries, 256 * 1024);    // size in bytes
} event_rb SEC(".maps");

// ignore whitelisted processes entirely
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u8));
} whitelist SEC(".maps");

// block blacklisted processes
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  // honestly way too many for the bl, but it's just 200KB, acceptable for a
  // prototype
  __uint(max_entries, 10240);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u8));
} blacklist SEC(".maps");

static bool str_has_prefix(const char *str, const char *pfx)
{
  // Check up to MAX_PATH_LEN. If we hit a null byte, the loop stops.
  for (int i = 0; i < MAX_PATH_LEN; i++) {
    if (pfx[i] == '\0')
      return true; // reached end of prefix, matched completely
    if (str[i] != pfx[i])
      return false; // end of string or mismatch
  }
  return false; // should not be reached if strings are valid
}

static bool contains_dot_cache(const char *str)
{
  // pattern is "/.cache/" (8 chars)
  for (int i = 0; i < MAX_PATH_LEN - 7; i++) {
    // we stop when there are fewer than 8 chars left
    if (str[i] == '\0' || str[i + 7] == '\0')
      break;

    // pattern matching
    if (str[i] == '/' &&
        str[i+1] == '.' &&
        str[i+2] == 'c' &&
        str[i+3] == 'a' &&
        str[i+4] == 'c' &&
        str[i+5] == 'h' &&
        str[i+6] == 'e' &&
        str[i+7] == '/') {
      return true;
    }
  }
  return false;
}

static bool should_ignore_path(const char *path)
{
  // directories to ignore entirely (simple prefix check)
  const char *ignore_prefixes[] = {
    "/tmp",
    "/dev",
    "/proc",
    "/sys",
    "/run",
    "/var/cache",
    "anon_inode",
    "/mnt/c", // ignore WSL stuff for now
  };

  if (path[0] == '\0')
    return true;

  // match prefixes
  for (int i = 0; i < sizeof(ignore_prefixes)/sizeof(ignore_prefixes[0]); i++) {
    if (str_has_prefix(path, ignore_prefixes[i]) == 1)
      return true;
  }

  // ignore cache files
  if (contains_dot_cache(path) == 1)
    return true;

  return false;
}

// monitoring function for file_open calls
SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file) {
  // initialize sample
  struct rb_fopen_sample *sample;
  char fpath_buf[MAX_PATH_LEN];
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // if process is whitelisted: ignore it
  if (bpf_map_lookup_elem(&whitelist, &pid))
    return 0;

  // if process is blacklisted: block it's execution
  if (bpf_map_lookup_elem(&blacklist, &pid))
    return -1;

  long ret = bpf_d_path(&file->f_path, fpath_buf, sizeof(fpath_buf));
  if (ret < 0) {
    bpf_printk("file_open: bpf_d_path failed, ret=%ld\n", ret);
    return 0; // path resolution failed
  }

  if (should_ignore_path(fpath_buf))
    return 0;

  /* if (str_has_prefix(fpath_buf, "/proc/")) */
  /*   bpf_printk("file_open proc: fpath=%s\n", fpath_buf); */

  bpf_printk("[DBG] file_open: fpath=%s\n", fpath_buf);

  // reserve space for our sample
  sample = bpf_ringbuf_reserve(&event_rb, sizeof(struct rb_fopen_sample), 0);
  if (!sample) {
    // ring buffer full -> drop
    return 0;
  }

  // get current PID
  // bpf_get_current_pid_tgid() returns (PID << 32) | TGID
  sample->pid = pid;
  sample->flags = file->f_flags;
  sample->timestamp = bpf_ktime_get_ns();
  bpf_probe_read_str(sample->path, sizeof(sample->path), fpath_buf);

  // submit sample to userspace
  bpf_ringbuf_submit(sample, 0);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
