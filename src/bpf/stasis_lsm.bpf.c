#include "include/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 256

#define PROC_SUPER_MAGIC 0x9FA0
#define SYSFS_MAGIC 0x62656572
#define TMPFS_MAGIC 0x01021994
#define DEVPTS_SUPER_MAGIC 0x1CD1
#define CGROUP_SUPER_MAGIC 0x27E0EB
#define CGROUP2_SUPER_MAGIC 0x63677270
#define BPF_FS_MAGIC 0xCAFE4A11
#define ANON_INODE_FS_MAGIC 0x09041901

struct rb_fopen_sample {
  u32 pid;
  u32 flags;               // open flags
  u64 timestamp;           // bpf_ktime_get_ns()
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

/* note: I did try to use 'BPF_MAP_TYPE_LPM_TRIE' for longest prefix
   matching, as it would be infinitely more efficient, but that
   doesn't work unfortunately. This is due to the fact that in order
   to get the file path with 'bpf_d_path()' we need our file_open-hook
   to be sleepable. Unfortunately 'BPF_MAP_TYP_LPM_TRIE' doesn't
   support sleepable execution. */

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 32);
  __uint(key_size, sizeof(u32));
  __uint(value_size, MAX_PATH_LEN);
} ignored_prefixes SEC(".maps");

static __always_inline bool str_has_prefix(const char *str, const char *pfx) {
  for (int i = 0; i < MAX_PATH_LEN; i++) {
    if (pfx[i] == '\0')
      return true; // Reached end of prefix, it's a match!
    if (str[i] != pfx[i])
      return false;
  }
  return false;
}

static inline bool is_virtual_fs(struct file *file) {
  unsigned long magic = BPF_CORE_READ(file, f_path.dentry, d_sb, s_magic);

  switch (magic) {
  case PROC_SUPER_MAGIC:
  case SYSFS_MAGIC:
  case TMPFS_MAGIC:
  case DEVPTS_SUPER_MAGIC:
  case CGROUP_SUPER_MAGIC:
  case CGROUP2_SUPER_MAGIC:
  case BPF_FS_MAGIC:
  case ANON_INODE_FS_MAGIC:
    return true;
  default:
    return false;
  }
}

static bool contains_dot_cache(const char *str) {
  // pattern is "/.cache/" (8 chars)
  for (int i = 0; i < MAX_PATH_LEN - 7; i++) {
    // we stop when there are fewer than 8 chars left
    if (str[i] == '\0' || str[i + 7] == '\0')
      break;

    // pattern matching
    if (str[i] == '/' && str[i + 1] == '.' && str[i + 2] == 'c' &&
        str[i + 3] == 'a' && str[i + 4] == 'c' && str[i + 5] == 'h' &&
        str[i + 6] == 'e' && str[i + 7] == '/') {
      return true;
    }
  }
  return false;
}

struct loop_ctx {
  const char *path;
  bool matched;
};

// verified in isolation, won't kill complexity
static int check_prefix_cb(u32 index, void *data) {
  struct loop_ctx *ctx = data;
  u32 key = index;

  char *prefix = bpf_map_lookup_elem(&ignored_prefixes, &key);
  if (!prefix || prefix[0] == '\0')
    return 0; // continue to next index

  if (str_has_prefix(ctx->path, prefix)) {
    ctx->matched = true;
    return 1; // break loop early
  }

  return 0; // continue loop
}

static bool should_ignore_path(const char *path) {
  if (path[0] == '\0')
    return true;

  struct loop_ctx ctx = {.path = path, .matched = false};

  // run the loop 32 times using the helper
  bpf_loop(32, check_prefix_cb, &ctx, 0);

  if (ctx.matched)
    return true;

  return contains_dot_cache(path);
}

SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file) {
  struct rb_fopen_sample *sample;
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // whitelist / blacklist checks
  if (bpf_map_lookup_elem(&whitelist, &pid))
    return 0;

  if (bpf_map_lookup_elem(&blacklist, &pid))
    return -1;

  // superblock check
  if (is_virtual_fs(file)) {
    return 0;
  }

  // allocate 256 bytes on the stack for the resolved path
  char fpath_buf[MAX_PATH_LEN] = {0};

  // resolve path directly into our buffer
  long ret = bpf_d_path(&file->f_path, fpath_buf, sizeof(fpath_buf));
  if (ret < 0) {
    bpf_printk("file_open: bpf_d_path failed, ret=%ld\n", ret);
    return 0;
  }

  // run matching logic (checks dynamic array + contains_dot_cache)
  if (should_ignore_path(fpath_buf))
    return 0;

  bpf_printk("[DBG] file_open: fpath=%s\n", fpath_buf);

  // reserve space in ring buffer
  sample = bpf_ringbuf_reserve(&event_rb, sizeof(struct rb_fopen_sample), 0);
  if (!sample) {
    return 0;
  }

  sample->pid = pid;
  sample->flags = file->f_flags;
  sample->timestamp = bpf_ktime_get_ns();
  bpf_probe_read_str(sample->path, sizeof(sample->path), fpath_buf);

  bpf_ringbuf_submit(sample, 0);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
