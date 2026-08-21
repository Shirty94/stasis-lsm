#include <vmlinux.h>

#define SEC(name) __attribute__((section(name)))

SEC("lsm/file_open")
int my_lsm_prog(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
