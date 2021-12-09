#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define BPF_MAX_STACK_DEPTH 127
#define TASK_COMM_LEN		16

struct alloc_info_t {
        __u64 size;
        __u64 timestamp_ns;
        int stack_id;
};

struct combined_alloc_info_t {
        __u64 total_size;
        __u64 number_of_allocs;
};

struct bpf_stacktrace {
        __u64 ip[BPF_MAX_STACK_DEPTH];
};

#endif
