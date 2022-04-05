#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define MAX_ENTRIES 10240
#define BPF_MAX_STACK_DEPTH 127
#define TASK_COMM_LEN 16

#define PAGE_SIZE 4096

struct alloc_info_t {
	__u32 pid;
	__u32 tgid;
	char comm[TASK_COMM_LEN];
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
	int kern_stack_id;
	int user_stack_id;
};

struct combined_alloc_info_t {
	__u64 total_size;
	__u64 number_of_allocs;
};

struct alloc_stack {
	uint64_t stack_id;
	int size;
	int nr;
};

#endif
