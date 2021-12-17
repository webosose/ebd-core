#ifndef __LSAN_H
#define __LSAN_H

#define BPF_MAX_STACK_DEPTH	127
#define TASK_COMM_LEN	16

struct lsan_info_t {
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
};

#endif /* __LSAN_H */
