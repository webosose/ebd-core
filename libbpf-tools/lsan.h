#ifndef __LSAN_H
#define __LSAN_H

enum chunk_tag {
	DIRECTLY_LEAKED = 0,  // default
	INDIRECTLY_LEAKED = 1,
	REACHABLE = 2,
	IGNORED = 3
};

struct lsan_info_t {
	__u64 size;
	int stack_id;
	enum chunk_tag tag;
};

#endif /* __LSAN_H */
