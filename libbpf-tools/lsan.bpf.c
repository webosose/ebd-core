#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "lsan.h"

#define MAX_ENTRIES	10248

const volatile bool kernel_threads_only = false;
const volatile bool user_threads_only = false;
const volatile pid_t targ_tgid = -1;
const volatile pid_t targ_pid = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u64);
	__type(value, u64);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1000000);
	__type(key, u64);
	__type(value, struct lsan_info_t);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, u64);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stack_traces SEC(".maps");

SEC("tracepoint/kmem/kmalloc")
int tracepoint__kmem__kmalloc(struct trace_event_raw_kmem_alloc *args)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
