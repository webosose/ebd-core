#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "vmlinux_defs.h"
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
	__uint(max_entries, MAX_ENTRIES);
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

static __always_inline
int gen_alloc_enter(struct pt_regs *ctx, size_t size)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 size64 = size;
	bpf_map_update_elem(&sizes, &pid, &size64, BPF_OK);
	return 0;
}

static __always_inline
int gen_alloc_exit2(struct pt_regs *ctx, u64 address)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 *size64 = bpf_map_lookup_elem(&sizes, &pid);
	struct lsan_info_t info = {0};

	if (size64 == 0)
		return 0;

	info.size = *size64;
	bpf_map_delete_elem(&sizes, &pid);
	if (address != 0) {
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
		info.tag = DIRECTLY_LEAKED;
		bpf_map_update_elem(&allocs, &address, &info, BPF_OK);
	}
	return 0;
}

static __always_inline
int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static __always_inline
int gen_free_enter(struct pt_regs *ctx, void *address)
{
	u64 addr = (u64)address;
	struct lsan_info_t *info = bpf_map_lookup_elem(&allocs, &addr);
	if (info == NULL)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);
	return 0;
}

SEC("kprobe/dummy_malloc")
int BPF_KPROBE(malloc_entry, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("kretprobe/dummy_malloc")
int BPF_KPROBE(malloc_return)
{
	return gen_alloc_exit(ctx);
}

SEC("kprobe/dummy_free")
int BPF_KPROBE(free_entry, void *address)
{
	return gen_free_enter(ctx, address);
}

SEC("kprobe/dummy_calloc")
int BPF_KPROBE(calloc_entry, size_t nmemb, size_t size)
{
	return gen_alloc_enter(ctx, nmemb * size);
}

SEC("kretprobe/dummy_calloc")
int BPF_KPROBE(calloc_return)
{
	return gen_alloc_exit(ctx);
}

SEC("kprobe/dummy_realloc")
int BPF_KPROBE(realloc_entry, void *ptr, size_t size)
{
	gen_free_enter(ctx, ptr);
	return gen_alloc_enter(ctx, size);
}

SEC("kretprobe/dummy_realloc")
int BPF_KPROBE(realloc_return)
{
	return gen_alloc_exit(ctx);
}

SEC("kprobe/dummy_posix_memalign")
int BPF_KPROBE(posix_memalign_entry, void **memptr, size_t alignment, size_t size)
{
	u64 memptr64 = (u64)(size_t)memptr;
	u64 pid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_OK);
	return gen_alloc_enter(ctx, size);
}

SEC("kretprobe/dummy_posix_memalign")
int BPF_KPROBE(posix_memalign_return)
{
	u64 pid = bpf_get_current_pid_tgid();
	u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	void *addr;
	if (memptr64 == 0)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);
	if (bpf_probe_read_user(&addr, sizeof(void *), (void *)(size_t)*memptr64))
		return 0;

	u64 addr64 = (u64)(size_t)addr;
	return gen_alloc_exit2(ctx, addr64);
}

SEC("kprobe/dummy_aligned_alloc")
int BPF_KPROBE(aligned_alloc_entry, size_t alignment, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("kretprobe/dummy_aligned_alloc")
int BPF_KPROBE(aligned_alloc_return)
{
	return gen_alloc_exit(ctx);
}

SEC("kprobe/dummy_valloc")
int BPF_KPROBE(valloc_entry, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("kretprobe/dummy_valloc")
int BPF_KPROBE(valloc_return)
{
	return gen_alloc_exit(ctx);
}

SEC("kprobe/dummy_memalign")
int BPF_KPROBE(memalign_entry, size_t alignment, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("kretprobe/dummy_memalign")
int BPF_KPROBE(memalign_return)
{
	return gen_alloc_exit(ctx);
}

SEC("kprobe/dummy_pvalloc")
int BPF_KPROBE(pvalloc_entry, size_t size)
{
	return gen_alloc_enter(ctx, size);
}

SEC("kretprobe/dummy_pvalloc")
int BPF_KPROBE(pvalloc_return)
{
	return gen_alloc_exit(ctx);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
