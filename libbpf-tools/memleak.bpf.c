/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, LG Electronics, Inc. */

#include <vmlinux.h>

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "vmlinux_defs.h"
#include "memleak.h"

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
	__type(value, struct alloc_info_t);
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct combined_alloc_info_t);
} combined_allocs SEC(".maps");

static __always_inline
void update_statistics_add(u64 stack_id, u64 sz)
{
	struct combined_alloc_info_t *existing_cinfo;
	struct combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo != 0)
		cinfo = *existing_cinfo;

	cinfo.total_size += sz;
	cinfo.number_of_allocs += 1;

	bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_OK);
}

static __always_inline
void update_statistics_del(u64 stack_id, u64 sz)
{
	struct combined_alloc_info_t *existing_cinfo;
	struct combined_alloc_info_t cinfo = {0};

	existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
	if (existing_cinfo != 0)
		cinfo = *existing_cinfo;

	if (sz >= cinfo.total_size)
		cinfo.total_size = 0;
	else
		cinfo.total_size -= sz;

	if (cinfo.number_of_allocs > 0)
		cinfo.number_of_allocs -= 1;

	bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_OK);
}

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
	struct alloc_info_t info = {0};

	if (size64 == 0)
		return 0;

	info.size = *size64;
	bpf_map_delete_elem(&sizes, &pid);

	if (address != 0) {
		info.pid = pid;
		bpf_get_current_comm(&info.comm, sizeof(info.comm));
		info.timestamp_ns = bpf_ktime_get_ns();
		info.kern_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
		info.user_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

		if (info.kern_stack_id > 0)
			info.stack_id = info.kern_stack_id;
		else
			info.stack_id = info.user_stack_id;

		bpf_map_update_elem(&allocs, &address, &info, BPF_OK);
		update_statistics_add(info.stack_id, info.size);
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
	struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &addr);

	if (info == 0)
		return 0;

	bpf_map_delete_elem(&allocs, &addr);
	update_statistics_del(info->stack_id, info->size);

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

SEC("tracepoint/kmem/kmalloc")
int tracepoint__kmem__kmalloc(struct trace_event_raw_kmem_alloc *args)
{
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

SEC("tracepoint/kmem/kmalloc_node")
int tracepoint__kmem__kmalloc_node(struct trace_event_raw_kmem_alloc_node *args)
{
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

SEC("tracepoint/kmem/kfree")
int tracepoint__kmem__kfree(struct trace_event_raw_kmem_free *args)
{
	return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}

#if 0   // not exist
SEC("tracepoint/kmem/kmem_cache_alloc")
int tracepoint__kmem__kmem_cache_alloc(struct trace_event_raw_kmem_cache_alloc *args)
{
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

SEC("tracepoint/kmem/kmem_cache_alloc_node")
int tracepoint__kmem__kmem_cache_alloc_node(struct trace_event_raw_kmem_cache_alloc_node *args)
{
	gen_alloc_enter((struct pt_regs *)args, args->bytes_alloc);
	return gen_alloc_exit2((struct pt_regs *)args, (size_t)args->ptr);
}

SEC("tracepoint/kmem/kmem_cache_free")
int tracepoint__kmem__kmem_cache_free(struct trace_event_raw_kmem_cache_free *args)
{
	return gen_free_enter((struct pt_regs *)args, (void *)args->ptr);
}
#endif

SEC("tracepoint/kmem/mm_page_alloc")
int tracepoint__kmem__mm_page_alloc(struct trace_event_raw_mm_page_alloc *args)
{
	gen_alloc_enter((struct pt_regs *)args, PAGE_SIZE << args->order);
	return gen_alloc_exit2((struct pt_regs *)args, args->pfn);
}

SEC("tracepoint/kmem/mm_page_free")
int tracepoint__kmem__mm_page_free(struct trace_event_raw_mm_page_free *args)
{
	return gen_free_enter((struct pt_regs *)args, (void *)args->pfn);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
