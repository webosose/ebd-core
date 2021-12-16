
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "memleak.h"

#define MAX_ENTRIES 10248

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

        bpf_printk("alloc entered, size = %u\\n", size);

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
                info.timestamp_ns = bpf_ktime_get_ns();
                info.stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
                bpf_map_update_elem(&allocs, &address, &info, BPF_OK);
                update_statistics_add(info.stack_id, info.size);
        }

        bpf_printk("alloc exited, size = %lu, result = %lx\\n",
                        info.size, address);

        return 0;
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

        bpf_printk("free enterd, address = %lx, size = %lu\\n",
                        address, info->size);

        return 0;
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
