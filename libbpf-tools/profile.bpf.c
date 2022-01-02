/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 LG Electronics */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "profile.h"
#include "maps.bpf.h"

#define MAX_ENTRIES		10240

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile pid_t targ_pid = -1;
const volatile pid_t targ_tid = -1;

extern int LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, sizeof(u64));
	__uint(max_entries, MAX_ENTRIES);
} counts SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx) {
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = id;
	u64 *valp;
	static const u64 zero;
	struct key_t key = {};

	if (!include_idle && tid == 0)
		return 0;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;
	if (targ_tid != -1 && targ_tid != tid)
		return 0;

	key.pid = pid;
	bpf_get_current_comm(&key.name, sizeof(key.name));

	if (user_stacks_only)
		key.kern_stack_id = -1;
	else
		key.kern_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, 0);

	if (kernel_stacks_only)
		key.user_stack_id = -1;
	else
		key.user_stack_id = bpf_get_stackid(&ctx->regs, &stackmap, BPF_F_USER_STACK);

	if (key.kern_stack_id >= 0) {
		// populate extras to fix the kernel stack

		// arm64 only supported
#ifdef __TARGET_ARCH_arm64
		extern __u32 CONFIG_ARM64_VA_BITS __kconfig __weak;
		extern bool CONFIG_ARM64_64K_PAGES __kconfig __weak;
		u64 ip = PT_REGS_IP(&ctx->regs);
		u64 page_offset;
		u32 va;

		if (CONFIG_ARM64_VA_BITS)
			va = CONFIG_ARM64_VA_BITS;
		else if (CONFIG_ARM64_64K_PAGES)
			va = 42;
		else
			va = 39;

		if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 4, 0))
			page_offset = (-(1UL << (va)));
		else
			page_offset = (0xffffffffffffffffUL - (1UL << (va - 1)) + 1);

		if (ip > page_offset) {
			key.kernel_ip = ip;
		}
#endif
	}

	valp = bpf_map_lookup_or_try_init(&counts, &key, &zero);
	if (valp)
		__sync_fetch_and_add(valp, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
