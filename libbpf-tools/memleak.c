/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021, LG Electronics, Inc. */

#include <argp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct env {
	pid_t pid;
	pid_t tid;
	bool kernel_threads_only;
	bool user_threads_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	int duration;
	bool verbose;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 10248,
	.perf_max_stack_depth = 127,
	.duration = 5,
};

static pid_t target_pid = 0;
static pid_t top_stacks = 10;
static const char *libc_path = NULL;

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace outstanding memory allocations that weren't freed.\n"
"Supports both user-mode allocations made with libc functions and kernel-mode\n"
"allocations made with kmalloc/kmem_cache_alloc/get_free_pages and\n"
"corresponding memory release functions.\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace"},
	{ "kernel-thread-olny", 'k', NULL, 0,
	  "Kernel threads only (no user threads)" },
	{ "top", 'T', "count", 0,
	  "display only this many top allocating stacks (by size)" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static int libbpf_print_fn(enum libbpf_print_level level,
			const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, top;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'T':
		top = strtol(arg, NULL, 10);
		top_stacks = top;
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'u':
		env.user_threads_only = true;
		break;
	case 'k':
		env.kernel_threads_only = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int compar(const void *a, const void *b)
{
	__u64 x = ((struct ip_stat *) a)->size;
	__u64 y = ((struct ip_stat *) b)->size;
	return x > y ? -1 : !(x == y);
}

static void print_outstanding(struct ksyms *ksyms, struct syms_cache *syms_cache,
				struct memleak_bpf *obj)
{
	unsigned long lookup_key = 0, next_key;
	const struct ksym *ksym;
	const struct syms *syms;
	const struct sym *sym;
	int i, j, err, ifd, sfd, rows = 0;
	struct alloc_info_t val;
	time_t timer;
	struct tm *t;
	static struct ip_stat stack_ips[MAX_ENTRIES];

	timer = time(NULL);
	t = localtime(&timer);

	printf("\n[%02d:%02d:%02d] Top %u stacks with outstanding allocations:\n",
		t->tm_hour, t->tm_min, t->tm_sec, top_stacks);

	ifd = bpf_map__fd(obj->maps.allocs);
	sfd = bpf_map__fd(obj->maps.stack_traces);

	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(ifd, &next_key, &val);
		if (err < 0) {
			warn("failed to lookup info: %d\n", err);
			return;
		}
		lookup_key = next_key;
		if (val.kern_stack_id < 0 || target_pid)
			goto print_ustack;

		if (bpf_map_lookup_elem(sfd, &val.kern_stack_id, stack_ips[rows].ip))
			continue;

		goto skip_ustack;

print_ustack:
		if (val.user_stack_id < 0 ||
			bpf_map_lookup_elem(sfd, &val.user_stack_id, stack_ips[rows].ip))
			continue;

skip_ustack:
		stack_ips[rows++].size = val.size;
	}

	qsort(stack_ips, rows, sizeof(struct ip_stat), compar);
	rows = rows < top_stacks ? rows : top_stacks;

	if (env.kernel_threads_only || !target_pid) {
		for (j = 0; j < rows; j++) {
			printf("\t%lld bytes in %d allocations from stack\n", stack_ips[j].size, 1);
			for (i = 0; i < env.perf_max_stack_depth && stack_ips[j].ip[i]; i++) {
				ksym = ksyms__map_addr(ksyms, stack_ips[j].ip[i]);
				printf("    %#lx %s\n", ksym->addr, ksym ? ksym->name : "Unknown");
			}
			printf("\n");
		}
		return;
	}

	syms = syms_cache__get_syms(syms_cache, val.pid);
	if (!syms) {
		warn("failed to get syms\n");
		goto skip_ustack;
	}

	for (j = 0; j < rows; j++) {
		printf("\t%lld bytes in %d allocations from user stack\n", stack_ips[j].size, 1);
		for (i = 0; i < env.perf_max_stack_depth && stack_ips[j].ip[i]; i++) {
			sym = syms__map_addr(syms, stack_ips[j].ip[i]);
			if (sym)
				printf("    %#016lx %s\n", stack_ips[j].ip[i], sym->name);
			else
				printf("    %#016lx [unknown]\n", stack_ips[j].ip[i]);
		}
		printf("    %-16s %s (%d)\n\n", "-", val.comm, val.pid);
	}
}

static int get_libc_path(char *path)
{
	FILE *f;
	char buf[PATH_MAX] = {};
	char *filename;
	float version;

	if (libc_path) {
		memcpy(path, libc_path, strlen(libc_path));
		return 0;
	}

	f = fopen("/proc/1/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf)
			continue;
		filename = strrchr(buf, '/') + 1;
		if (sscanf(filename, "libc-%f.so", &version) == 1) {
			memcpy(path, buf, strlen(buf));
			fclose(f);
			return 0;
		}
	}

	fclose(f);
	return -1;
}

static int attach_kprobes(struct memleak_bpf *obj)
{
	long err;

	printf("Attaching to kernel allocators, Ctrl+C to quit.\n");

	obj->links.tracepoint__kmem__kmalloc =
		bpf_program__attach(obj->progs.tracepoint__kmem__kmalloc);
	err = libbpf_get_error(obj->links.tracepoint__kmem__kmalloc);
	if (err) {
		warn("failed to attach tracepoint: %s\n", strerror(-err));
		return -1;
	}

	obj->links.tracepoint__kmem__kmalloc_node =
		bpf_program__attach(obj->progs.tracepoint__kmem__kmalloc_node);
	err = libbpf_get_error(obj->links.tracepoint__kmem__kmalloc_node);
	if (err) {
		warn("failed to attach tracepoint: %s\n", strerror(-err));
		return -1;
	}

	obj->links.tracepoint__kmem__kfree =
		bpf_program__attach(obj->progs.tracepoint__kmem__kfree);
	err = libbpf_get_error(obj->links.tracepoint__kmem__kfree);
	if (err) {
		warn("failed to attach tracepoint: %s\n", strerror(-err));
		return -1;
	}

	return 0;
}

static int attach_uprobes(struct memleak_bpf *obj)
{
	int err;
	char libc_path[PATH_MAX] = {};
	off_t func_off;

	printf("Attaching to pid %d, Ctrl+C to quit.\n", target_pid);

	err = get_libc_path(libc_path);
	if (err) {
		warn("could not find libc.so\n");
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "malloc");
	if (func_off < 0) {
		warn("could not find malloc in %s\n", libc_path);
		return -1;
	}
	obj->links.malloc_entry =
		bpf_program__attach_uprobe(obj->progs.malloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.malloc_entry);
	if (err) {
		warn("failed to attach malloc_entry: %d\n", err);
		return -1;
	}
	obj->links.malloc_return =
		bpf_program__attach_uprobe(obj->progs.malloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.malloc_return);
	if (err) {
		warn("failed to attach malloc_return: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "free");
	if (func_off < 0) {
		warn("could not find free in %s\n", libc_path);
		return -1;
	}
	obj->links.free_entry =
		bpf_program__attach_uprobe(obj->progs.free_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.free_entry);
	if (err) {
		warn("failed to attach free_entry: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "calloc");
	if (func_off < 0) {
		warn("could not find calloc in %s\n", libc_path);
		return -1;
	}
	obj->links.calloc_entry =
		bpf_program__attach_uprobe(obj->progs.calloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.calloc_entry);
	if (err) {
		warn("failed to attach calloc_entry: %d\n", err);
		return -1;
	}
	obj->links.calloc_return =
		bpf_program__attach_uprobe(obj->progs.calloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.calloc_return);
	if (err) {
		warn("failed to attach calloc_return: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "realloc");
	if (func_off < 0) {
		warn("could not find realloc in %s\n", libc_path);
		return -1;
	}
	obj->links.realloc_entry =
		bpf_program__attach_uprobe(obj->progs.realloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.realloc_entry);
	if (err) {
		warn("failed to attach realloc_entry: %d\n", err);
		return -1;
	}
	obj->links.realloc_return =
		bpf_program__attach_uprobe(obj->progs.realloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.realloc_return);
	if (err) {
		warn("failed to attach realloc_return: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "posix_memalign");
	if (func_off < 0) {
		warn("could not find posix_memalign in %s\n", libc_path);
		return -1;
	}
	obj->links.posix_memalign_entry =
		bpf_program__attach_uprobe(obj->progs.posix_memalign_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.posix_memalign_entry);
	if (err) {
		warn("failed to attach posix_memalign_entry: %d\n", err);
		return -1;
	}
	obj->links.posix_memalign_return =
		bpf_program__attach_uprobe(obj->progs.posix_memalign_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.posix_memalign_return);
	if (err) {
		warn("failed to attach posix_memalign_return: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "aligned_alloc");
	if (func_off < 0) {
		warn("could not find aligned_alloc in %s\n", libc_path);
		return -1;
	}
	obj->links.aligned_alloc_entry =
		bpf_program__attach_uprobe(obj->progs.aligned_alloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.aligned_alloc_entry);
	if (err) {
		warn("failed to attach aligned_alloc_entry: %d\n", err);
		return -1;
	}
	obj->links.aligned_alloc_return =
		bpf_program__attach_uprobe(obj->progs.aligned_alloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.aligned_alloc_return);
	if (err) {
		warn("failed to attach aligned_alloc_return: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "valloc");
	if (func_off < 0) {
		warn("could not find valloc in %s\n", libc_path);
		return -1;
	}
	obj->links.valloc_entry =
		bpf_program__attach_uprobe(obj->progs.valloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.valloc_entry);
	if (err) {
		warn("failed to attach valloc_entry: %d\n", err);
		return -1;
	}
	obj->links.valloc_return =
		bpf_program__attach_uprobe(obj->progs.valloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.valloc_return);
	if (err) {
		warn("failed to attach valloc_return: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "memalign");
	if (func_off < 0) {
		warn("could not find memalign in %s\n", libc_path);
		return -1;
	}
	obj->links.memalign_entry =
		bpf_program__attach_uprobe(obj->progs.memalign_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.memalign_entry);
	if (err) {
		warn("failed to attach memalign_entry: %d\n", err);
		return -1;
	}
	obj->links.memalign_return =
		bpf_program__attach_uprobe(obj->progs.memalign_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.memalign_return);
	if (err) {
		warn("failed to attach memalign_return: %d\n", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "pvalloc");
	if (func_off < 0) {
		warn("could not find pvalloc in %s\n", libc_path);
		return -1;
	}
	obj->links.pvalloc_entry =
		bpf_program__attach_uprobe(obj->progs.pvalloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.pvalloc_entry);
	if (err) {
		warn("failed to attach pvalloc_entry: %d\n", err);
		return -1;
	}
	obj->links.pvalloc_return =
		bpf_program__attach_uprobe(obj->progs.pvalloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.pvalloc_return);
	if (err) {
		warn("failed to attach pvalloc_return: %d\n", err);
		return -1;
	}

	return 0;
}

static int attach_probes(struct memleak_bpf *obj)
{
	if (target_pid != 0)
		return attach_uprobes(obj);
	return attach_kprobes(obj);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;
	struct memleak_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = memleak_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->user_threads_only = env.user_threads_only;
	obj->rodata->kernel_threads_only = env.kernel_threads_only;

	bpf_map__set_value_size(obj->maps.stack_traces,
			env.perf_max_stack_depth * sizeof(unsigned long long));
	bpf_map__set_max_entries(obj->maps.stack_traces, env.stack_storage_size);

	err = memleak_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	//err = memleak_bpf__attach(obj);
	err = attach_probes(obj);
	if (err) {
		warn("failed to attach BPF programs\n");
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		warn("failed to load kallsyms\n");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		warn("failed to load kallsyms\n");
		goto cleanup;
	}

	do {
		sleep(env.duration);
		print_outstanding(ksyms, syms_cache, obj);
	} while(1);

cleanup:
	memleak_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);

	return err != 0;
}
