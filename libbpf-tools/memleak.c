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

enum log_level {
	DEBUG,
	WARN,
	ERROR,
};

static enum log_level log_level = ERROR;

static void __p(enum log_level level, char *level_str, char *fmt, ...)
{
	va_list ap;

	if (level < log_level)
		return;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", level_str);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	fflush(stderr);
}

#define p_err(fmt, ...) __p(ERROR, "Error", fmt, ##__VA_ARGS__)
#define p_warn(fmt, ...) __p(WARN, "Warn", fmt, ##__VA_ARGS__)
#define p_debug(fmt, ...) __p(DEBUG, "Debug", fmt, ##__VA_ARGS__)

static struct env {
	pid_t pid;
	pid_t tid;
	bool kernel_threads_only;
	bool user_threads_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	int duration;
	int top;
	bool verbose;
} env = {
	.pid = -1,
	.tid = -1,
	.stack_storage_size = 1024,
	.perf_max_stack_depth = BPF_MAX_STACK_DEPTH,
	.duration = 5,
	.top = 10,
};

static pid_t target_pid = 0;
static const char *libc_path = NULL;

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace outstanding memory allocations that weren't freed.\n"
"Supports both user-mode allocations made with libc functions and kernel-mode\n"
"allocations made with kmalloc/kmem_cache_alloc/get_free_pages and\n"
"corresponding memory release functions.\n"
"\n"
"USAGE: memleak [-h] [-p PID] [-t] [-a] [-o OLDER] [-c COMMAND]\n"
"                [--combined-only] [--wa-missing-free] [-s SAMPLE_RATE]\n"
"                [-T TOP] [-z MIN_SIZE] [-Z MAX_SIZE] [-O OBJ]\n"
"                [interval] [count]\n";

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --pef-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace"},
	{ "kernel-threads-only", 'k', NULL, 0,
	  "Kernel threads only (no user threads)" },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)" },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces that can be stored and displayed (default 1024)" },
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
	long pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			p_err("Invalid PID: %s", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'T':
		env.top = strtol(arg, NULL, 10);
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
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			p_err("invalid perf max stack depth: %s", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			p_err("invalid stack storage size: %s", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int compar(const void *a, const void *b)
{
	__u64 x = ((struct alloc_stack *) a)->size;
	__u64 y = ((struct alloc_stack *) b)->size;
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
	unsigned long *ip;
	struct alloc_info_t val;
	struct alloc_stack *stack, *stacks;
	time_t timer;
	struct tm *t;

	timer = time(NULL);
	t = localtime(&timer);

	printf("\n[%02d:%02d:%02d] Top %u stacks with outstanding allocations:\n",
		t->tm_hour, t->tm_min, t->tm_sec, env.top);

	ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		p_err("failed to allocation memory of stack trace");
		return;
	}

	stacks = calloc(MAX_ENTRIES, sizeof(*stacks));
	if (!stacks) {
		p_err("failed to allocation memory of stack info");
		goto cleanup;
	}

	ifd = bpf_map__fd(obj->maps.allocs);
	sfd = bpf_map__fd(obj->maps.stack_traces);

	while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(ifd, &next_key, &val);
		if (err < 0) {
			p_warn("no entry found!");
			goto cleanup;
		}
		lookup_key = next_key;

		stack = NULL;
		for (i = 0; i < MAX_ENTRIES; i++) {
			if (stacks[i].stack_id == val.stack_id) {
				stack = &stacks[i];
				break;
			}
			if (stacks[i].stack_id == 0) {
				stack = &stacks[i];
				stack->stack_id = val.stack_id;
				rows++;
				break;
			}
		}
		if (stack == NULL)
			continue;

		stack->size += val.size;
		stack->nr++;
	}

	qsort(stacks, rows, sizeof(*stacks), compar);

	if (rows > env.top)
		rows = env.top;

	if (env.kernel_threads_only || !target_pid) {
		for (i = 0; i < rows; i++) {
			if (bpf_map_lookup_elem(sfd, &stacks[i].stack_id, ip) != 0) {
				p_warn("\t[Missed Kernel Stack]");
				continue;
			}

			printf("\t[%d] %d bytes in %d allocations from kernel stack\n",
				i + 1, stacks[i].size, stacks[i].nr);
			for (j = 0; j < env.perf_max_stack_depth && ip[j]; j++) {
				ksym = ksyms__map_addr(ksyms, ip[j]);
				if (ksym) {
					printf("\t#%-2d 0x%lx %s+0x%lx\n", j + 1,
						ip[j], ksym->name, ip[j] - ksym->addr);
				} else
					printf("\t#%-2d 0x%lx [unknown]\n", j + 1, ip[j]);
			}
			printf("\n");
		}
	} else {
		syms = syms_cache__get_syms(syms_cache, val.pid);

		for (i = 0; i < rows; i++) {
			if (bpf_map_lookup_elem(sfd, &stacks[i].stack_id, ip) != 0) {
				p_warn("\t[Missed User Stack]");
				continue;
			}

			printf("\t[%d] %d bytes in %d allocations from user stack\n",
				i + 1, stacks[i].size, stacks[i].nr);
			for (j = 0; j < env.perf_max_stack_depth && ip[j]; j++) {
				if (!syms)
					printf("\t#%-2d 0x%016lx [unknown]\n", j + 1, ip[j]);
				else {
					char *dso_name = NULL;
					uint64_t dso_offset = 0;
					sym = syms__map_addr_dso(syms, ip[j], &dso_name, &dso_offset);
					printf("\t#%-2d %#016lx", j + 1, ip[j]);
					if (sym)
						printf(" %s+0x%lx", sym->name, sym->offset);
					if (dso_name)
						printf(" (%s_0x%lx)", dso_name, dso_offset);
					printf("\n");
				}
			}
			printf("\t%-16s %s (%d)\n\n", "-", val.comm, val.pid);
		}
	}

cleanup:
	if (stacks)
		free(stacks);
	if (ip)
		free(ip);
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
		p_warn("failed to attach tracepoint: %s", strerror(-err));
		return -1;
	}

	obj->links.tracepoint__kmem__kmalloc_node =
		bpf_program__attach(obj->progs.tracepoint__kmem__kmalloc_node);
	err = libbpf_get_error(obj->links.tracepoint__kmem__kmalloc_node);
	if (err) {
		p_warn("failed to attach tracepoint: %s", strerror(-err));
		return -1;
	}

	obj->links.tracepoint__kmem__kfree =
		bpf_program__attach(obj->progs.tracepoint__kmem__kfree);
	err = libbpf_get_error(obj->links.tracepoint__kmem__kfree);
	if (err) {
		p_warn("failed to attach tracepoint: %s", strerror(-err));
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
		p_warn("could not find libc.so");
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "malloc");
	if (func_off < 0) {
		p_warn("could not find malloc in %s", libc_path);
		return -1;
	}
	obj->links.malloc_entry =
		bpf_program__attach_uprobe(obj->progs.malloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.malloc_entry);
	if (err) {
		p_warn("failed to attach malloc_entry: %d", err);
		return -1;
	}
	obj->links.malloc_return =
		bpf_program__attach_uprobe(obj->progs.malloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.malloc_return);
	if (err) {
		p_warn("failed to attach malloc_return: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "free");
	if (func_off < 0) {
		p_warn("could not find free in %s", libc_path);
		return -1;
	}
	obj->links.free_entry =
		bpf_program__attach_uprobe(obj->progs.free_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.free_entry);
	if (err) {
		p_warn("failed to attach free_entry: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "calloc");
	if (func_off < 0) {
		p_warn("could not find calloc in %s", libc_path);
		return -1;
	}
	obj->links.calloc_entry =
		bpf_program__attach_uprobe(obj->progs.calloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.calloc_entry);
	if (err) {
		p_warn("failed to attach calloc_entry: %d", err);
		return -1;
	}
	obj->links.calloc_return =
		bpf_program__attach_uprobe(obj->progs.calloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.calloc_return);
	if (err) {
		p_warn("failed to attach calloc_return: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "realloc");
	if (func_off < 0) {
		p_warn("could not find realloc in %s", libc_path);
		return -1;
	}
	obj->links.realloc_entry =
		bpf_program__attach_uprobe(obj->progs.realloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.realloc_entry);
	if (err) {
		p_warn("failed to attach realloc_entry: %d", err);
		return -1;
	}
	obj->links.realloc_return =
		bpf_program__attach_uprobe(obj->progs.realloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.realloc_return);
	if (err) {
		p_warn("failed to attach realloc_return: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "posix_memalign");
	if (func_off < 0) {
		p_warn("could not find posix_memalign in %s", libc_path);
		return -1;
	}
	obj->links.posix_memalign_entry =
		bpf_program__attach_uprobe(obj->progs.posix_memalign_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.posix_memalign_entry);
	if (err) {
		p_warn("failed to attach posix_memalign_entry: %d", err);
		return -1;
	}
	obj->links.posix_memalign_return =
		bpf_program__attach_uprobe(obj->progs.posix_memalign_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.posix_memalign_return);
	if (err) {
		p_warn("failed to attach posix_memalign_return: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "aligned_alloc");
	if (func_off < 0) {
		p_warn("could not find aligned_alloc in %s", libc_path);
		return -1;
	}
	obj->links.aligned_alloc_entry =
		bpf_program__attach_uprobe(obj->progs.aligned_alloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.aligned_alloc_entry);
	if (err) {
		p_warn("failed to attach aligned_alloc_entry: %d", err);
		return -1;
	}
	obj->links.aligned_alloc_return =
		bpf_program__attach_uprobe(obj->progs.aligned_alloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.aligned_alloc_return);
	if (err) {
		p_warn("failed to attach aligned_alloc_return: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "valloc");
	if (func_off < 0) {
		p_warn("could not find valloc in %s", libc_path);
		return -1;
	}
	obj->links.valloc_entry =
		bpf_program__attach_uprobe(obj->progs.valloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.valloc_entry);
	if (err) {
		p_warn("failed to attach valloc_entry: %d", err);
		return -1;
	}
	obj->links.valloc_return =
		bpf_program__attach_uprobe(obj->progs.valloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.valloc_return);
	if (err) {
		p_warn("failed to attach valloc_return: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "memalign");
	if (func_off < 0) {
		p_warn("could not find memalign in %s", libc_path);
		return -1;
	}
	obj->links.memalign_entry =
		bpf_program__attach_uprobe(obj->progs.memalign_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.memalign_entry);
	if (err) {
		p_warn("failed to attach memalign_entry: %d", err);
		return -1;
	}
	obj->links.memalign_return =
		bpf_program__attach_uprobe(obj->progs.memalign_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.memalign_return);
	if (err) {
		p_warn("failed to attach memalign_return: %d", err);
		return -1;
	}

	func_off = get_elf_func_offset(libc_path, "pvalloc");
	if (func_off < 0) {
		p_warn("could not find pvalloc in %s", libc_path);
		return -1;
	}
	obj->links.pvalloc_entry =
		bpf_program__attach_uprobe(obj->progs.pvalloc_entry, false,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.pvalloc_entry);
	if (err) {
		p_warn("failed to attach pvalloc_entry: %d", err);
		return -1;
	}
	obj->links.pvalloc_return =
		bpf_program__attach_uprobe(obj->progs.pvalloc_return, true,
					target_pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.pvalloc_return);
	if (err) {
		p_warn("failed to attach pvalloc_return: %d", err);
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
		p_err("failed to increase rlimit: %d", err);
		return 1;
	}

	obj = memleak_bpf__open();
	if (!obj) {
		p_err("failed to open BPF object");
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
		p_err("failed to load BPF object: %d", err);
		goto cleanup;
	}

	//err = memleak_bpf__attach(obj);
	err = attach_probes(obj);
	if (err) {
		p_err("failed to attach BPF programs");
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		p_err("failed to load kallsyms");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		p_err("failed to load kallsyms");
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
