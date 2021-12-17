#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lsan.h"
#include "lsan.skel.h"
#include "trace_helpers.h"

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
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.duration = 5,
};

const char *argp_program_version = "lsan 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] = "Detect memory leak";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

typedef unsigned long long uptr;
typedef void (*for_each_chunk_callback)(uptr chunk);

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	//static int pos_args;
	long pid;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			fprintf(stderr, "Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		env.pid = pid;
		break;
	}
	return 0;
}

static void for_each_chunk(for_each_chunk_callback callback) {
}

static void collect_leaks_cb(uptr chunk) {
}

static void collect_ignore_cb(uptr chunk) {
}

static void mark_indirectly_leaked_cb(uptr chunk) {
}

static void read_table() {
}

static void process_global_regions() {
}

static void process_threads() {
}

static void process_root_regions() {
}

static void flood_fill_tag() {
}

static void process_pc() {
}

static void process_platform_specific_allocations() {
}

static void classify_all_chunks() {
	for_each_chunk(collect_ignore_cb);
	process_global_regions();
	process_threads();
	process_root_regions();
	flood_fill_tag();
	process_pc();
	process_platform_specific_allocations();
	flood_fill_tag();
	for_each_chunk(mark_indirectly_leaked_cb);
}

static void report_leaks() {
}

static void empty_table() {
}

static void do_leak_check() {
	read_table();
	classify_all_chunks();
	for_each_chunk(collect_leaks_cb);
	report_leaks();
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
	struct lsan_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = lsan_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	obj->rodata->targ_tgid = env.pid;
	obj->rodata->targ_pid = env.tid;
	obj->rodata->user_threads_only = env.user_threads_only;
	obj->rodata->kernel_threads_only = env.kernel_threads_only;

	bpf_map__set_value_size(obj->maps.stack_traces,
		env.perf_max_stack_depth * sizeof(unsigned long));
	bpf_map__set_max_entries(obj->maps.stack_traces,
		env.stack_storage_size);

	err = lsan_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = lsan_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	do {
		sleep(env.duration);
		empty_table();
		do_leak_check();
	} while (1);

cleanup:
	lsan_bpf__destroy(obj);
	syms_cache__free(syms_cache);
	ksyms__free(ksyms);
	return err != 0;
}
