#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "memleak.h"
#include "memleak.skel.h"
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
    .duration = 99999999,
};

const char *argp_program_version = "memleak 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Trace memory allocations.";

static const struct argp_option opts[] = {
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
    return 0;
}

static void print_outstanding(struct ksyms *ksyms, struct syms_cache *syms_cache,
                struct memleak_bpf *obj)
{
    unsigned long lookup_key = 0, next_key, *ip;
    const struct ksym *ksym;
    int i, err, ifd, sfd, scnt = 0, top_stacks = 10;
    struct alloc_info_t val;
    time_t timer;
    struct tm *t;

    timer = time(NULL);
    t = localtime(&timer);

    printf("\n[%02d:%02d:%02d] Top %u stacks with outstanding allocations:\n",
           t->tm_hour, t->tm_min, t->tm_sec, top_stacks);

    ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
    if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return;
	}

    ifd = bpf_map__fd(obj->maps.allocs);
    sfd = bpf_map__fd(obj->maps.stack_traces);
    while (!bpf_map_get_next_key(ifd, &lookup_key, &next_key) && (scnt++ < top_stacks)) {
        err = bpf_map_lookup_elem(ifd, &next_key, &val);
        if (err < 0) {
            fprintf(stderr, "failed to lookup info: %d\n", err);
			goto cleanup;
		}
        lookup_key = next_key;
        if (val.stack_id < 0)
			continue;
        if (bpf_map_lookup_elem(sfd, &val.stack_id, ip) != 0) {
            fprintf(stderr, "    [Missed Kernel Stack]\n");
			goto print_ustack;
		}
        printf("\t%lld bytes in %d allocations from stack\n", val.size, 1);
        for (i = 0; i < env.perf_max_stack_depth && ip[i]; i++) {
			ksym = ksyms__map_addr(ksyms, ip[i]);
			printf("    #%d 0x%lx %s\n", i, ksym->addr, ksym ? ksym->name : "Unknown");
		}

print_ustack:
        if (next_key == -1)
            goto skip_ustack;

        err = bpf_map_lookup_elem(sfd, &next_key, ip);
        if (err < 0) {
			fprintf(stderr, "    [Missed User Stack]\n");
			continue;
		}

skip_ustack:
        //printf("    %-16s %s (%d)\n", "-", val.tgid, val.pid);
        printf("        0x%d\n\n", val.stack_id);
    }

cleanup:
    free(ip);
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
        fprintf(stderr, "failed to increase rlimit: %d\n", err);
        return 1;
    }

    obj = memleak_bpf__open();
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
    bpf_map__set_max_entries(obj->maps.stack_traces, env.stack_storage_size);

    err = memleak_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = memleak_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    ksyms = ksyms__load();
    if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

    syms_cache = syms_cache__new(0);
    if (!syms_cache) {
        fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

    print_outstanding(ksyms, syms_cache, obj);

    sleep(env.duration);

cleanup:
    memleak_bpf__destroy(obj);
    syms_cache__free(syms_cache);
    ksyms__free(ksyms);

    return err != 0;
}
