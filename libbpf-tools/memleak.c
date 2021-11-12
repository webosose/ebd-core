#include <argp.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "memleak.h"
#include "memleak.skel.h"
#include "trace_helpers.h"

static struct env {
    bool kernel;
    bool user;
    bool verbose;
} env = {
    .kernel = 1,
    .user = 0
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

int main(int argc, char **argv)
{
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
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

    err = memleak_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    obj->rodata->is_kernel = env.kernel;

    err = memleak_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

cleanup:
    memleak_bpf__destroy(obj);

    return err != 0;
}
