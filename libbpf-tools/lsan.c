#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "lsan.h"
#include "lsan.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"
#include "cvector.h"
#include "uthash.h"

#define LSAN_OPTIMIZED
#define STACK_MAX 127
#define BUF_MAX (STACK_MAX * LINE_MAX * 2)

enum maps {
	MAPS_ADDRESS = 0,
	MAPS_PERMISSIONS = 1,
	MAPS_OFFSET = 2,
	MAPS_DEVICE = 3,
	MAPS_INODE = 4,
	MAPS_PATH = 5,
	MAPS_COLUMN_MAX = 6
};

enum suppr {
	SUPPR_KIND = 0,
	SUPPR_PATH = 1,
	SUPPR_MAX = 2
};

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
	.perf_max_stack_depth = STACK_MAX,
	.duration = 10,
};

typedef unsigned long long uptr;
struct lsan_hash_t {
	__u64 size;
	int stack_id;
	enum chunk_tag tag;
	uptr id;
	UT_hash_handle hh;
};

struct report_info_t {
	__u64 size;
	int count;
	int id;
	UT_hash_handle hh;
};

struct lsan_hash_t *copied = NULL;
struct report_info_t *direct = NULL;
struct report_info_t *indirect = NULL;

const char *argp_program_version = "lsan 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] = "Detect memory leak";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "help", 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "pid", 'p', "PID", 0, "Set pid(mandatory option)" },
	{},
};
const char *suppression_path = "/usr/etc/suppr.txt";

typedef void (*for_each_chunk_callback)(uptr chunk);

static const char *libc_path = NULL;
struct lsan_bpf *obj;
cvector_vector_type(uptr) frontier = NULL;
cvector_vector_type(uptr) key_table = NULL;
cvector_vector_type(char*) suppression = NULL;
FILE *fp_mem = NULL;

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
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int get_libc_path(char *path)
{
	FILE *f;
	char buf[PATH_MAX] = {};
	char *file_name;
	float version;

	if (libc_path) {
		memcpy(path, libc_path, strlen(libc_path));
		return 0;
	}

	f = fopen("/proc/1/maps", "rt");
	if (f == NULL) {
		fprintf(stderr, "Failed to open /proc/1/maps\n");
		return -errno;
	}

	while (fscanf(f, "%*x-%*x %*s %*s %*s %*s %[^\n]\n", buf) != EOF) {
		if (strchr(buf, '/') != buf)
			continue;

		file_name = strrchr(buf, '/') + 1;
		if (sscanf(file_name, "libc-%f.so", &version) == 1) {
			memcpy(path, buf, strlen(buf));
			fclose(f);
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static int attach_uprobes(struct lsan_bpf *obj)
{
	int err;
	char libc_path[PATH_MAX] = {};
	off_t func_off;

	err = get_libc_path(libc_path);
	if (err) {
		fprintf(stderr, "Failed to find libc.so, %d\n", err);
		return err;
	}

	// malloc
	func_off = get_elf_func_offset(libc_path, "malloc");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.malloc_entry =
			bpf_program__attach_uprobe(obj->progs.malloc_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.malloc_entry);
	if (err) {
		fprintf(stderr, "Failed to attach malloc_entry\n");
		return err;
	}
	obj->links.malloc_return =
			bpf_program__attach_uprobe(obj->progs.malloc_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.malloc_return);
	if (err) {
		fprintf(stderr, "Failed to attach malloc_return\n");
		return err;
	}

	// free
	func_off = get_elf_func_offset(libc_path, "free");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.free_entry =
			bpf_program__attach_uprobe(obj->progs.free_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.free_entry);
	if (err) {
		fprintf(stderr, "Failed to attach free_entry\n");
		return err;
	}

	// calloc
	func_off = get_elf_func_offset(libc_path, "calloc");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.calloc_entry =
			bpf_program__attach_uprobe(obj->progs.calloc_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.calloc_entry);
	if (err) {
		fprintf(stderr, "Failed to attach calloc_entry\n");
		return err;
	}
	obj->links.calloc_return =
			bpf_program__attach_uprobe(obj->progs.calloc_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.calloc_return);
	if (err) {
		fprintf(stderr, "Failed to attach calloc_return\n");
		return err;
	}

	// realloc
	func_off = get_elf_func_offset(libc_path, "realloc");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.realloc_entry =
			bpf_program__attach_uprobe(obj->progs.realloc_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.realloc_entry);
	if (err) {
		fprintf(stderr, "Failed to attach realloc_entry\n");
		return err;
	}
	obj->links.realloc_return =
			bpf_program__attach_uprobe(obj->progs.realloc_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.realloc_return);
	if (err) {
		fprintf(stderr, "Failed to attach realloc_return\n");
		return err;
	}

	// posix_memalign
	func_off = get_elf_func_offset(libc_path, "posix_memalign");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.posix_memalign_entry =
			bpf_program__attach_uprobe(obj->progs.posix_memalign_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.posix_memalign_entry);
	if (err) {
		fprintf(stderr, "Failed to attach posix_memalign_entry\n");
		return err;
	}
	obj->links.posix_memalign_return =
			bpf_program__attach_uprobe(obj->progs.posix_memalign_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.posix_memalign_return);
	if (err) {
		fprintf(stderr, "Failed to attach posix_memalign_return\n");
		return err;
	}

	// aligned_alloc
	func_off = get_elf_func_offset(libc_path, "aligned_alloc");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.aligned_alloc_entry =
			bpf_program__attach_uprobe(obj->progs.aligned_alloc_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.aligned_alloc_entry);
	if (err) {
		fprintf(stderr, "Failed to attach aligned_alloc_entry\n");
		return err;
	}
	obj->links.aligned_alloc_return =
			bpf_program__attach_uprobe(obj->progs.aligned_alloc_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.aligned_alloc_return);
	if (err) {
		fprintf(stderr, "Failed to attach aligned_alloc_return\n");
		return err;
	}

	// valloc
	func_off = get_elf_func_offset(libc_path, "valloc");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.valloc_entry =
			bpf_program__attach_uprobe(obj->progs.valloc_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.valloc_entry);
	if (err) {
		fprintf(stderr, "Failed to attach valloc_entry\n");
		return err;
	}
	obj->links.valloc_return =
			bpf_program__attach_uprobe(obj->progs.valloc_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.valloc_return);
	if (err) {
		fprintf(stderr, "Failed to attach valloc_return\n");
		return err;
	}

	// memalign
	func_off = get_elf_func_offset(libc_path, "memalign");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.memalign_entry =
			bpf_program__attach_uprobe(obj->progs.memalign_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.memalign_entry);
	if (err) {
		fprintf(stderr, "Failed to attach memalign_entry\n");
		return err;
	}
	obj->links.memalign_return =
			bpf_program__attach_uprobe(obj->progs.memalign_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.memalign_return);
	if (err) {
		fprintf(stderr, "Failed to attach memalign_return\n");
		return err;
	}

	// pvalloc
	func_off = get_elf_func_offset(libc_path, "pvalloc");
	if (func_off < 0) {
		fprintf(stderr, "Failed to get func offset\n");
		return func_off;
	}
	obj->links.pvalloc_entry =
			bpf_program__attach_uprobe(obj->progs.pvalloc_entry,
			false, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.pvalloc_entry);
	if (err) {
		fprintf(stderr, "Failed to attach pvalloc_entry\n");
		return err;
	}
	obj->links.pvalloc_return =
			bpf_program__attach_uprobe(obj->progs.pvalloc_return,
			true, env.pid ? : -1, libc_path, func_off);
	err = libbpf_get_error(obj->links.pvalloc_return);
	if (err) {
		fprintf(stderr, "Failed to attach pvalloc_return\n");
		return err;
	}

	return 0;
}

static int attach_probes(struct lsan_bpf *obj)
{
	// Support only uprobes currently
	return attach_uprobes(obj);
}

static void for_each_chunk(for_each_chunk_callback callback)
{
	struct lsan_hash_t *curr, *next;
	HASH_ITER(hh, copied, curr, next) {
		callback(curr->id);
	}
}

static uptr get_reference(uptr pp, size_t size)
{
	char *buf = (char*)malloc(sizeof(char) * size);
	uptr rst = 0;
	fseek(fp_mem, pp, SEEK_SET);
	size_t sz = fread(buf, sizeof(char), size, fp_mem);
	if (size != sz) {
		fprintf(stderr, "Tried to read %ld bytes but only read %ld bytes\n",
			size, sz);
		return rst;
	}
	int i;
	for (i=0; i<size; ++i) {
#if LITTLE_ENDIAN
		rst += ((uptr)buf[i] << (i*size));
#else
		rst += ((uptr)buf[i] << ((size-1-i)*size));
#endif
	}
	free(buf);
	return rst;
}

static uptr find_key(uptr start, uptr end, uptr ptr)
{
	while (1) {
		if (start >= end)
			return 0;

		if (end - start == 1) {
			struct lsan_hash_t *val;
			uptr key = key_table[start];
			HASH_FIND(hh, copied, &key, sizeof(uptr), val);
			if (key <= ptr && ptr < key + val->size)
				return key;

			return 0;
		}
		uptr mid = (start + end) / 2;
		if (ptr < key_table[mid]) {
			end = mid;
		} else { // ptr >= key_table[mid]
			start = mid;
		}
	}
}

static uptr points_into_chunk(uptr ptr)
{
#ifndef LSAN_OPTIMIZED
	struct lsan_hash_t *curr, *next;
	HASH_ITER(hh, copied, curr, next) {
		if (curr->id <= ptr && ptr < curr->id + curr->size) {
			return curr->id;
		}
	}
	return 0;
#else
	return find_key(0, cvector_size(key_table), ptr);
#endif
}

static void scan_range_for_pointers(uptr begin, uptr end, enum chunk_tag tag)
{
	size_t word_size = sizeof(uptr);
	int alignment = 1; // TODO: Need to increase this value for speed
	uptr pp = begin;
	if (pp % alignment != 0) {
		pp = pp + alignment - pp % alignment;
	}
	while (pp + word_size <= end) {
		uptr p = get_reference(pp, word_size);
		pp += alignment;
		uptr chunk = points_into_chunk(p);
		if (chunk == 0)
			continue;

		if (chunk == begin)
			continue;

		struct lsan_hash_t *val;
		HASH_FIND(hh, copied, &chunk, sizeof(uptr), val);
		if (val == NULL)
			continue;

		if (val->tag == REACHABLE || val->tag == IGNORED)
			continue;

		struct lsan_hash_t *item = (struct lsan_hash_t*)malloc(
			sizeof(struct lsan_hash_t));
		item->size = val->size;
		item->stack_id = val->stack_id;
		item->tag = tag;
		item->id = val->id;
		HASH_REPLACE(hh, copied, id, sizeof(uptr), item, val);
		free(val);
		if (tag == REACHABLE)
			cvector_push_back(frontier, p);
	}
}

static void collect_leaks_cb(uptr chunk)
{
	chunk = points_into_chunk(chunk);
	if (chunk == 0)
		return;

	struct lsan_hash_t *val;
	HASH_FIND(hh, copied, &chunk, sizeof(uptr), val);
	if (val == NULL)
		return;

	struct report_info_t *old;
	struct report_info_t *item = (struct report_info_t*)malloc(
			sizeof(struct report_info_t));
	item->size = val->size;
	item->id = val->stack_id;
	int stack_id = val->stack_id;
	// TODO: need to remove duplication
	if (val->tag == DIRECTLY_LEAKED) {
		HASH_FIND(hh, direct, &stack_id, sizeof(int), old);
		if (old == NULL) {
			item->count = 1;
			HASH_ADD(hh, direct, id, sizeof(int), item);
		} else {
			item->count = old->count + 1;
			HASH_REPLACE(hh, direct, id, sizeof(int), item, old);
			free(old);
		}
	} else if (val->tag == INDIRECTLY_LEAKED) {
		HASH_FIND(hh, indirect, &stack_id, sizeof(int), old);
		if (old == NULL) {
			item->count = 1;
			HASH_ADD(hh, indirect, id, sizeof(int), item);
		} else {
			item->count = old->count + 1;
			HASH_REPLACE(hh, indirect, id, sizeof(int), item, old);
			free(old);
		}
	}
}

static void collect_ignore_cb(uptr chunk)
{
	// TODO: low priority
}

static void mark_indirectly_leaked_cb(uptr chunk)
{
	chunk = points_into_chunk(chunk);
	if (chunk == 0)
		return;

	struct lsan_hash_t *val;
	HASH_FIND(hh, copied, &chunk, sizeof(uptr), val);
	if (val == NULL)
		return;
	if (val->tag != REACHABLE) {
		scan_range_for_pointers(val->id, val->id + val->size,
			INDIRECTLY_LEAKED);
	}
}

int compare(const void* a, const void* b)
{
	uptr aa = *(uptr*)a;
	uptr bb = *(uptr*)b;
	if (aa < bb)
		return -1;

	if (aa > bb)
		return 1;

	return 0;
}

static int read_table()
{
	struct lsan_info_t val;
	unsigned long lookup_key, next_key;
	int err;
	int afd = bpf_map__fd(obj->maps.allocs);
	lookup_key = 0;
	while (!bpf_map_get_next_key(afd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(afd, &next_key, &val);
		if (err < 0) {
			return 0;
		}
		if (val.stack_id >= 0) {
			struct lsan_hash_t *item = (struct lsan_hash_t*)malloc(
				sizeof(struct lsan_hash_t));
			item->size = val.size;
			item->stack_id = val.stack_id;
			item->tag = val.tag;
			item->id = next_key;
			HASH_ADD(hh, copied, id, sizeof(uptr), item);
		}
		cvector_push_back(key_table, next_key);
		lookup_key = next_key;
	}
	qsort(key_table, cvector_size(key_table), sizeof(uptr), compare);
	return 0;
}

static void process_global_regions()
{
	// TODO: absorbed to process_root_regions
}

static void process_threads()
{
	// TODO: absorbed to process_root_regions
}

static void process_root_regions()
{
	char file_name[FILENAME_MAX];
	char line[LINE_MAX];
	sprintf(file_name, "/proc/%d/maps", env.pid);
	FILE *fp = fopen(file_name, "rt");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open : %s\n", file_name);
		return;
	}
	while (fgets(line, sizeof(line), fp) != NULL) {
		char v[MAPS_COLUMN_MAX][PATH_MAX] = { {0, }, };
		int i = 0;
		char *ptr = strtok(line, " ");
		while (ptr != NULL) {
			memcpy(v[i], ptr, strlen(ptr));
			++i;
			ptr = strtok(NULL, " ");
		}
		if (i >= MAPS_PATH && (v[MAPS_PERMISSIONS][0] == 'r'
				&& v[MAPS_PERMISSIONS][1] == 'w')) {
			if (!(i == MAPS_COLUMN_MAX &&
					(strcmp(v[MAPS_PATH], "[heap]\n") == 0
					|| strcmp(v[MAPS_PATH], "[vvar]\n") == 0
					|| strcmp(v[MAPS_PATH], "[vdso]\n") == 0
					|| strcmp(v[MAPS_PATH], "[uprobes]\n") == 0))) {
				uptr begin, end;
				int hex = 16;
				ptr = strtok(v[MAPS_ADDRESS], "-");
				begin = strtoull(ptr, NULL, hex);
				ptr = strtok(NULL, "-");
				end = strtoull(ptr, NULL, hex);
				scan_range_for_pointers(begin, end, REACHABLE);
			}
		}
	}
	fclose(fp);
}

static void flood_fill_tag(enum chunk_tag tag)
{
	while (!cvector_empty(frontier)) {
		uptr next_chunk = frontier[cvector_size(frontier)];
		cvector_pop_back(frontier);
		uptr origin = points_into_chunk(next_chunk);
		struct lsan_hash_t *val;
		HASH_FIND(hh, copied, &origin, sizeof(uptr), val);
		if (val == NULL)
			continue;

		scan_range_for_pointers(origin, origin + val->size, tag);
	}
}

static void process_pc()
{
	// TODO: low priority
}

static void process_platform_specific_allocations()
{
	// TODO: low priority
}

static void classify_all_chunks()
{
	for_each_chunk(collect_ignore_cb);
	process_global_regions();
	process_threads();
	process_root_regions();
	flood_fill_tag(REACHABLE);
	process_pc();
	process_platform_specific_allocations();
	flood_fill_tag(REACHABLE);
	for_each_chunk(mark_indirectly_leaked_cb);
}

// Decending order
static int report_info_sort(struct report_info_t *a, struct report_info_t *b)
{
	return b->size * b->count - a->size * a->count;
}

static const char* demangle(const char* name)
{
	// TODO
	// return demangled function name
	// return name if it's not mangled
	return name;
}

static void leak_printer(struct report_info_t *curr, unsigned long *ip,
	const struct syms *syms, const char *kind)
{
	const struct sym *sym = NULL;
	char report_buf[BUF_MAX];
	char str[LINE_MAX];
	size_t i, j;
	memset(report_buf, 0, BUF_MAX);
	sprintf(report_buf,
		"%lld bytes %s leak found in %d allocations from stack\n",
		curr->size * curr->count, kind, curr->count);
	for (i = 0; i < env.perf_max_stack_depth && ip[i]; ++i) {
		sprintf(str, "\t#%ld %#016lx", i+1, ip[i]);
		strcat(report_buf, str);
		char* dso_name = NULL;
		uint64_t dso_offset;
		sym = syms__map_addr_dso(syms, ip[i], &dso_name, &dso_offset);
		if (sym) {
			sprintf(str, " %s+%#lx", demangle(sym->name), sym->offset);
			strcat(report_buf, str);
		}
		if (dso_name) {
			sprintf(str, " (%s+%#lx)", dso_name, dso_offset);
			strcat(report_buf, str);
		}
		if (i == 0 || i == 1) {
			for (j = 0; j < cvector_size(suppression); ++j) {
				if (strstr(str, suppression[j]) != NULL) {
					return;
				}
			}
		}
		sprintf(str, "\n");
		strcat(report_buf, str);
	}
	printf("%s\n", report_buf);
}

static void report_leak(struct syms_cache *syms_cache, unsigned long *ip,
	int sfd, struct report_info_t *container, const char* kind)
{
	const struct syms *syms = NULL;
	struct report_info_t *curr, *next;
	int rst;
	HASH_SORT(container, report_info_sort);
	HASH_ITER(hh, container, curr, next) {
		rst = bpf_map_lookup_elem(sfd, &(curr->id), ip);
		syms = syms_cache__get_syms(syms_cache, env.pid);
		if (rst == 0 && syms != NULL) {
			leak_printer(curr, ip, syms, kind);
		}
	}
}

static void report_leaks(struct syms_cache *syms_cache)
{
	unsigned long *ip = calloc(env.perf_max_stack_depth, sizeof(*ip));
	if (!ip) {
		fprintf(stderr, "Failed to alloc ip\n");
		return;
	}
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	printf("\n[%04d-%02d-%02d %02d:%02d:%02d] Print leaks:\n",
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
	int sfd = bpf_map__fd(obj->maps.stack_traces);
	report_leak(syms_cache, ip, sfd, direct, "direct");
	report_leak(syms_cache, ip, sfd, indirect, "indirect");
	free(ip);
}

static void empty_table()
{
	cvector_free(frontier);
	frontier = NULL;
	cvector_free(key_table);
	key_table = NULL;
	HASH_CLEAR(hh, copied);
	HASH_CLEAR(hh, direct);
	HASH_CLEAR(hh, indirect);
}

static int do_leak_check(struct syms_cache *syms_cache)
{
	int ret = read_table();
	if (ret < 0)
		return ret;

	classify_all_chunks();
	for_each_chunk(collect_leaks_cb);
	report_leaks(syms_cache);
	return 0;
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct syms_cache *syms_cache = NULL;
	int err;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.pid == -1) {
		fprintf(stderr, "\'-p\' is a mandatory option\n");
		return -1;
	}
	libbpf_set_print(libbpf_print_fn);
	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "Failed to increase rlimit: %d\n", err);
		return -1;
	}
	obj = lsan_bpf__open();
	if (!obj) {
		fprintf(stderr, "Failed to open BPF object\n");
		return -1;
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
		fprintf(stderr, "Failed to load BPF object: %d\n", err);
		return -1;
	}
	err = attach_probes(obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs\n");
		fprintf(stderr, "Is this process alive? pid: %d\n", env.pid);
		return -1;
	}
	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "Failed to load syms\n");
		return -1;
	}
	char file_name[FILENAME_MAX];
	sprintf(file_name, "/proc/%d/mem", env.pid);
	fp_mem = fopen(file_name, "rb");
	if (fp_mem == NULL) {
		fprintf(stderr, "Failed to open: %s\n", file_name);
		return -1;
	}
	FILE *fp_suppression = fopen(suppression_path, "rt");
	if (fp_suppression == NULL) {
		fprintf(stderr, "Failed to open: %s\n", suppression_path);
	} else {
		char line[LINE_MAX];
		while (fgets(line, sizeof(line), fp_suppression) != NULL) {
			char v[SUPPR_MAX][PATH_MAX] = { {0, }, };
			int i = 0;
			char *ptr = strtok(line, ":");
			while (ptr != NULL) {
				memcpy(v[i], ptr, strlen(ptr));
				++i;
				ptr = strtok(NULL, ":");
			}
			if (strcmp(v[SUPPR_KIND], "leak") == 0) {
				char* str = (char*)malloc(sizeof(char)*(strlen(v[SUPPR_PATH]) + 1));
				memset(str, 0, strlen(v[SUPPR_PATH]) + 1);
				strncpy(str, v[SUPPR_PATH], strlen(v[SUPPR_PATH]));
				str[strlen(v[SUPPR_PATH])] = '\0';
				if (strlen(v[SUPPR_PATH]) - 1 >= 0 &&
						str[strlen(v[SUPPR_PATH]) - 1] == '\n') {
					str[strlen(v[SUPPR_PATH]) - 1] = '\0';
				}
				cvector_push_back(suppression, str);
			}
		}
	}
	do {
		sleep(env.duration);
		empty_table();
	} while (do_leak_check(syms_cache) == 0);

	// cleanup
	int i;
	for (i = 0; i < cvector_size(suppression); ++i) {
		free(suppression[i]);
	}
	cvector_free(suppression);
	fclose(fp_mem);
	syms_cache__free(syms_cache);
	cvector_free(frontier);
	cvector_free(key_table);
	lsan_bpf__destroy(obj);
	return 0;
}
