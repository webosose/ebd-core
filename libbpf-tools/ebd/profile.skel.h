/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __PROFILE_BPF_SKEL_H__
#define __PROFILE_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct profile_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *stackmap;
		struct bpf_map *counts;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *do_perf_event;
	} progs;
	struct {
		struct bpf_link *do_perf_event;
	} links;
	struct profile_bpf__rodata {
		bool kernel_stacks_only;
		bool user_stacks_only;
		bool include_idle;
		pid_t targ_pid;
		pid_t targ_tid;
	} *rodata;
};

static void
profile_bpf__destroy(struct profile_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
profile_bpf__create_skeleton(struct profile_bpf *obj);

static inline struct profile_bpf *
profile_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct profile_bpf *obj;
	int err;

	obj = (struct profile_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = profile_bpf__create_skeleton(obj);
	err = err ?: bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	profile_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct profile_bpf *
profile_bpf__open(void)
{
	return profile_bpf__open_opts(NULL);
}

static inline int
profile_bpf__load(struct profile_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct profile_bpf *
profile_bpf__open_and_load(void)
{
	struct profile_bpf *obj;
	int err;

	obj = profile_bpf__open();
	if (!obj)
		return NULL;
	err = profile_bpf__load(obj);
	if (err) {
		profile_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
profile_bpf__attach(struct profile_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
profile_bpf__detach(struct profile_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline int
profile_bpf__create_skeleton(struct profile_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		goto err;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "profile_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 3;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	s->maps[0].name = "stackmap";
	s->maps[0].map = &obj->maps.stackmap;

	s->maps[1].name = "counts";
	s->maps[1].map = &obj->maps.counts;

	s->maps[2].name = "profile_.rodata";
	s->maps[2].map = &obj->maps.rodata;
	s->maps[2].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "do_perf_event";
	s->progs[0].prog = &obj->progs.do_perf_event;
	s->progs[0].link = &obj->links.do_perf_event;

	s->data_sz = 6584;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x38\x16\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0e\0\
\x0d\0\xbf\x16\0\0\0\0\0\0\x85\0\0\0\x0e\0\0\0\xb7\x01\0\0\0\0\0\0\x7b\x1a\xf8\
\xff\0\0\0\0\x7b\x1a\xf0\xff\0\0\0\0\x7b\x1a\xe8\xff\0\0\0\0\x7b\x1a\xe0\xff\0\
\0\0\0\x7b\x1a\xd8\xff\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\x11\0\0\
\0\0\0\0\x55\x01\x04\0\0\0\0\0\xbf\x01\0\0\0\0\0\0\x67\x01\0\0\x20\0\0\0\x77\
\x01\0\0\x20\0\0\0\x15\x01\x4c\0\0\0\0\0\xbf\x01\0\0\0\0\0\0\x77\x01\0\0\x20\0\
\0\0\x18\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x34\0\0\0\0\0\0\x18\x02\0\0\xff\
\xff\xff\xff\0\0\0\0\0\0\0\0\x1d\x24\x02\0\0\0\0\0\x61\x33\0\0\0\0\0\0\x5d\x13\
\x42\0\0\0\0\0\x18\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x61\x34\0\0\0\0\0\0\x1d\x24\
\x04\0\0\0\0\0\x61\x32\0\0\0\0\0\0\x67\0\0\0\x20\0\0\0\x77\0\0\0\x20\0\0\0\x5d\
\x02\x3a\0\0\0\0\0\x63\x1a\xd8\xff\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xf0\
\xff\xff\xff\xb7\x02\0\0\x10\0\0\0\x85\0\0\0\x10\0\0\0\x18\x07\0\0\xff\xff\xff\
\xff\0\0\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\x11\0\0\0\0\0\0\
\x18\0\0\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\x55\x01\x07\0\0\0\0\0\xb7\x02\0\0\0\
\0\0\0\xbf\x61\0\0\0\0\0\0\x0f\x21\0\0\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xb7\x03\0\0\0\0\0\0\x85\0\0\0\x1b\0\0\0\x63\x0a\xec\xff\0\0\0\0\x18\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x71\x11\0\0\0\0\0\0\x55\x01\x08\0\0\0\0\0\xb7\x01\0\
\0\0\0\0\0\x0f\x16\0\0\0\0\0\0\xbf\x61\0\0\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\xb7\x03\0\0\0\x01\0\0\x85\0\0\0\x1b\0\0\0\xbf\x07\0\0\0\0\0\0\x63\x7a\
\xe8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xd8\xff\xff\xff\x18\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x55\0\x10\0\0\0\0\0\xbf\xa2\0\0\0\0\
\0\0\x07\x02\0\0\xd8\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x03\0\
\0\x10\0\0\0\0\0\0\0\0\0\0\0\xb7\x04\0\0\x01\0\0\0\x85\0\0\0\x02\0\0\0\x15\0\
\x01\0\0\0\0\0\x55\0\x08\0\xef\xff\xff\xff\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xd8\
\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x02\
\0\0\0\0\0\xb7\x01\0\0\x01\0\0\0\xdb\x10\0\0\0\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\
\0\0\0\0\0\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x47\x50\x4c\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x50\x04\0\0\x50\
\x04\0\0\x17\x05\0\0\0\0\0\0\0\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x07\0\0\0\x05\0\0\0\
\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\
\0\0\0\x02\0\0\0\x04\0\0\0\x04\0\0\0\0\0\0\0\x02\0\0\x04\x10\0\0\0\x19\0\0\0\
\x01\0\0\0\0\0\0\0\x1e\0\0\0\x05\0\0\0\x40\0\0\0\x27\0\0\0\0\0\0\x0e\x07\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x0c\0\0\0\x30\0\0\0\x05\0\0\x04\x28\0\0\0\
\x36\0\0\0\x0d\0\0\0\0\0\0\0\x3a\0\0\0\x0f\0\0\0\x40\0\0\0\x44\0\0\0\x02\0\0\0\
\x80\0\0\0\x52\0\0\0\x02\0\0\0\xa0\0\0\0\x60\0\0\0\x12\0\0\0\xc0\0\0\0\x65\0\0\
\0\0\0\0\x08\x0e\0\0\0\x6b\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\x78\0\0\0\0\0\0\
\x08\x10\0\0\0\x7e\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\x95\0\0\0\0\0\0\x01\x01\
\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x04\0\0\0\x10\0\0\0\0\0\
\0\0\0\0\0\x02\x14\0\0\0\x9a\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\x02\x16\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\x28\0\0\0\0\0\0\
\x04\0\0\x04\x20\0\0\0\x19\0\0\0\x09\0\0\0\0\0\0\0\xac\0\0\0\x0b\0\0\0\x40\0\0\
\0\xb0\0\0\0\x13\0\0\0\x80\0\0\0\xb6\0\0\0\x15\0\0\0\xc0\0\0\0\xc2\0\0\0\0\0\0\
\x0e\x17\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x1a\0\0\0\xc9\0\0\0\x03\0\0\x04\x20\
\x01\0\0\xdd\0\0\0\x1b\0\0\0\0\0\0\0\xe2\0\0\0\x0f\0\0\0\x80\x08\0\0\xf0\0\0\0\
\x0f\0\0\0\xc0\x08\0\0\xf5\0\0\0\0\0\0\x08\x1c\0\0\0\x08\x01\0\0\x04\0\0\x04\
\x10\x01\0\0\xdd\0\0\0\x1d\0\0\0\0\0\0\0\x15\x01\0\0\x0f\0\0\0\xc0\x07\0\0\x18\
\x01\0\0\x0f\0\0\0\0\x08\0\0\x1b\x01\0\0\x0f\0\0\0\x40\x08\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x0f\0\0\0\x04\0\0\0\x1f\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x22\
\x01\0\0\x19\0\0\0\x26\x01\0\0\x01\0\0\x0c\x1e\0\0\0\0\0\0\0\0\0\0\x0a\x21\0\0\
\0\0\0\0\0\0\0\0\x09\x22\0\0\0\x7f\x04\0\0\0\0\0\x08\x23\0\0\0\x84\x04\0\0\0\0\
\0\x01\x01\0\0\0\x08\0\0\x04\x8a\x04\0\0\0\0\0\x0e\x20\0\0\0\x01\0\0\0\x9d\x04\
\0\0\0\0\0\x0e\x20\0\0\0\x01\0\0\0\xae\x04\0\0\0\0\0\x0e\x20\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\x0a\x28\0\0\0\0\0\0\0\0\0\0\x09\x29\0\0\0\xbb\x04\0\0\0\0\0\x08\
\x2a\0\0\0\xc1\x04\0\0\0\0\0\x08\x02\0\0\0\xd0\x04\0\0\0\0\0\x0e\x27\0\0\0\x01\
\0\0\0\xd9\x04\0\0\0\0\0\x0e\x27\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x0a\x2e\0\0\0\
\xe2\x04\0\0\0\0\0\x08\x0f\0\0\0\xe6\x04\0\0\0\0\0\x0e\x2d\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x04\0\0\0\x04\0\0\0\xf9\x04\0\0\0\0\0\x0e\x30\0\
\0\0\x01\0\0\0\x01\x05\0\0\x02\0\0\x0f\0\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\x18\
\0\0\0\0\0\0\0\x20\0\0\0\x07\x05\0\0\x06\0\0\x0f\0\0\0\0\x24\0\0\0\0\0\0\0\x01\
\0\0\0\x25\0\0\0\0\0\0\0\x01\0\0\0\x26\0\0\0\0\0\0\0\x01\0\0\0\x2b\0\0\0\0\0\0\
\0\x04\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x2f\0\0\0\x10\0\0\0\x08\0\0\0\x0f\x05\
\0\0\x01\0\0\x0f\0\0\0\0\x31\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\0\x5f\x5f\
\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x74\x79\
\x70\x65\0\x6b\x65\x79\x5f\x73\x69\x7a\x65\0\x73\x74\x61\x63\x6b\x6d\x61\x70\0\
\x6b\x65\x79\x5f\x74\0\x70\x69\x64\0\x6b\x65\x72\x6e\x65\x6c\x5f\x69\x70\0\x75\
\x73\x65\x72\x5f\x73\x74\x61\x63\x6b\x5f\x69\x64\0\x6b\x65\x72\x6e\x5f\x73\x74\
\x61\x63\x6b\x5f\x69\x64\0\x6e\x61\x6d\x65\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\x36\x34\0\x6c\x6f\x6e\x67\
\x20\x6c\x6f\x6e\x67\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x63\
\x68\x61\x72\0\x6c\x6f\x6e\x67\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\
\x74\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\
\x65\x73\0\x63\x6f\x75\x6e\x74\x73\0\x62\x70\x66\x5f\x70\x65\x72\x66\x5f\x65\
\x76\x65\x6e\x74\x5f\x64\x61\x74\x61\0\x72\x65\x67\x73\0\x73\x61\x6d\x70\x6c\
\x65\x5f\x70\x65\x72\x69\x6f\x64\0\x61\x64\x64\x72\0\x62\x70\x66\x5f\x75\x73\
\x65\x72\x5f\x70\x74\x5f\x72\x65\x67\x73\x5f\x74\0\x75\x73\x65\x72\x5f\x70\x74\
\x5f\x72\x65\x67\x73\0\x73\x70\0\x70\x63\0\x70\x73\x74\x61\x74\x65\0\x63\x74\
\x78\0\x64\x6f\x5f\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\x74\0\x70\x65\x72\x66\
\x5f\x65\x76\x65\x6e\x74\0\x2f\x68\x6f\x6d\x65\x2f\x65\x73\x2e\x6c\x65\x65\x2f\
\x74\x6f\x6f\x6c\x73\x2f\x65\x62\x64\x2d\x63\x6f\x72\x65\x2f\x6c\x69\x62\x62\
\x70\x66\x2d\x74\x6f\x6f\x6c\x73\x2f\x70\x72\x6f\x66\x69\x6c\x65\x2e\x62\x70\
\x66\x2e\x63\0\x69\x6e\x74\x20\x64\x6f\x5f\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\
\x74\x28\x73\x74\x72\x75\x63\x74\x20\x62\x70\x66\x5f\x70\x65\x72\x66\x5f\x65\
\x76\x65\x6e\x74\x5f\x64\x61\x74\x61\x20\x2a\x63\x74\x78\x29\0\x09\x75\x36\x34\
\x20\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\
\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\x64\x28\x29\x3b\0\x09\x73\x74\x72\x75\
\x63\x74\x20\x6b\x65\x79\x5f\x74\x20\x6b\x65\x79\x20\x3d\x20\x7b\x7d\x3b\0\x09\
\x69\x66\x20\x28\x21\x69\x6e\x63\x6c\x75\x64\x65\x5f\x69\x64\x6c\x65\x20\x26\
\x26\x20\x74\x69\x64\x20\x3d\x3d\x20\x30\x29\0\x09\x69\x66\x20\x28\x74\x61\x72\
\x67\x5f\x70\x69\x64\x20\x21\x3d\x20\x2d\x31\x20\x26\x26\x20\x74\x61\x72\x67\
\x5f\x70\x69\x64\x20\x21\x3d\x20\x70\x69\x64\x29\0\x09\x69\x66\x20\x28\x74\x61\
\x72\x67\x5f\x74\x69\x64\x20\x21\x3d\x20\x2d\x31\x20\x26\x26\x20\x74\x61\x72\
\x67\x5f\x74\x69\x64\x20\x21\x3d\x20\x74\x69\x64\x29\0\x09\x75\x33\x32\x20\x74\
\x69\x64\x20\x3d\x20\x69\x64\x3b\0\x09\x6b\x65\x79\x2e\x70\x69\x64\x20\x3d\x20\
\x70\x69\x64\x3b\0\x09\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\
\x74\x5f\x63\x6f\x6d\x6d\x28\x26\x6b\x65\x79\x2e\x6e\x61\x6d\x65\x2c\x20\x73\
\x69\x7a\x65\x6f\x66\x28\x6b\x65\x79\x2e\x6e\x61\x6d\x65\x29\x29\x3b\0\x09\x69\
\x66\x20\x28\x75\x73\x65\x72\x5f\x73\x74\x61\x63\x6b\x73\x5f\x6f\x6e\x6c\x79\
\x29\0\x30\x3a\x30\0\x09\x09\x6b\x65\x79\x2e\x6b\x65\x72\x6e\x5f\x73\x74\x61\
\x63\x6b\x5f\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x73\x74\x61\
\x63\x6b\x69\x64\x28\x26\x63\x74\x78\x2d\x3e\x72\x65\x67\x73\x2c\x20\x26\x73\
\x74\x61\x63\x6b\x6d\x61\x70\x2c\x20\x30\x29\x3b\0\x09\x69\x66\x20\x28\x6b\x65\
\x72\x6e\x65\x6c\x5f\x73\x74\x61\x63\x6b\x73\x5f\x6f\x6e\x6c\x79\x29\0\x09\x09\
\x6b\x65\x79\x2e\x75\x73\x65\x72\x5f\x73\x74\x61\x63\x6b\x5f\x69\x64\x20\x3d\
\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x73\x74\x61\x63\x6b\x69\x64\x28\x26\x63\
\x74\x78\x2d\x3e\x72\x65\x67\x73\x2c\x20\x26\x73\x74\x61\x63\x6b\x6d\x61\x70\
\x2c\x20\x42\x50\x46\x5f\x46\x5f\x55\x53\x45\x52\x5f\x53\x54\x41\x43\x4b\x29\
\x3b\0\x2f\x68\x6f\x6d\x65\x2f\x65\x73\x2e\x6c\x65\x65\x2f\x74\x6f\x6f\x6c\x73\
\x2f\x65\x62\x64\x2d\x63\x6f\x72\x65\x2f\x6c\x69\x62\x62\x70\x66\x2d\x74\x6f\
\x6f\x6c\x73\x2f\x2e\x2f\x6d\x61\x70\x73\x2e\x62\x70\x66\x2e\x68\0\x09\x76\x61\
\x6c\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\
\x65\x6c\x65\x6d\x28\x6d\x61\x70\x2c\x20\x6b\x65\x79\x29\x3b\0\x09\x69\x66\x20\
\x28\x76\x61\x6c\x29\0\x09\x65\x72\x72\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\
\x5f\x75\x70\x64\x61\x74\x65\x5f\x65\x6c\x65\x6d\x28\x6d\x61\x70\x2c\x20\x6b\
\x65\x79\x2c\x20\x69\x6e\x69\x74\x2c\x20\x42\x50\x46\x5f\x4e\x4f\x45\x58\x49\
\x53\x54\x29\x3b\0\x09\x69\x66\x20\x28\x65\x72\x72\x20\x26\x26\x20\x65\x72\x72\
\x20\x21\x3d\x20\x2d\x45\x45\x58\x49\x53\x54\x29\0\x09\x72\x65\x74\x75\x72\x6e\
\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\
\x6d\x28\x6d\x61\x70\x2c\x20\x6b\x65\x79\x29\x3b\0\x09\x69\x66\x20\x28\x76\x61\
\x6c\x70\x29\0\x09\x09\x5f\x5f\x73\x79\x6e\x63\x5f\x66\x65\x74\x63\x68\x5f\x61\
\x6e\x64\x5f\x61\x64\x64\x28\x76\x61\x6c\x70\x2c\x20\x31\x29\x3b\0\x7d\0\x62\
\x6f\x6f\x6c\0\x5f\x42\x6f\x6f\x6c\0\x6b\x65\x72\x6e\x65\x6c\x5f\x73\x74\x61\
\x63\x6b\x73\x5f\x6f\x6e\x6c\x79\0\x75\x73\x65\x72\x5f\x73\x74\x61\x63\x6b\x73\
\x5f\x6f\x6e\x6c\x79\0\x69\x6e\x63\x6c\x75\x64\x65\x5f\x69\x64\x6c\x65\0\x70\
\x69\x64\x5f\x74\0\x5f\x5f\x6b\x65\x72\x6e\x65\x6c\x5f\x70\x69\x64\x5f\x74\0\
\x74\x61\x72\x67\x5f\x70\x69\x64\0\x74\x61\x72\x67\x5f\x74\x69\x64\0\x75\x36\
\x34\0\x64\x6f\x5f\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\x74\x2e\x7a\x65\x72\x6f\
\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\x74\
\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\
\x14\0\0\0\x2c\x02\0\0\x40\x02\0\0\x2c\0\0\0\x08\0\0\0\x34\x01\0\0\x01\0\0\0\0\
\0\0\0\x1f\0\0\0\x10\0\0\0\x34\x01\0\0\x22\0\0\0\0\0\0\0\x3f\x01\0\0\x76\x01\0\
\0\0\xcc\0\0\x08\0\0\0\x3f\x01\0\0\xa9\x01\0\0\x0b\xd4\0\0\x18\0\0\0\x3f\x01\0\
\0\xcf\x01\0\0\x0f\xe8\0\0\x40\0\0\0\x3f\x01\0\0\xe7\x01\0\0\x07\xf0\0\0\x58\0\
\0\0\x3f\x01\0\0\xe7\x01\0\0\x14\xf0\0\0\x80\0\0\0\x3f\x01\0\0\0\0\0\0\0\0\0\0\
\x90\0\0\0\x3f\x01\0\0\x07\x02\0\0\x06\xfc\0\0\xb8\0\0\0\x3f\x01\0\0\x07\x02\0\
\0\x15\xfc\0\0\xc0\0\0\0\x3f\x01\0\0\x07\x02\0\0\x18\xfc\0\0\xc8\0\0\0\x3f\x01\
\0\0\x07\x02\0\0\x06\xfc\0\0\xd0\0\0\0\x3f\x01\0\0\x2f\x02\0\0\x06\x04\x01\0\
\xe8\0\0\0\x3f\x01\0\0\x2f\x02\0\0\x15\x04\x01\0\xf0\0\0\0\x3f\x01\0\0\x2f\x02\
\0\0\x18\x04\x01\0\xf8\0\0\0\x3f\x01\0\0\x57\x02\0\0\x0c\xdc\0\0\x08\x01\0\0\
\x3f\x01\0\0\x2f\x02\0\0\x06\x04\x01\0\x10\x01\0\0\x3f\x01\0\0\x66\x02\0\0\x0a\
\x10\x01\0\x18\x01\0\0\x3f\x01\0\0\x76\x02\0\0\x17\x14\x01\0\x28\x01\0\0\x3f\
\x01\0\0\x76\x02\0\0\x02\x14\x01\0\x48\x01\0\0\x3f\x01\0\0\xaa\x02\0\0\x06\x1c\
\x01\0\x70\x01\0\0\x3f\x01\0\0\xaa\x02\0\0\x06\x1c\x01\0\x90\x01\0\0\x3f\x01\0\
\0\xc5\x02\0\0\x17\x28\x01\0\xb0\x01\0\0\x3f\x01\0\0\xc5\x02\0\0\x15\x28\x01\0\
\xb8\x01\0\0\x3f\x01\0\0\x06\x03\0\0\x06\x30\x01\0\xd0\x01\0\0\x3f\x01\0\0\x06\
\x03\0\0\x06\x30\x01\0\xe8\x01\0\0\x3f\x01\0\0\x1f\x03\0\0\x17\x3c\x01\0\x18\
\x02\0\0\x3f\x01\0\0\x1f\x03\0\0\x15\x3c\x01\0\x30\x02\0\0\x6f\x03\0\0\xa5\x03\
\0\0\x08\x3c\0\0\x48\x02\0\0\x6f\x03\0\0\xcb\x03\0\0\x06\x40\0\0\x58\x02\0\0\
\x6f\x03\0\0\xd5\x03\0\0\x08\x4c\0\0\x90\x02\0\0\x6f\x03\0\0\x0e\x04\0\0\x0a\
\x50\0\0\xa8\x02\0\0\x6f\x03\0\0\x2a\x04\0\0\x09\x5c\0\0\xc8\x02\0\0\x3f\x01\0\
\0\x51\x04\0\0\x06\x74\x01\0\xd8\x02\0\0\x3f\x01\0\0\x5c\x04\0\0\x03\x78\x01\0\
\xe0\x02\0\0\x3f\x01\0\0\x7d\x04\0\0\x01\x84\x01\0\x10\0\0\0\x34\x01\0\0\x02\0\
\0\0\x78\x01\0\0\x1a\0\0\0\xc1\x02\0\0\0\0\0\0\xd8\x01\0\0\x1a\0\0\0\xc1\x02\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x02\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\x01\0\0\0\0\x02\0\x80\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xea\0\0\0\0\0\x02\0\xe0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf2\0\0\0\
\0\0\x02\0\xd0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe3\0\0\0\0\0\x02\0\x10\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xdc\0\0\0\0\0\x02\0\xb0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x10\x01\0\0\0\0\x02\0\x18\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf9\0\0\0\0\0\x02\0\
\xd0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6b\0\0\0\x01\0\x03\0\x10\0\0\0\0\0\0\0\
\x08\0\0\0\0\0\0\0\x01\x01\0\0\0\0\x02\0\xa0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x47\0\0\0\x12\0\x02\0\0\0\0\
\0\0\0\0\0\xf0\x02\0\0\0\0\0\0\x94\0\0\0\x11\0\x03\0\x02\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\xaa\0\0\0\x11\0\x03\0\x04\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\xa1\0\0\0\
\x11\0\x03\0\x08\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x01\0\0\0\x11\0\x03\0\x01\0\0\
\0\0\0\0\0\x01\0\0\0\0\0\0\0\x62\0\0\0\x11\0\x04\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\
\0\0\0\x12\0\0\0\x11\0\x03\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x55\0\0\0\x11\0\
\x04\0\x10\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\xd4\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\
\0\x04\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\0\x0d\0\0\0\x90\0\0\0\0\0\0\0\
\x01\0\0\0\x0e\0\0\0\xd0\0\0\0\0\0\0\0\x01\0\0\0\x0f\0\0\0\x48\x01\0\0\0\0\0\0\
\x01\0\0\0\x10\0\0\0\x90\x01\0\0\0\0\0\0\x01\0\0\0\x11\0\0\0\xb8\x01\0\0\0\0\0\
\0\x01\0\0\0\x12\0\0\0\xf0\x01\0\0\0\0\0\0\x01\0\0\0\x11\0\0\0\x30\x02\0\0\0\0\
\0\0\x01\0\0\0\x13\0\0\0\x60\x02\0\0\0\0\0\0\x01\0\0\0\x13\0\0\0\x70\x02\0\0\0\
\0\0\0\x01\0\0\0\x0b\0\0\0\xb0\x02\0\0\0\0\0\0\x01\0\0\0\x13\0\0\0\xe8\x03\0\0\
\0\0\0\0\x04\0\0\0\x11\0\0\0\xf4\x03\0\0\0\0\0\0\x04\0\0\0\x13\0\0\0\x0c\x04\0\
\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x18\x04\0\0\0\0\0\0\x03\0\0\0\x10\0\0\0\x24\x04\
\0\0\0\0\0\0\x03\0\0\0\x0d\0\0\0\x30\x04\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x3c\
\x04\0\0\0\0\0\0\x03\0\0\0\x0f\0\0\0\x48\x04\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\
\x60\x04\0\0\0\0\0\0\x04\0\0\0\x14\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x40\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x60\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x80\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xa0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xc0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xd0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\xe0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xf0\0\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\0\
\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x10\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\
\x20\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x30\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\
\0\x40\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x50\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\
\0\0\x60\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x70\x01\0\0\0\0\0\0\x04\0\0\0\x01\
\0\0\0\x80\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x90\x01\0\0\0\0\0\0\x04\0\0\0\
\x01\0\0\0\xa0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xb0\x01\0\0\0\0\0\0\x04\0\0\
\0\x01\0\0\0\xc0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xd0\x01\0\0\0\0\0\0\x04\0\
\0\0\x01\0\0\0\xe0\x01\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\xf0\x01\0\0\0\0\0\0\x04\
\0\0\0\x01\0\0\0\0\x02\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x10\x02\0\0\0\0\0\0\x04\
\0\0\0\x01\0\0\0\x20\x02\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x30\x02\0\0\0\0\0\0\
\x04\0\0\0\x01\0\0\0\x40\x02\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x50\x02\0\0\0\0\0\
\0\x04\0\0\0\x01\0\0\0\x6c\x02\0\0\0\0\0\0\x04\0\0\0\x01\0\0\0\x7c\x02\0\0\0\0\
\0\0\x04\0\0\0\x01\0\0\0\x12\x18\x16\x13\x14\x15\x0a\x17\x19\x1a\0\x75\x73\x65\
\x72\x5f\x73\x74\x61\x63\x6b\x73\x5f\x6f\x6e\x6c\x79\0\x6b\x65\x72\x6e\x65\x6c\
\x5f\x73\x74\x61\x63\x6b\x73\x5f\x6f\x6e\x6c\x79\0\x2e\x74\x65\x78\x74\0\x2e\
\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x2e\x72\x65\x6c\x70\x65\x72\x66\
\x5f\x65\x76\x65\x6e\x74\0\x64\x6f\x5f\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\x74\
\0\x63\x6f\x75\x6e\x74\x73\0\x2e\x6d\x61\x70\x73\0\x73\x74\x61\x63\x6b\x6d\x61\
\x70\0\x64\x6f\x5f\x70\x65\x72\x66\x5f\x65\x76\x65\x6e\x74\x2e\x7a\x65\x72\x6f\
\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\
\x73\x65\0\x69\x6e\x63\x6c\x75\x64\x65\x5f\x69\x64\x6c\x65\0\x74\x61\x72\x67\
\x5f\x74\x69\x64\0\x74\x61\x72\x67\x5f\x70\x69\x64\0\x2e\x73\x74\x72\x74\x61\
\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\
\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x4c\x42\x42\x30\x5f\x38\0\
\x4c\x42\x42\x30\x5f\x36\0\x4c\x42\x42\x30\x5f\x31\x35\0\x4c\x42\x42\x30\x5f\
\x34\0\x4c\x42\x42\x30\x5f\x31\x34\0\x4c\x42\x42\x30\x5f\x31\x33\0\x4c\x42\x42\
\x30\x5f\x32\0\x4c\x42\x42\x30\x5f\x31\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x25\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x4a\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\
\0\0\xf0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc3\
\0\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x03\0\0\0\0\0\0\x18\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5c\0\0\0\x01\0\0\
\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x03\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x8c\0\0\0\x01\0\0\0\x03\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x78\x03\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xcf\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x7c\x03\0\0\0\0\0\0\x7f\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x2f\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfb\
\x0c\0\0\0\0\0\0\x8c\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\xbb\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\x0f\0\0\0\0\0\
\0\xf8\x01\0\0\0\0\0\0\x0d\0\0\0\x0c\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\
\x38\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x11\0\0\0\0\0\0\xb0\0\
\0\0\0\0\0\0\x08\0\0\0\x02\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xcb\0\0\0\
\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x30\x12\0\0\0\0\0\0\x90\0\0\0\0\0\0\
\0\x08\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x2b\0\0\0\x09\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\x12\0\0\0\0\0\0\x50\x02\0\0\0\0\0\0\x08\0\
\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x7e\0\0\0\x03\x4c\xff\x6f\0\
\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x10\x15\0\0\0\0\0\0\x0a\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb3\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x1a\x15\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -ENOMEM;
}

#endif /* __PROFILE_BPF_SKEL_H__ */
