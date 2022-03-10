#ifndef __VMLINUX_DEFS_H__
#define __VMLINUX_DEFS_H__

#define BPF_F_USER_STACK                (1ULL << 8)

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY         0 /* create new element or update existing */
#define BPF_NOEXIST     1 /* create new element if it didn't exist */
#define BPF_EXIST       2 /* update existing element */
#define BPF_F_LOCK      4 /* spin_lock-ed map_lookup/map_update */

#endif /* __VMLINUX_DEFS_H__ */
