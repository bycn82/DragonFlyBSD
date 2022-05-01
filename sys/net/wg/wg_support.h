#ifndef __WG_SUPPORT_H__
#define __WG_SUPPORT_H__

#include <sys/time.h>

#ifndef _KERNEL
#error "This file should not be included by userland programs."
#endif

int time_expired(struct timespec*, uint32_t, uint32_t);
bool refcount_acquire_if_not_zero(volatile u_int*);

#define MSEC_2_TICKS(m) max(1, (uint32_t)((hz == 1000) ? \
	  (m) : ((uint64_t)(m) * (uint64_t)hz)/(uint64_t)1000))
#define SO_USER_COOKIE 0x1015
#define M_PROTOFLAGS M_PROTO1 | M_PROTO2 | M_PROTO3 | M_PROTO4 |  \
		     M_PROTO5 | M_PROTO6 | M_PROTO7 | M_PROTO8

#ifndef atomic_load_acq_bool
#define atomic_load_acq_bool(p) atomic_load_acq_char((char*)(p))
#endif

#ifndef atomic_store_rel_bool
#define atomic_store_rel_bool(p,v) atomic_store_rel_char((char*)(p),(char)(v))
#endif

#define load_ptr(p)	(__volatile__ __typeof__(p))atomic_load_acq_ptr(&p)
#define store_ptr(p,v)	atomic_store_rel_ptr(&p, (u_long)(v));

#define explicit_bzero(a,b) bzero(a,b)

#endif /* __WG_SUPPORT_H__ */
