#ifndef __WG_DRAGONFLYBSD_H__
#define __WG_DRAGONFLYBSD_H__

/* This file contains tools for porting wireguard from FreeBSD */

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/taskqueue.h>
#include <sys/lock.h>
#include <sys/thread2.h>
#include <machine/atomic.h>

#define WG_MALLOC_DEFINE()		MALLOC_DEFINE(M_WG, "WG", "wg")
#define WG_MALLOC(_size)		kmalloc(_size, M_WG, M_NOWAIT | M_ZERO)
#define WG_FREE(_p)			kfree(_p, M_WG)

#define WG_NOISE_MALLOC_DEFINE()	MALLOC_DEFINE(M_WG_NOISE, "WG_NOISE", "wg noise")
#define WG_NOISE_MALLOC(_size)		kmalloc(_size, M_WG_NOISE, M_NOWAIT | M_ZERO)
#define WG_NOISE_FREE(_p)		kfree(_p, M_WG_NOISE)

#define WG_COOKIE_MALLOC_DEFINE()	MALLOC_DEFINE(M_WG_COOKIE, "WG_COOKIE", "wg noise")
#define WG_COOKIE_MALLOC(_size)		kmalloc(_size, M_WG_COOKIE, M_NOWAIT | M_ZERO)
#define WG_COOKIE_FREE(_p)		kfree(_p, M_WG_COOKIE)

static inline void 
wg_empty_func(void){
};

#define WG_TASKQUEUE_DEFINE()			TASKQUEUE_DEFINE(wg_tq, NULL, NULL, wg_empty_func())
#define WG_TASK_INIT(_task, _func, _ctx)	TASK_INIT(&(_task), 0, (task_fn_t*)(_func), _ctx)
#define WG_TASK_DRAIN(_task)			taskqueue_drain(taskqueue_wg_tq, &(_task))
#define WG_TASK_ENQUEUE(_task)			taskqueue_enqueue(taskqueue_wg_tq, &(_task))
#define WG_TASK_PENDING(_task)			((_task).ta_pending != 0)

#define WG_LOCK_INIT(_lk, _msg)		lockinit(_lk, _msg, 0, LK_CANRECURSE)
#define WG_LOCK_UNINIT(_lk)		lockuninit(_lk)
#define WG_LOCK(_lk)			lockmgr(_lk, LK_EXCLUSIVE)
#define WG_SLOCK(_lk)			lockmgr(_lk, LK_SHARED)
#define WG_UNLOCK(_lk)			lockmgr(_lk, LK_RELEASE)

#define MPASS(ex)	\
	 KASSERT((ex), ("Assertion %s failed at %s:%d", #ex, __FILE__, __LINE__))
#define wmb()   __asm __volatile("sfence;" : : : "memory")

#ifndef atomic_load_acq_bool
#define atomic_load_acq_bool(p) atomic_load_acq_char((char*)(p))
#endif

#ifndef atomic_store_rel_bool
#define atomic_store_rel_bool(p,v) atomic_store_rel_char((char*)(p),(char)(v))
#endif

#define load_ptr(p)	(__volatile__ __typeof__(p))atomic_load_acq_ptr(&p)
#define store_ptr(p,v)	atomic_store_rel_ptr(&p, (u_long)(v));

#define WG_CRIT_ENTER() crit_enter_id("WG")
#define WG_CRIT_EXIT()	crit_exit_id("WG")
#define WG_CRIT_WAIT() {\
	WG_CRIT_ENTER();\
	WG_CRIT_EXIT();\
}
#define WG_CRIT_CALL(f,p) {\
	WG_CRIT_ENTER();\
	f(p); \
	WG_CRIT_EXIT();\
}

#define MSEC_2_TICKS(m) max(1, (uint32_t)((hz == 1000) ? \
	  (m) : ((uint64_t)(m) * (uint64_t)hz)/(uint64_t)1000))

#define SO_USER_COOKIE 0x1015

#define IF_LINK_STATE_CHANGE(ifp, state) {\
	if (ifp->if_link_state != state) {\
		ifp->if_link_state = state;\
		if_link_state_change(ifp);\
	}\
}


static inline bool
refcount_acquire_if_not_zero(volatile u_int *count)
{
	u_int old;
	for(;;) {
		old = atomic_load_acq_int(count);
		if (old <= 0)
			return (false);
		if (__predict_false(((old) & (1U << 31)) != 0) )
			return (true);
		if (atomic_fcmpset_int(count, &old, old + 1))
			return (true);
	}
}

// TODO
#define explicit_bzero(a,b)  bzero(a,b)

#endif /* __WG_DRAGONFLYBSD_H__ */
