#include <sys/refcount.h>
#include "wg_support.h"

inline int
time_expired(struct timespec *time, uint32_t sec, uint32_t nsec)
{
	struct timespec uptime;
	struct timespec expire = { .tv_sec=sec, .tv_nsec=nsec};
	getnanouptime(&uptime);
	timespecadd(time, &expire, &expire);
	return timespeccmp(&uptime, &expire, >) ? ETIMEDOUT : 0;
}

inline bool
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
