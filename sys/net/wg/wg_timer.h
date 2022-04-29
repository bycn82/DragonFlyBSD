#ifndef __WG_TIMER_H__
#define __WG_TIMER_H__

#include <sys/time.h>

#ifndef _KERNEL
#error "This file should not be included by userland programs."
#endif

#define NSEC_PER_SEC 1000000000L
static inline int
timer_expired(struct timespec *timer, uint32_t sec, uint32_t nsec)
{
	struct timespec uptime;
	struct timespec expire = { .tv_sec=sec, .tv_nsec=nsec};
	getnanouptime(&uptime);
	timespecadd(timer, &expire, &expire);
	return timespeccmp(&uptime, &expire, >) ? ETIMEDOUT : 0;
}

static inline long
get_nsec(void)
{
	struct timespec uptime;
	nanouptime(&uptime);
	return uptime.tv_sec * NSEC_PER_SEC + uptime.tv_nsec;

}

#endif /* __WG_TIMER_H__ */
