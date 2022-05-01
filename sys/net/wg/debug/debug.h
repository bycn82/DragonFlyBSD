#ifndef __WG_DEBUG_H__
#define __WG_DEBUG_H__

/* This file contains tools for debug */

#include <sys/time.h>
#include <sys/timex.h>
#include <sys/malloc.h>
#include "../wg_support.h"

#ifndef _KERNEL
#error "This file should not be included by userland programs."
#endif

static inline long
get_nsec(void)
{
	struct timespec uptime;
	nanouptime(&uptime);
	return uptime.tv_sec * NANOSECOND + uptime.tv_nsec;

}

#define WG_DEBUG

#ifdef WG_DEBUG
#define wg_debug(_fmt, ... ){ \
	kprintf( "[wg %5d] [%30s]", __LINE__, __FUNCTION__ ); \
	kprintf( " "_fmt , ##__VA_ARGS__ ); \
	kprintf( "\n");  \
}

#define wg_debug_ip(_tag, _s) { \
	unsigned char sip[16]; \
	kinet_ntoa(_s, sip); \
	wg_debug("[%s] %s", _tag, sip); \
}

#else
#define wg_debug( _fmt, ... )
#define wg_debug_ip(_tag, _s)
#endif

//#define WG_DEBUG_IOCTL
#if defined(WG_DEBUG) && defined(WG_DEBUG_IOCTL)
#define wg_debug_ioctl(_fmt, ...) wg_debug(_fmt, ##__VA_ARGS__)
#else
#define wg_debug_ioctl(_fmt, ...)
#endif

//#define WG_DEBUG_PKT
#if defined(WG_DEBUG) && defined(WG_DEBUG_PKT)
#define wg_debug_pkt_timer_define()  \
	long p_debug_timer;\
	long p_debug_timer_last;

#define wg_debug_pkt_timer_init(_p) { \
	(_p)->p_debug_timer = get_nsec();\
	(_p)->p_debug_timer_last = (_p)->p_debug_timer; \
}

#define wg_debug_pkt_timer(_p) { \
	long t0, t1, ms, us, ms0, us0;  \
	t0 = (_p)->p_debug_timer_last; \
	t1 = (_p)->p_debug_timer_last = get_nsec();\
	us = (t1-t0) / 1000; \
	ms = us / 1000; \
	us = us % 1000; \
	us0 = (t1-(_p)->p_debug_timer) / 1000; \
	ms0 = us0 / 1000; \
	us0 = us0 % 1000; \
	wg_debug("[%ld] %ld.%ld/%ld.%ld", \
		(_p)->p_debug_timer, \
		ms0, us0, \
		ms, us\
		);\
}

#define wg_debug_pkt_timer_print(_fmt, ...) wg_debug(_fmt, ##__VA_ARGS__)
#else
#define wg_debug_pkt_timer_define() 
#define wg_debug_pkt_timer_init(p)
#define wg_debug_pkt_timer(p)
#define wg_debug_pkt_timer_print(_fmt, ...)
#endif /* WG_DEBUG_PKT */


//#define WG_DEBUG_INPUT
#if defined(WG_DEBUG) && defined(WG_DEBUG_INPUT)
#define wg_debug_input(_fmt, ...) wg_debug(_fmt, ##__VA_ARGS__)
#define wg_debug_input_ip(_tag, _s) wg_debug_ip(_tag, _s)
#else
#define wg_debug_input(_fmt, ...)
#define wg_debug_input_ip(_tag, _s)
#endif

//#define WG_DEBUG_OUTPUT
#if defined(WG_DEBUG) && defined(WG_DEBUG_OUTPUT)
#define wg_debug_output(_fmt, ...) wg_debug(_fmt, ##__VA_ARGS__)
#define wg_debug_output_ip(_tag, _s) wg_debug_ip(_tag, _s)
#else
#define wg_debug_output(_fmt, ...)
#define wg_debug_output_ip(_tag, _s)
#endif

//#define WG_DEBUG_FUNC
#if defined(WG_DEBUG) && defined(WG_DEBUG_FUNC)
#define wg_debug_func() wg_debug()
#else
#define wg_debug_func()
#endif

//#define WG_DEBUG_LOCK
#if defined(WG_DEBUG) && defined(WG_DEBUG_LOCK)
#define wg_debug_lock(_fmt, ...) wg_debug(_fmt, ##__VA_ARGS__)
#else
#define wg_debug_lock(_fmt, ...)
#endif

//#define WG_DEBUG_TASK
#if defined(WG_DEBUG) && defined(WG_DEBUG_TASK)
#define wg_debug_task(_fmt, ...) wg_debug(_fmt, ##__VA_ARGS__)
#else
#define wg_debug_task(_fmt, ...)
#endif

#endif /* __WG_DEBUG_H__ */


