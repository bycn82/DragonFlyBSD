#ifndef __WG_DEBUG_H__
#define __WG_DEBUG_H__

#include <sys/types.h>
#include <sys/systm.h>

#define WG_DEBUG

#ifdef WG_DEBUG
#define wg_debug( _fmt, ... ) \
	kprintf( "wg: "_fmt, ##__VA_ARGS__ )
#else
#define wg_debug( _fmt, ... )
#endif


#endif /* __WG_DEBUG_H__ */
