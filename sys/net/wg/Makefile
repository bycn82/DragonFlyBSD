# $DragonFlyBSD$

KMOD= if_wg

SRCS = if_wg.c wg_noise.c wg_cookie.c 
SRCS+= wg_support.c
SRCS+= opt_inet.h opt_inet6.h

opt_inet.h:
	echo "#define INET 1" > ${.TARGET}

opt_inet6.h:
	echo "#define INET6 1" > ${.TARGET}

.PATH: ${.CURDIR}/crypto
SRCS+= crypto.c

.PATH: ${.CURDIR}/crypto/siphash
SRCS+= siphash.c

.include <bsd.kmod.mk>
