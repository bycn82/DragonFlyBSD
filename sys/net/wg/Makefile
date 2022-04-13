# $DragonFlyBSD$

KMOD= if_wg

SRCS = if_wg.c wg_noise.c wg_cookie.c 

.PATH: ${.CURDIR}/crypto
SRCS+= crypto.c

.PATH: ${.CURDIR}/crypto/siphash
SRCS+= siphash.c

.include <bsd.kmod.mk>
