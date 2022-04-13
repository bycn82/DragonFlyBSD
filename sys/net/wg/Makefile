# $DragonFlyBSD$

KMOD= if_wg

SRCS= opt_inet.h opt_inet6.h
SRCS+= if_wg.c wg_noise.c wg_cookie.c crypto/crypto.c crypto/siphash/siphash.c

.include <bsd.kmod.mk>
