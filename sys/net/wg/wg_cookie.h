/* SPDX-License-Identifier: ISC
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2021 Matt Dunwoodie <ncon@noconroy.net>
 */

#ifndef __COOKIE_H__
#define __COOKIE_H__

#include <netinet/in.h>

#include "crypto/siphash/siphash.h"
#include "crypto/crypto.h"
#include "wg_support.h"

#ifndef _KERNEL
#error "This file should not be included by userland programs."
#endif

#define COOKIE_MAC_SIZE		16
#define COOKIE_KEY_SIZE		32
#define COOKIE_NONCE_SIZE	XCHACHA20POLY1305_NONCE_SIZE
#define COOKIE_COOKIE_SIZE	16
#define COOKIE_SECRET_SIZE	32
#define COOKIE_INPUT_SIZE	32
#define COOKIE_ENCRYPTED_SIZE	(COOKIE_COOKIE_SIZE + COOKIE_MAC_SIZE)

struct cookie_macs {
	uint8_t	mac1[COOKIE_MAC_SIZE];
	uint8_t	mac2[COOKIE_MAC_SIZE];
};

struct cookie_maker {
	uint8_t		cm_mac1_key[COOKIE_KEY_SIZE];
	uint8_t		cm_cookie_key[COOKIE_KEY_SIZE];

	struct lock	cm_lock;
	bool		cm_cookie_valid;
	uint8_t		cm_cookie[COOKIE_COOKIE_SIZE];
	struct timespec	cm_cookie_birthdate;	
	bool		cm_mac1_sent;
	uint8_t		cm_mac1_last[COOKIE_MAC_SIZE];
};

struct cookie_checker {
	struct lock	cc_key_lock;
	uint8_t		cc_mac1_key[COOKIE_KEY_SIZE];
	uint8_t		cc_cookie_key[COOKIE_KEY_SIZE];

	struct lock	cc_secret_lock;
	struct timespec	cc_secret_birthdate;
	uint8_t		cc_secret[COOKIE_SECRET_SIZE];
};

int	cookie_init(void);
void	cookie_deinit(void);
void	cookie_checker_init(struct cookie_checker *);
void	cookie_checker_free(struct cookie_checker *);
void	cookie_checker_update(struct cookie_checker *,
	    const uint8_t[COOKIE_INPUT_SIZE]);
void	cookie_checker_create_payload(struct cookie_checker *,
	    struct cookie_macs *cm, uint8_t[COOKIE_NONCE_SIZE],
	    uint8_t [COOKIE_ENCRYPTED_SIZE], struct sockaddr *);
void	cookie_maker_init(struct cookie_maker *, const uint8_t[COOKIE_INPUT_SIZE]);
void	cookie_maker_free(struct cookie_maker *);
int	cookie_maker_consume_payload(struct cookie_maker *,
	    uint8_t[COOKIE_NONCE_SIZE], uint8_t[COOKIE_ENCRYPTED_SIZE]);
void	cookie_maker_mac(struct cookie_maker *, struct cookie_macs *,
	    void *, size_t);
int	cookie_checker_validate_macs(struct cookie_checker *,
	    struct cookie_macs *, void *, size_t, bool, struct sockaddr *);

#endif /* __COOKIE_H__ */
