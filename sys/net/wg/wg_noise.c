/* SPDX-License-Identifier: ISC
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2021 Matt Dunwoodie <ncon@noconroy.net>
 */

#include <sys/refcount.h>
#include <sys/endian.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/lock.h>

#include "crypto/siphash/siphash.h"
#include "crypto/crypto.h"
#include "wg_noise.h"
#include "wg_support.h"

/* Protocol string constants */
#define NOISE_HANDSHAKE_NAME	"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
#define NOISE_IDENTIFIER_NAME	"WireGuard v1 zx2c4 Jason@zx2c4.com"

/* Constants for the counter */
#define COUNTER_BITS_TOTAL	8192
#ifdef __LP64__
#define COUNTER_ORDER		6
#define COUNTER_BITS		64
#else
#define COUNTER_ORDER		5
#define COUNTER_BITS		32
#endif
#define COUNTER_REDUNDANT_BITS	COUNTER_BITS
#define COUNTER_WINDOW_SIZE	(COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS)

/* Constants for the keypair */
#define REKEY_AFTER_MESSAGES	(1ull << 60)
#define REJECT_AFTER_MESSAGES	(UINT64_MAX - COUNTER_WINDOW_SIZE - 1)
#define REKEY_AFTER_TIME	120
#define REKEY_AFTER_TIME_RECV	165
#define REJECT_INTERVAL		(1000000000 / 50) /* fifty times per sec */
/* 24 = floor(log2(REJECT_INTERVAL)) */
#define REJECT_INTERVAL_MASK	(~((1ull<<24)-1))
#define TIMER_RESET		(struct timespec){ -(REKEY_TIMEOUT+1), 0}

#define HT_INDEX_SIZE		(1 << 13)
#define HT_INDEX_MASK		(HT_INDEX_SIZE - 1)
#define HT_REMOTE_SIZE		(1 << 11)
#define HT_REMOTE_MASK		(HT_REMOTE_SIZE - 1)
#define MAX_REMOTE_PER_LOCAL	(1 << 20)

MALLOC_DEFINE(M_WG_NOISE, "WG_NOISE", "wg noise");
#define WG_MALLOC(_size) \
	kmalloc(_size, M_WG_NOISE, M_NOWAIT | M_ZERO)
#define WG_FREE(_p) \
	kfree(_p, M_WG_NOISE)

struct noise_index {
	LIST_ENTRY(noise_index)		 i_entry;
	uint32_t			 i_local_index;
	uint32_t			 i_remote_index;
	int				 i_is_keypair;
};

struct noise_keypair {
	struct noise_index		 kp_index;
	struct lock			 kp_lock;

	u_int				 kp_refcnt;
	bool				 kp_can_send;
	bool				 kp_is_initiator;
	struct timespec			 kp_birthdate; 
	struct noise_remote		*kp_remote;

	uint8_t				 kp_send[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t				 kp_recv[NOISE_SYMMETRIC_KEY_LEN];

	/* Counter elements */
	struct lock			 kp_nonce_lock;
	uint64_t			 kp_nonce_send;
	uint64_t			 kp_nonce_recv;
	unsigned long			 kp_backtrack[COUNTER_BITS_TOTAL / COUNTER_BITS];
};

struct noise_handshake {
	uint8_t	 			 hs_e[NOISE_PUBLIC_KEY_LEN];
	uint8_t	 			 hs_hash[NOISE_HASH_LEN];
	uint8_t	 			 hs_ck[NOISE_HASH_LEN];
};

enum noise_handshake_state {
	HANDSHAKE_DEAD,
	HANDSHAKE_INITIATOR,
	HANDSHAKE_RESPONDER,
};

struct noise_remote {
	struct noise_index		 r_index;
	struct lock			 r_lock;

	LIST_ENTRY(noise_remote) 	 r_entry;
	bool				 r_entry_inserted;
	uint8_t				 r_public[NOISE_PUBLIC_KEY_LEN];

	struct lock			 r_handshake_lock;
	struct noise_handshake		 r_handshake;
	enum noise_handshake_state	 r_handshake_state;
	struct timespec			 r_last_sent; 
	struct timespec			 r_last_init_recv;
	uint8_t				 r_timestamp[NOISE_TIMESTAMP_LEN];
	uint8_t				 r_psk[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t		 		 r_ss[NOISE_PUBLIC_KEY_LEN];

	u_int				 r_refcnt;
	struct noise_local		*r_local;
	void				*r_arg;

	struct lock			 r_keypair_lock;
	struct noise_keypair		*r_next, *r_current, *r_previous;
	void				 (*r_cleanup)(struct noise_remote *);
};

struct noise_local {
	struct lock			 l_lock;
	struct lock			 l_identity_lock;
	bool				 l_has_identity;
	uint8_t				 l_public[NOISE_PUBLIC_KEY_LEN];
	uint8_t				 l_private[NOISE_PUBLIC_KEY_LEN];

	u_int				 l_refcnt;
	uint8_t				 l_hash_key[SIPHASH_KEY_LENGTH];
	void				*l_arg;
	void				 (*l_cleanup)(struct noise_local *);

	struct lock			 l_remote_lock;
	size_t				 l_remote_num;
	LIST_HEAD(,noise_remote)	 l_remote_hash[HT_REMOTE_SIZE];

	struct lock			 l_index_lock;
	LIST_HEAD(,noise_index)	 l_index_hash[HT_INDEX_SIZE];
};

static void	noise_precompute_ss(struct noise_local *, struct noise_remote *);

static void	noise_remote_index_insert(struct noise_local *, struct noise_remote *);
static struct noise_remote *
		noise_remote_index_lookup(struct noise_local *, uint32_t, bool);
static int	noise_remote_index_remove(struct noise_local *, struct noise_remote *);
static void	noise_remote_expire_current(struct noise_remote *);

static void	noise_add_new_keypair(struct noise_local *, struct noise_remote *, struct noise_keypair *);
static int	noise_begin_session(struct noise_remote *);
static void	noise_keypair_drop(struct noise_keypair *);

static void	noise_kdf(uint8_t *, uint8_t *, uint8_t *, const uint8_t *,
		    size_t, size_t, size_t, size_t,
		    const uint8_t [NOISE_HASH_LEN]);
static int	noise_mix_dh(uint8_t [NOISE_HASH_LEN], uint8_t [NOISE_SYMMETRIC_KEY_LEN],
		    const uint8_t [NOISE_PUBLIC_KEY_LEN],
		    const uint8_t [NOISE_PUBLIC_KEY_LEN]);
static int	noise_mix_ss(uint8_t ck[NOISE_HASH_LEN], uint8_t [NOISE_SYMMETRIC_KEY_LEN],
		    const uint8_t [NOISE_PUBLIC_KEY_LEN]);
static void	noise_mix_hash(uint8_t [NOISE_HASH_LEN], const uint8_t *, size_t);
static void	noise_mix_psk(uint8_t [NOISE_HASH_LEN], uint8_t [NOISE_HASH_LEN],
		    uint8_t [NOISE_SYMMETRIC_KEY_LEN], const uint8_t [NOISE_SYMMETRIC_KEY_LEN]);
static void	noise_param_init(uint8_t [NOISE_HASH_LEN], uint8_t [NOISE_HASH_LEN],
		    const uint8_t [NOISE_PUBLIC_KEY_LEN]);
static void	noise_msg_encrypt(uint8_t *, const uint8_t *, size_t,
		    uint8_t [NOISE_SYMMETRIC_KEY_LEN], uint8_t [NOISE_HASH_LEN]);
static int	noise_msg_decrypt(uint8_t *, const uint8_t *, size_t,
		    uint8_t [NOISE_SYMMETRIC_KEY_LEN], uint8_t [NOISE_HASH_LEN]);
static void	noise_msg_ephemeral(uint8_t [NOISE_HASH_LEN], uint8_t [NOISE_HASH_LEN],
		    const uint8_t [NOISE_PUBLIC_KEY_LEN]);
static void	noise_tai64n_now(uint8_t [NOISE_TIMESTAMP_LEN]);
static uint64_t siphash24(const uint8_t [SIPHASH_KEY_LENGTH], const void *, size_t);

/* Local configuration */
struct noise_local *
noise_local_alloc(void *arg)
{
	struct noise_local *l;
	size_t i;

	l = WG_MALLOC(sizeof(*l));
	if (!l)
		return (NULL);

	lockinit(&l->l_identity_lock, "noise_identity", 0, LK_CANRECURSE);
	lockinit(&l->l_lock, "local", 0, LK_CANRECURSE);
	l->l_has_identity = false;
	bzero(l->l_public, NOISE_PUBLIC_KEY_LEN);
	bzero(l->l_private, NOISE_PUBLIC_KEY_LEN);

	refcount_init(&l->l_refcnt, 1);
	karc4rand(l->l_hash_key, sizeof(l->l_hash_key));
	l->l_arg = arg;
	l->l_cleanup = NULL;

	lockinit(&l->l_remote_lock, "noise_remote", 0, LK_CANRECURSE);
	l->l_remote_num = 0;
	for (i = 0; i < HT_REMOTE_SIZE; i++)
		LIST_INIT(&l->l_remote_hash[i]);

	lockinit(&l->l_index_lock, "noise_index", 0, LK_CANRECURSE);
	for (i = 0; i < HT_INDEX_SIZE; i++)
		LIST_INIT(&l->l_index_hash[i]);

	return (l);
}

struct noise_local *
noise_local_ref(struct noise_local *l)
{
	refcount_acquire(&l->l_refcnt);
	return (l);
}

void
noise_local_put(struct noise_local *l)
{
	lockmgr(&l->l_lock, LK_EXCLUSIVE);
	if (refcount_release(&l->l_refcnt)) {
		if (l->l_cleanup != NULL)
			l->l_cleanup(l);
		lockuninit(&l->l_identity_lock);
		lockuninit(&l->l_remote_lock);
		lockuninit(&l->l_index_lock);
		lockmgr(&l->l_lock, LK_RELEASE);
		lockuninit(&l->l_lock);
		explicit_bzero(l, sizeof(*l));
		WG_FREE(l);
		return;
	}
	lockmgr(&l->l_lock, LK_RELEASE);
}

void
noise_local_free(struct noise_local *l, void (*cleanup)(struct noise_local *))
{
	l->l_cleanup = cleanup;
	noise_local_put(l);
}

void *
noise_local_arg(struct noise_local *l)
{
	return (l->l_arg);
}

void
noise_local_private(struct noise_local *l, const uint8_t private[NOISE_PUBLIC_KEY_LEN])
{
	struct noise_remote *r;
	size_t i;

	lockmgr(&l->l_identity_lock, LK_EXCLUSIVE);
	memcpy(l->l_private, private, NOISE_PUBLIC_KEY_LEN);
	curve25519_clamp_secret(l->l_private);
	l->l_has_identity = curve25519_generate_public(l->l_public, l->l_private);
	lockmgr(&l->l_identity_lock, LK_RELEASE);

	lockmgr(&l->l_remote_lock, LK_SHARED);
	for (i = 0; i < HT_REMOTE_SIZE; i++) {
		LIST_FOREACH(r, &l->l_remote_hash[i], r_entry) {
			noise_precompute_ss(l, r);
			noise_remote_expire_current(r);
		}
	}
	lockmgr(&l->l_remote_lock, LK_RELEASE);
}

int
noise_local_keys(struct noise_local *l, uint8_t public[NOISE_PUBLIC_KEY_LEN],
    uint8_t private[NOISE_PUBLIC_KEY_LEN])
{
	int has_identity;
	lockmgr(&l->l_identity_lock, LK_SHARED);
	if ((has_identity = l->l_has_identity)) {
		if (public != NULL)
			memcpy(public, l->l_public, NOISE_PUBLIC_KEY_LEN);
		if (private != NULL)
			memcpy(private, l->l_private, NOISE_PUBLIC_KEY_LEN);
	}
	lockmgr(&l->l_identity_lock, LK_RELEASE);
	return (has_identity ? 0 : ENXIO);
}

static void
noise_precompute_ss(struct noise_local *l, struct noise_remote *r)
{
	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);
	if (!l->l_has_identity ||
	    !curve25519(r->r_ss, l->l_private, r->r_public))
		bzero(r->r_ss, NOISE_PUBLIC_KEY_LEN);
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
}

/* Remote configuration */
struct noise_remote *
noise_remote_alloc(struct noise_local *l, void *arg,
    const uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
	struct noise_remote *r;

	if ((r = WG_MALLOC(sizeof(*r))) == NULL)
		return (NULL);
	memcpy(r->r_public, public, NOISE_PUBLIC_KEY_LEN);

	lockinit(&r->r_handshake_lock, "noise_handshake", 0, LK_CANRECURSE);
	lockinit(&r->r_lock, "remote", 0, LK_CANRECURSE);
	r->r_handshake_state = HANDSHAKE_DEAD;
	r->r_last_sent = TIMER_RESET;
	r->r_last_init_recv = TIMER_RESET;
	noise_precompute_ss(l, r);

	refcount_init(&r->r_refcnt, 1);
	r->r_local = noise_local_ref(l);
	r->r_arg = arg;

	lockinit(&r->r_keypair_lock, "noise_keypair", 0, LK_CANRECURSE);

	return (r);
}

int
noise_remote_enable(struct noise_remote *r)
{
	struct noise_local *l = r->r_local;
	uint64_t idx;
	int ret = 0;

	/* Insert to hashtable */
	idx = siphash24(l->l_hash_key, r->r_public, NOISE_PUBLIC_KEY_LEN) & HT_REMOTE_MASK;

	lockmgr(&l->l_remote_lock, LK_EXCLUSIVE);
	if (!r->r_entry_inserted) {
		if (l->l_remote_num < MAX_REMOTE_PER_LOCAL) {
			r->r_entry_inserted = true;
			l->l_remote_num++;
			LIST_INSERT_HEAD(&l->l_remote_hash[idx], r, r_entry);
		} else {
			ret = ENOSPC;
		}
	}
	lockmgr(&l->l_remote_lock, LK_RELEASE);

	return ret;
}

void
noise_remote_disable(struct noise_remote *r)
{
	struct noise_local *l = r->r_local;
	/* remove from hashtable */
	lockmgr(&l->l_remote_lock, LK_EXCLUSIVE);
	if (r->r_entry_inserted) {
		r->r_entry_inserted = false;
		LIST_REMOVE(r, r_entry);
		l->l_remote_num--;
	};
	lockmgr(&l->l_remote_lock, LK_RELEASE);
}

struct noise_remote *
noise_remote_lookup(struct noise_local *l, const uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
	struct noise_remote *r, *ret = NULL;
	uint64_t idx;

	idx = siphash24(l->l_hash_key, public, NOISE_PUBLIC_KEY_LEN) & HT_REMOTE_MASK;

	lockmgr(&l->l_remote_lock, LK_SHARED);
	LIST_FOREACH(r, &l->l_remote_hash[idx], r_entry) {
		if (timingsafe_bcmp(r->r_public, public, NOISE_PUBLIC_KEY_LEN) == 0) {
			if (refcount_acquire_if_not_zero(&r->r_refcnt))
				ret = r;
			break;
		}
	}
	lockmgr(&l->l_remote_lock, LK_RELEASE);
	return (ret);
}

static void
noise_remote_index_insert(struct noise_local *l, struct noise_remote *r)
{
	struct noise_index *i, *r_i = &r->r_index;
	uint32_t idx;

	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);
	noise_remote_index_remove(l, r);
	lockmgr(&r->r_handshake_lock, LK_RELEASE);

assign_id:
	r_i->i_local_index = karc4random();
	idx = r_i->i_local_index & HT_INDEX_MASK;
	lockmgr(&l->l_index_lock, LK_SHARED);
	LIST_FOREACH(i, &l->l_index_hash[idx], i_entry) {
		if (i->i_local_index == r_i->i_local_index) {
			lockmgr(&l->l_index_lock, LK_RELEASE);
			goto assign_id;
		}
	}

	LIST_FOREACH(i, &l->l_index_hash[idx], i_entry) {
		if (i->i_local_index == r_i->i_local_index) {
			lockmgr(&l->l_index_lock, LK_RELEASE);
			goto assign_id;
		}
	}
	lockmgr(&l->l_index_lock, LK_RELEASE);

	lockmgr(&l->l_index_lock, LK_EXCLUSIVE);
	LIST_INSERT_HEAD(&l->l_index_hash[idx], r_i, i_entry);
	lockmgr(&l->l_index_lock, LK_RELEASE);
}

static struct noise_remote *
noise_remote_index_lookup(struct noise_local *l, uint32_t idx0, bool lookup_keypair)
{
	struct noise_index *i;
	struct noise_keypair *kp;
	struct noise_remote *r, *ret = NULL;
	uint32_t idx = idx0 & HT_INDEX_MASK;

	lockmgr(&l->l_index_lock, LK_SHARED);
	LIST_FOREACH(i, &l->l_index_hash[idx], i_entry) {
		if (i->i_local_index == idx0) {
			if (!i->i_is_keypair) {
				r = (struct noise_remote *) i;
			} else if (lookup_keypair) {
				kp = (struct noise_keypair *) i;
				r = kp->kp_remote;
			} else {
				break;
			}
			if (refcount_acquire_if_not_zero(&r->r_refcnt))
				ret = r;
			break;
		}
	}
	lockmgr(&l->l_index_lock, LK_RELEASE);
	return (ret);
}

struct noise_remote *
noise_remote_index(struct noise_local *l, uint32_t idx)
{
	return noise_remote_index_lookup(l, idx, true);
}

static int
noise_remote_index_remove(struct noise_local *l, struct noise_remote *r)
{
	if (r->r_handshake_state != HANDSHAKE_DEAD) {
		lockmgr(&l->l_index_lock, LK_EXCLUSIVE);
		r->r_handshake_state = HANDSHAKE_DEAD;
		LIST_REMOVE(&r->r_index, i_entry);
		lockmgr(&l->l_index_lock, LK_RELEASE);
		return (1);
	}
	return (0);
}

struct noise_remote *
noise_remote_ref(struct noise_remote *r)
{
	refcount_acquire(&r->r_refcnt);
	return (r);
}

void
noise_remote_put(struct noise_remote *r)
{
	lockmgr(&r->r_lock, LK_EXCLUSIVE);
	if (refcount_release(&r->r_refcnt)) {
		if (r->r_cleanup != NULL)
			r->r_cleanup(r);
		noise_local_put(r->r_local);
		lockuninit(&r->r_handshake_lock);
		lockuninit(&r->r_keypair_lock);
		lockmgr(&r->r_lock, LK_RELEASE);
		lockuninit(&r->r_lock);
		explicit_bzero(r, sizeof(*r));
		WG_FREE(r);
		return;
	}
	lockmgr(&r->r_lock, LK_RELEASE);
}

void
noise_remote_free(struct noise_remote *r, void (*cleanup)(struct noise_remote *))
{
	r->r_cleanup = cleanup;
	noise_remote_disable(r);

	/* now clear all keypairs and handshakes, then put this reference */
	noise_remote_handshake_clear(r);
	noise_remote_keypairs_clear(r);
	noise_remote_put(r);
}

struct noise_local *
noise_remote_local(struct noise_remote *r)
{
	return (noise_local_ref(r->r_local));
}

void *
noise_remote_arg(struct noise_remote *r)
{
	return (r->r_arg);
}

void
noise_remote_set_psk(struct noise_remote *r,
    const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);
	if (psk == NULL)
		bzero(r->r_psk, NOISE_SYMMETRIC_KEY_LEN);
	else
		memcpy(r->r_psk, psk, NOISE_SYMMETRIC_KEY_LEN);
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
}

int
noise_remote_keys(struct noise_remote *r, uint8_t public[NOISE_PUBLIC_KEY_LEN],
    uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
	static uint8_t null_psk[NOISE_SYMMETRIC_KEY_LEN];
	int ret;

	if (public != NULL)
		memcpy(public, r->r_public, NOISE_PUBLIC_KEY_LEN);

	lockmgr(&r->r_handshake_lock, LK_SHARED);
	if (psk != NULL)
		memcpy(psk, r->r_psk, NOISE_SYMMETRIC_KEY_LEN);
	ret = timingsafe_bcmp(r->r_psk, null_psk, NOISE_SYMMETRIC_KEY_LEN);
	lockmgr(&r->r_handshake_lock, LK_RELEASE);

	return (ret ? 0 : ENOENT);
}

int
noise_remote_initiation_expired(struct noise_remote *r)
{
	int expired;
	lockmgr(&r->r_handshake_lock, LK_SHARED);
	expired = time_expired(&r->r_last_sent, REKEY_TIMEOUT, 0);
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
	return (expired);
}

void
noise_remote_handshake_clear(struct noise_remote *r)
{
	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);
	if (noise_remote_index_remove(r->r_local, r))
		bzero(&r->r_handshake, sizeof(r->r_handshake));
	r->r_last_sent = TIMER_RESET;
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
}

void
noise_remote_keypairs_clear(struct noise_remote *r)
{
	struct noise_keypair *kp;

	lockmgr(&r->r_keypair_lock, LK_EXCLUSIVE);
	kp = load_ptr(r->r_next);
	store_ptr(r->r_next, NULL);
	noise_keypair_drop(kp);

	kp = load_ptr(r->r_current);
	store_ptr(r->r_current, NULL);
	noise_keypair_drop(kp);

	kp = load_ptr(r->r_previous);
	store_ptr(r->r_previous, NULL);
	noise_keypair_drop(kp);
	lockmgr(&r->r_keypair_lock, LK_RELEASE);
}

static void
noise_remote_expire_current(struct noise_remote *r)
{
	struct noise_keypair *kp;

	noise_remote_handshake_clear(r);

	lockmgr(&r->r_lock, LK_SHARED);
	kp = load_ptr(r->r_next);
	if (kp != NULL)
		atomic_store_rel_bool(&kp->kp_can_send, false);
	kp = load_ptr(r->r_current);
	if (kp != NULL)
		atomic_store_rel_bool(&kp->kp_can_send, false);
	lockmgr(&r->r_lock, LK_RELEASE);
}

/* Keypair functions */
static void
noise_add_new_keypair(struct noise_local *l, struct noise_remote *r,
    struct noise_keypair *kp)
{
	struct noise_keypair *next, *current, *previous;
	struct noise_index *r_i = &r->r_index;

	/* Insert into the keypair table */
	lockmgr(&r->r_keypair_lock, LK_EXCLUSIVE);
	next = load_ptr(r->r_next);
	current = load_ptr(r->r_current);
	previous = load_ptr(r->r_previous);

	if (kp->kp_is_initiator) {
		if (next != NULL) {
			store_ptr(r->r_next, NULL);
			store_ptr(r->r_previous, next);
			noise_keypair_drop(current);
		} else {
			store_ptr(r->r_previous, current);
		}
		noise_keypair_drop(previous);
		store_ptr(r->r_current, kp);
	} else {
		store_ptr(r->r_next, kp);
		noise_keypair_drop(next);
		store_ptr(r->r_previous, NULL);
		noise_keypair_drop(previous);

	}
	lockmgr(&r->r_keypair_lock, LK_RELEASE);

	/* Insert into index table */

	kp->kp_index.i_is_keypair = true;
	kp->kp_index.i_local_index = r_i->i_local_index;
	kp->kp_index.i_remote_index = r_i->i_remote_index;

	lockmgr(&l->l_index_lock, LK_EXCLUSIVE);
	LIST_INSERT_BEFORE(r_i, &kp->kp_index, i_entry);
	r->r_handshake_state = HANDSHAKE_DEAD;
	LIST_REMOVE(r_i, i_entry);
	lockmgr(&l->l_index_lock, LK_RELEASE);

	explicit_bzero(&r->r_handshake, sizeof(r->r_handshake));
}

static int
noise_begin_session(struct noise_remote *r)
{
	struct noise_keypair *kp;

	if ((kp = WG_MALLOC(sizeof(*kp))) == NULL)
		return (ENOSPC);

	refcount_init(&kp->kp_refcnt, 1);
	kp->kp_can_send = true;
	kp->kp_is_initiator = r->r_handshake_state == HANDSHAKE_INITIATOR;
	getnanouptime(&kp->kp_birthdate);
	kp->kp_remote = noise_remote_ref(r);

	if (kp->kp_is_initiator)
		noise_kdf(kp->kp_send, kp->kp_recv, NULL, NULL,
		    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
		    r->r_handshake.hs_ck);
	else
		noise_kdf(kp->kp_recv, kp->kp_send, NULL, NULL,
		    NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, 0,
		    r->r_handshake.hs_ck);

	lockinit(&kp->kp_nonce_lock, "noise_nonce", 0, LK_CANRECURSE);
	lockinit(&kp->kp_lock, "keypair", 0, LK_CANRECURSE);

	noise_add_new_keypair(r->r_local, r, kp);
	return (0);
}

struct noise_keypair *
noise_keypair_lookup(struct noise_local *l, uint32_t idx0)
{
	struct noise_index *i;
	struct noise_keypair *kp, *ret = NULL;
	uint32_t idx = idx0 & HT_INDEX_MASK;

	lockmgr(&l->l_index_lock, LK_SHARED);
	LIST_FOREACH(i, &l->l_index_hash[idx], i_entry) {
		if (i->i_local_index == idx0 && i->i_is_keypair) {
			kp = (struct noise_keypair *) i;
			if (refcount_acquire_if_not_zero(&kp->kp_refcnt))
				ret = kp;
			break;
		}
	}
	lockmgr(&l->l_index_lock, LK_RELEASE);
	return (ret);
}

struct noise_keypair *
noise_keypair_current(struct noise_remote *r)
{
	struct noise_keypair *kp, *ret = NULL;

	lockmgr(&r->r_lock, LK_SHARED);
	kp = load_ptr(r->r_current);
	if (kp != NULL && atomic_load_acq_bool(&kp->kp_can_send)) {
		if (time_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0))
			atomic_store_rel_bool(&kp->kp_can_send, false);
		else if (refcount_acquire_if_not_zero(&kp->kp_refcnt))
			ret = kp;
	}
	lockmgr(&r->r_lock, LK_RELEASE);
	return (ret);
}

struct noise_keypair *
noise_keypair_ref(struct noise_keypair *kp)
{
	refcount_acquire(&kp->kp_refcnt);
	return (kp);
}

int
noise_keypair_received_with(struct noise_keypair *kp)
{
	struct noise_keypair *old;
	struct noise_remote *r = kp->kp_remote;

	if (kp != load_ptr(r->r_next))
		return (0);

	lockmgr(&r->r_keypair_lock, LK_EXCLUSIVE);
	if (kp != load_ptr(r->r_next)) {
		lockmgr(&r->r_keypair_lock, LK_RELEASE);
		return (0);
	}

	old = load_ptr(r->r_previous);
	store_ptr(r->r_previous, load_ptr(r->r_current));
	noise_keypair_drop(old);
	store_ptr(r->r_current, kp);
	store_ptr(r->r_next, NULL);
	lockmgr(&r->r_keypair_lock, LK_RELEASE);

	return (ECONNRESET);
}

void
noise_keypair_put(struct noise_keypair *kp)
{
	lockmgr(&kp->kp_lock, LK_EXCLUSIVE);
	if (refcount_release(&kp->kp_refcnt)) {
		noise_remote_put(kp->kp_remote);
		lockuninit(&kp->kp_nonce_lock);
		lockmgr(&kp->kp_lock, LK_RELEASE);
		lockuninit(&kp->kp_lock);
		explicit_bzero(kp, sizeof(*kp));
		WG_FREE(kp);
		return;
	}
	lockmgr(&kp->kp_lock, LK_RELEASE);
}

static void
noise_keypair_drop(struct noise_keypair *kp)
{
	struct noise_remote *r;
	struct noise_local *l;

	if (kp == NULL)
		return;

	r = kp->kp_remote;
	l = r->r_local;

	lockmgr(&l->l_index_lock, LK_EXCLUSIVE);
	LIST_REMOVE(&kp->kp_index, i_entry);
	lockmgr(&l->l_index_lock, LK_RELEASE);

	noise_keypair_put(kp);
}

struct noise_remote *
noise_keypair_remote(struct noise_keypair *kp)
{
	return (noise_remote_ref(kp->kp_remote));
}

int
noise_keypair_nonce_next(struct noise_keypair *kp, uint64_t *send)
{
	if (!atomic_load_acq_bool(&kp->kp_can_send))
		return (EINVAL);

#ifdef __LP64__
	*send = atomic_fetchadd_64(&kp->kp_nonce_send, 1);
#else
	lockmgr(&kp->kp_nonce_lock, LK_EXCLUSIVE);
	*send = kp->kp_nonce_send++;
	lockmgr(&kp->kp_nonce_lock, LK_RELEASE);
#endif
	if (*send < REJECT_AFTER_MESSAGES)
		return (0);
	atomic_store_rel_bool(&kp->kp_can_send, false);
	return (EINVAL);
}

int
noise_keypair_nonce_check(struct noise_keypair *kp, uint64_t recv)
{
	unsigned long index, index_current, top, i, bit;
	int ret = EEXIST;

	lockmgr(&kp->kp_nonce_lock, LK_EXCLUSIVE);

	if (__predict_false(kp->kp_nonce_recv >= REJECT_AFTER_MESSAGES + 1 ||
			    recv >= REJECT_AFTER_MESSAGES))
		goto error;

	++recv;

	if (__predict_false(recv + COUNTER_WINDOW_SIZE < kp->kp_nonce_recv))
		goto error;

	index = recv >> COUNTER_ORDER;

	if (__predict_true(recv > kp->kp_nonce_recv)) {
		index_current = kp->kp_nonce_recv >> COUNTER_ORDER;
		top = MIN(index - index_current, COUNTER_BITS_TOTAL / COUNTER_BITS);
		for (i = 1; i <= top; i++)
			kp->kp_backtrack[
			    (i + index_current) &
				((COUNTER_BITS_TOTAL / COUNTER_BITS) - 1)] = 0;
#ifdef __LP64__
		atomic_store_rel_64(&kp->kp_nonce_recv, recv);
#else
		kp->kp_nonce_recv = recv;
#endif
	}

	index &= (COUNTER_BITS_TOTAL / COUNTER_BITS) - 1;
	bit = 1ul << (recv & (COUNTER_BITS - 1));
	if (kp->kp_backtrack[index] & bit)
		goto error;

	kp->kp_backtrack[index] |= bit;
	ret = 0;
error:
	lockmgr(&kp->kp_nonce_lock, LK_RELEASE);
	return (ret);
}

int
noise_keep_key_fresh_send(struct noise_remote *r)
{
	struct noise_keypair *current;
	int keep_key_fresh;
	uint64_t nonce;

	lockmgr(&r->r_lock, LK_SHARED);
	current = load_ptr(r->r_current);
	keep_key_fresh = current != NULL && atomic_load_acq_bool(&current->kp_can_send);
	if (!keep_key_fresh)
		goto out;
#ifdef __LP64__
	nonce = atomic_load_acq_64(&current->kp_nonce_send);
#else
	lockmgr(&current->kp_nonce_lock, LK_SHARED);
	nonce = current->kp_nonce_send;
	lockmgr(&current->kp_nonce_lock, LK_RELEASE);
#endif
	keep_key_fresh = nonce > REKEY_AFTER_MESSAGES;
	if (keep_key_fresh)
		goto out;
	keep_key_fresh = current->kp_is_initiator && time_expired(&current->kp_birthdate, REKEY_AFTER_TIME, 0);

out:
	lockmgr(&r->r_lock, LK_RELEASE);
	return (keep_key_fresh ? ESTALE : 0);
}

int
noise_keep_key_fresh_recv(struct noise_remote *r)
{
	struct noise_keypair *current;
	int keep_key_fresh;

	lockmgr(&r->r_lock, LK_SHARED);
	current = load_ptr(r->r_current);
	keep_key_fresh = current != NULL && atomic_load_acq_bool(&current->kp_can_send) &&
	    current->kp_is_initiator && time_expired(&current->kp_birthdate,
			REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT, 0);
	lockmgr(&r->r_lock, LK_RELEASE);

	return (keep_key_fresh ? ESTALE : 0);
}

int
noise_keypair_encrypt(struct noise_keypair *kp, uint32_t *r_idx, uint64_t nonce, struct mbuf *m)
{
	if (chacha20poly1305_encrypt_mbuf(m, nonce, kp->kp_send) == 0)
	       return (ENOMEM);

	*r_idx = kp->kp_index.i_remote_index;
	return (0);
}

int
noise_keypair_decrypt(struct noise_keypair *kp, uint64_t nonce, struct mbuf *m)
{
	uint64_t cur_nonce;

#ifdef __LP64__
	cur_nonce = atomic_load_acq_64(&kp->kp_nonce_recv);
#else
	lockmgr(&kp->kp_nonce_lock, LK_SHARED);
	cur_nonce = kp->kp_nonce_recv;
	lockmgr(&kp->kp_nonce_lock, LK_RELEASE);
#endif

	if (cur_nonce >= REJECT_AFTER_MESSAGES ||
	    time_expired(&kp->kp_birthdate, REJECT_AFTER_TIME, 0))
		return (EINVAL);

	if (chacha20poly1305_decrypt_mbuf(m, nonce, kp->kp_recv) == 0)
		return (EINVAL);

	return (0);
}

/* Handshake functions */
int
noise_create_initiation(struct noise_remote *r,
    uint32_t *s_idx,
    uint8_t ue[NOISE_PUBLIC_KEY_LEN],
    uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
    uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN])
{
	struct noise_handshake *hs = &r->r_handshake;
	struct noise_local *l = r->r_local;
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	int ret = EINVAL;

	lockmgr(&l->l_identity_lock, LK_SHARED);
	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);
	if (!l->l_has_identity)
		goto error;
	if (!time_expired(&r->r_last_sent, REKEY_TIMEOUT, 0))
		goto error;
	noise_param_init(hs->hs_ck, hs->hs_hash, r->r_public);

	/* e */
	curve25519_generate_secret(hs->hs_e);
	if (curve25519_generate_public(ue, hs->hs_e) == 0)
		goto error;
	noise_msg_ephemeral(hs->hs_ck, hs->hs_hash, ue);

	/* es */
	if (noise_mix_dh(hs->hs_ck, key, hs->hs_e, r->r_public) != 0)
		goto error;

	/* s */
	noise_msg_encrypt(es, l->l_public,
	    NOISE_PUBLIC_KEY_LEN, key, hs->hs_hash);

	/* ss */
	if (noise_mix_ss(hs->hs_ck, key, r->r_ss) != 0)
		goto error;

	/* {t} */
	noise_tai64n_now(ets);
	noise_msg_encrypt(ets, ets,
	    NOISE_TIMESTAMP_LEN, key, hs->hs_hash);

	noise_remote_index_insert(l, r);
	r->r_handshake_state = HANDSHAKE_INITIATOR;
	getnanouptime(&r->r_last_sent);
	*s_idx = r->r_index.i_local_index;
	ret = 0;
error:
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
	lockmgr(&l->l_identity_lock, LK_RELEASE);
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	return (ret);
}

int
noise_consume_initiation(struct noise_local *l, struct noise_remote **rp,
    uint32_t s_idx,
    uint8_t ue[NOISE_PUBLIC_KEY_LEN],
    uint8_t es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN],
    uint8_t ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN])
{
	struct noise_remote *r;
	struct noise_handshake hs;
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t r_public[NOISE_PUBLIC_KEY_LEN];
	uint8_t	timestamp[NOISE_TIMESTAMP_LEN];
	int ret = EINVAL;

	lockmgr(&l->l_identity_lock, LK_SHARED);
	if (!l->l_has_identity)
		goto error;
	noise_param_init(hs.hs_ck, hs.hs_hash, l->l_public);

	/* e */
	noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, ue);

	/* es */
	if (noise_mix_dh(hs.hs_ck, key, l->l_private, ue) != 0)
		goto error;

	/* s */
	if (noise_msg_decrypt(r_public, es,
	    NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN, key, hs.hs_hash) != 0)
		goto error;

	/* Lookup the remote we received from */
	if ((r = noise_remote_lookup(l, r_public)) == NULL)
		goto error;

	/* ss */
	if (noise_mix_ss(hs.hs_ck, key, r->r_ss) != 0)
		goto error_put;

	/* {t} */
	if (noise_msg_decrypt(timestamp, ets,
	    NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN, key, hs.hs_hash) != 0)
		goto error_put;

	memcpy(hs.hs_e, ue, NOISE_PUBLIC_KEY_LEN);

	/* We have successfully computed the same results, now we ensure that
	 * this is not an initiation replay, or a flood attack */
	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);

	/* Replay */
	if (memcmp(timestamp, r->r_timestamp, NOISE_TIMESTAMP_LEN) > 0)
		memcpy(r->r_timestamp, timestamp, NOISE_TIMESTAMP_LEN);
	else
		goto error_set;
	/* Flood attack */
	if (time_expired(&r->r_last_init_recv, 0, REJECT_INTERVAL))
		getnanouptime(&r->r_last_init_recv);
	else
		goto error_set;

	/* Ok, we're happy to accept this initiation now */
	noise_remote_index_insert(l, r);
	r->r_index.i_remote_index = s_idx;
	r->r_handshake_state = HANDSHAKE_RESPONDER;
	r->r_handshake = hs;
	*rp = noise_remote_ref(r);
	ret = 0;
error_set:
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
error_put:
	noise_remote_put(r);
error:
	lockmgr(&l->l_identity_lock, LK_RELEASE);
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	explicit_bzero(&hs, sizeof(hs));
	return (ret);
}

int
noise_create_response(struct noise_remote *r,
    uint32_t *s_idx, uint32_t *r_idx,
    uint8_t ue[NOISE_PUBLIC_KEY_LEN],
    uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
	struct noise_handshake *hs = &r->r_handshake;
	struct noise_local *l = r->r_local;
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t e[NOISE_PUBLIC_KEY_LEN];
	int ret = EINVAL;

	lockmgr(&l->l_identity_lock, LK_SHARED);
	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);

	if (r->r_handshake_state != HANDSHAKE_RESPONDER)
		goto error;

	/* e */
	curve25519_generate_secret(e);
	if (curve25519_generate_public(ue, e) == 0)
		goto error;
	noise_msg_ephemeral(hs->hs_ck, hs->hs_hash, ue);

	/* ee */
	if (noise_mix_dh(hs->hs_ck, NULL, e, hs->hs_e) != 0)
		goto error;

	/* se */
	if (noise_mix_dh(hs->hs_ck, NULL, e, r->r_public) != 0)
		goto error;

	/* psk */
	noise_mix_psk(hs->hs_ck, hs->hs_hash, key, r->r_psk);

	/* {} */
	noise_msg_encrypt(en, NULL, 0, key, hs->hs_hash);

	if ((ret = noise_begin_session(r)) == 0) {
		getnanouptime(&r->r_last_sent);
		*s_idx = r->r_index.i_local_index;
		*r_idx = r->r_index.i_remote_index;
	}
error:
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
	lockmgr(&l->l_identity_lock, LK_RELEASE);
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	explicit_bzero(e, NOISE_PUBLIC_KEY_LEN);
	return (ret);
}

int
noise_consume_response(struct noise_local *l, struct noise_remote **rp,
    uint32_t s_idx, uint32_t r_idx,
    uint8_t ue[NOISE_PUBLIC_KEY_LEN],
    uint8_t en[0 + NOISE_AUTHTAG_LEN])
{
	uint8_t preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	uint8_t key[NOISE_SYMMETRIC_KEY_LEN];
	struct noise_handshake hs;
	struct noise_remote *r = NULL;
	int ret = EINVAL;

	if ((r = noise_remote_index_lookup(l, r_idx, false)) == NULL)
		return (ret);

	lockmgr(&l->l_identity_lock, LK_SHARED);
	if (!l->l_has_identity)
		goto error;

	lockmgr(&r->r_handshake_lock, LK_SHARED);
	if (r->r_handshake_state != HANDSHAKE_INITIATOR) {
		lockmgr(&r->r_handshake_lock, LK_RELEASE);
		goto error;
	}
	memcpy(preshared_key, r->r_psk, NOISE_SYMMETRIC_KEY_LEN);
	hs = r->r_handshake;
	lockmgr(&r->r_handshake_lock, LK_RELEASE);

	/* e */
	noise_msg_ephemeral(hs.hs_ck, hs.hs_hash, ue);

	/* ee */
	if (noise_mix_dh(hs.hs_ck, NULL, hs.hs_e, ue) != 0)
		goto error_zero;

	/* se */
	if (noise_mix_dh(hs.hs_ck, NULL, l->l_private, ue) != 0)
		goto error_zero;

	/* psk */
	noise_mix_psk(hs.hs_ck, hs.hs_hash, key, preshared_key);

	/* {} */
	if (noise_msg_decrypt(NULL, en,
	    0 + NOISE_AUTHTAG_LEN, key, hs.hs_hash) != 0)
		goto error_zero;

	lockmgr(&r->r_handshake_lock, LK_EXCLUSIVE);
	if (r->r_handshake_state == HANDSHAKE_INITIATOR &&
	    r->r_index.i_local_index == r_idx) {
		r->r_handshake = hs;
		r->r_index.i_remote_index = s_idx;
		if ((ret = noise_begin_session(r)) == 0)
			*rp = noise_remote_ref(r);
	}
	lockmgr(&r->r_handshake_lock, LK_RELEASE);
error_zero:
	explicit_bzero(preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	explicit_bzero(key, NOISE_SYMMETRIC_KEY_LEN);
	explicit_bzero(&hs, sizeof(hs));
error:
	lockmgr(&l->l_identity_lock, LK_RELEASE);
	noise_remote_put(r);
	return (ret);
}

/* Handshake helper functions */
static void
noise_kdf(uint8_t *a, uint8_t *b, uint8_t *c, const uint8_t *x,
    size_t a_len, size_t b_len, size_t c_len, size_t x_len,
    const uint8_t ck[NOISE_HASH_LEN])
{
	uint8_t out[BLAKE2S_HASH_SIZE + 1];
	uint8_t sec[BLAKE2S_HASH_SIZE];

	/* Extract entropy from "x" into sec */
	blake2s_hmac(sec, x, ck, BLAKE2S_HASH_SIZE, x_len, NOISE_HASH_LEN);

	if (a == NULL || a_len == 0)
		goto out;

	/* Expand first key: key = sec, data = 0x1 */
	out[0] = 1;
	blake2s_hmac(out, out, sec, BLAKE2S_HASH_SIZE, 1, BLAKE2S_HASH_SIZE);
	memcpy(a, out, a_len);

	if (b == NULL || b_len == 0)
		goto out;

	/* Expand second key: key = sec, data = "a" || 0x2 */
	out[BLAKE2S_HASH_SIZE] = 2;
	blake2s_hmac(out, out, sec, BLAKE2S_HASH_SIZE, BLAKE2S_HASH_SIZE + 1,
			BLAKE2S_HASH_SIZE);
	memcpy(b, out, b_len);

	if (c == NULL || c_len == 0)
		goto out;

	/* Expand third key: key = sec, data = "b" || 0x3 */
	out[BLAKE2S_HASH_SIZE] = 3;
	blake2s_hmac(out, out, sec, BLAKE2S_HASH_SIZE, BLAKE2S_HASH_SIZE + 1,
			BLAKE2S_HASH_SIZE);
	memcpy(c, out, c_len);

out:
	/* Clear sensitive data from stack */
	explicit_bzero(sec, BLAKE2S_HASH_SIZE);
	explicit_bzero(out, BLAKE2S_HASH_SIZE + 1);
}

static int
noise_mix_dh(uint8_t ck[NOISE_HASH_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t private[NOISE_PUBLIC_KEY_LEN],
    const uint8_t public[NOISE_PUBLIC_KEY_LEN])
{
	uint8_t dh[NOISE_PUBLIC_KEY_LEN];

	if (!curve25519(dh, private, public))
		return (EINVAL);
	noise_kdf(ck, key, NULL, dh,
	    NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, ck);
	explicit_bzero(dh, NOISE_PUBLIC_KEY_LEN);
	return (0);
}

static int
noise_mix_ss(uint8_t ck[NOISE_HASH_LEN], uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t ss[NOISE_PUBLIC_KEY_LEN])
{
	static uint8_t null_point[NOISE_PUBLIC_KEY_LEN];
	if (timingsafe_bcmp(ss, null_point, NOISE_PUBLIC_KEY_LEN) == 0)
		return (ENOENT);
	noise_kdf(ck, key, NULL, ss,
	    NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN, 0, NOISE_PUBLIC_KEY_LEN, ck);
	return (0);
}

static void
noise_mix_hash(uint8_t hash[NOISE_HASH_LEN], const uint8_t *src,
    size_t src_len)
{
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash);
}

static void
noise_mix_psk(uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN],
    const uint8_t psk[NOISE_SYMMETRIC_KEY_LEN])
{
	uint8_t tmp[NOISE_HASH_LEN];

	noise_kdf(ck, tmp, key, psk,
	    NOISE_HASH_LEN, NOISE_HASH_LEN, NOISE_SYMMETRIC_KEY_LEN,
	    NOISE_SYMMETRIC_KEY_LEN, ck);
	noise_mix_hash(hash, tmp, NOISE_HASH_LEN);
	explicit_bzero(tmp, NOISE_HASH_LEN);
}

static void
noise_param_init(uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
    const uint8_t s[NOISE_PUBLIC_KEY_LEN])
{
	struct blake2s_state blake;

	blake2s(ck, (uint8_t *)NOISE_HANDSHAKE_NAME, NULL,
	    NOISE_HASH_LEN, strlen(NOISE_HANDSHAKE_NAME), 0);
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, ck, NOISE_HASH_LEN);
	blake2s_update(&blake, (uint8_t *)NOISE_IDENTIFIER_NAME,
	    strlen(NOISE_IDENTIFIER_NAME));
	blake2s_final(&blake, hash);

	noise_mix_hash(hash, s, NOISE_PUBLIC_KEY_LEN);
}

static void
noise_msg_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN])
{
	/* Nonce always zero for Noise_IK */
	chacha20poly1305_encrypt(dst, src, src_len,
	    hash, NOISE_HASH_LEN, 0, key);
	noise_mix_hash(hash, dst, src_len + NOISE_AUTHTAG_LEN);
}

static int
noise_msg_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len,
    uint8_t key[NOISE_SYMMETRIC_KEY_LEN], uint8_t hash[NOISE_HASH_LEN])
{
	/* Nonce always zero for Noise_IK */
	if (!chacha20poly1305_decrypt(dst, src, src_len,
	    hash, NOISE_HASH_LEN, 0, key))
		return (EINVAL);
	noise_mix_hash(hash, src, src_len);
	return (0);
}

static void
noise_msg_ephemeral(uint8_t ck[NOISE_HASH_LEN], uint8_t hash[NOISE_HASH_LEN],
    const uint8_t src[NOISE_PUBLIC_KEY_LEN])
{
	noise_mix_hash(hash, src, NOISE_PUBLIC_KEY_LEN);
	noise_kdf(ck, NULL, NULL, src, NOISE_HASH_LEN, 0, 0,
		  NOISE_PUBLIC_KEY_LEN, ck);
}

static void
noise_tai64n_now(uint8_t output[NOISE_TIMESTAMP_LEN])
{
	struct timespec time;
	uint64_t sec;
	uint32_t nsec;

	getnanotime(&time);

	/* Round down the nsec counter to limit precise timing leak. */
	time.tv_nsec &= REJECT_INTERVAL_MASK;

	/* https://cr.yp.to/libtai/tai64.html */
	sec = htobe64(0x400000000000000aULL + time.tv_sec);
	nsec = htobe32(time.tv_nsec);

	/* memcpy to output buffer, assuming output could be unaligned. */
	memcpy(output, &sec, sizeof(sec));
	memcpy(output + sizeof(sec), &nsec, sizeof(nsec));
}

static uint64_t siphash24(const uint8_t key[SIPHASH_KEY_LENGTH], const void *src, size_t len)
{
	SIPHASH_CTX ctx;
	return (SipHashX(&ctx, 2, 4, key, src, len));
}

