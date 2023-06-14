/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2015-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2019-2021 Matt Dunwoodie <ncon@noconroy.net>
 * Copyright (c) 2019-2020 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2021 Kyle Evans <kevans@FreeBSD.org>
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/cdefs.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/socketops.h>
#include <sys/endian.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/malloc.h>
#include <sys/lock.h>

#include <net/bpf.h>
#include <net/if_clone.h>
#include <net/if_types.h>
#include <net/altq/if_altq.h>
#include <net/ifq_var.h>
#include <net/radix.h>
#include <net/netisr.h>

#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "wg_noise.h"
#include "wg_cookie.h"
#include "version.h"
#include "if_wg.h"
#include "wg_support.h"
#include "debug/debug.h"

#ifndef PRIV_NET_WG
#define PRIV_NET_WG PRIV_NET_HWIOCTL
#endif

#ifndef IFT_WIREGUARD
#define IFT_WIREGUARD IFT_PPP
#endif

#define DEFAULT_MTU		(ETHERMTU - 80)
#define MAX_MTU			(IF_MAXMTU - 80)

#define MAX_STAGED_PKT		128
#define MAX_QUEUED_PKT		1024
#define MAX_QUEUED_PKT_MASK	(MAX_QUEUED_PKT - 1)

#define MAX_QUEUED_HANDSHAKES	4096

#define REKEY_TIMEOUT_JITTER	334 /* 1/3 sec, round for arc4random_uniform */
#define MAX_TIMER_HANDSHAKES	(90 / REKEY_TIMEOUT)
#define NEW_HANDSHAKE_TIMEOUT	(REKEY_TIMEOUT + KEEPALIVE_TIMEOUT)
#define UNDERLOAD_TIMEOUT	1

#define PRIu64  "lu"
#define DPRINTF(sc, ...) if (sc->sc_ifp->if_flags & IFF_DEBUG) if_printf(sc->sc_ifp, ##__VA_ARGS__)

/* First byte indicating packet type on the wire */
#define WG_PKT_INITIATION htole32(1)
#define WG_PKT_RESPONSE htole32(2)
#define WG_PKT_COOKIE htole32(3)
#define WG_PKT_DATA htole32(4)

#define WG_PKT_PADDING		16
#define	WGF_DYING	0x0001

#define WG_TASKQUEUE taskqueue_swi
#define WG_TASK_INIT(task, func, ctx) TASK_INIT(task, 0, func, ctx)
#define WG_TASK_DRAIN(task) {\
	while(taskqueue_cancel(WG_TASKQUEUE, task, NULL) != 0) \
		taskqueue_drain(WG_TASKQUEUE, task);\
}
#define WG_TASK_ENQUEUE(task) taskqueue_enqueue(WG_TASKQUEUE, task) 
#define WG_SC_TASK_ENQUEUE(sc, task) {\
	if(!(sc->sc_flags & WGF_DYING)){\
		WG_TASK_ENQUEUE(task); \
	}\
}

#define IF_LINK_STATE_CHANGE(ifp, state) {\
	if (ifp->if_link_state != state) {\
		ifp->if_link_state = state;\
		if_link_state_change(ifp);\
	}\
}

MALLOC_DEFINE(M_WG, "WG", "wg");
#define WG_MALLOC(_size) \
	kmalloc(_size, M_WG, M_NOWAIT | M_ZERO)
#define WG_FREE(_p) \
	kfree(_p, M_WG)

struct wg_pkt_initiation {
	uint32_t		t;
	uint32_t		s_idx;
	uint8_t			ue[NOISE_PUBLIC_KEY_LEN];
	uint8_t			es[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN];
	uint8_t			ets[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN];
	struct cookie_macs	m;
};

struct wg_pkt_response {
	uint32_t		t;
	uint32_t		s_idx;
	uint32_t		r_idx;
	uint8_t			ue[NOISE_PUBLIC_KEY_LEN];
	uint8_t			en[0 + NOISE_AUTHTAG_LEN];
	struct cookie_macs	m;
};

struct wg_pkt_cookie {
	uint32_t		t;
	uint32_t		r_idx;
	uint8_t			nonce[COOKIE_NONCE_SIZE];
	uint8_t			ec[COOKIE_ENCRYPTED_SIZE];
};

struct wg_pkt_data {
	uint32_t		t;
	uint32_t		r_idx;
	uint64_t		nonce;
	uint8_t			buf[];
};

struct wg_endpoint {
	union {
		struct sockaddr		r_sa;
		struct sockaddr_in	r_sin;
#ifdef INET6
		struct sockaddr_in6	r_sin6;
#endif
	} e_remote;
	union {
		struct in_addr		l_in;
#ifdef INET6
		struct in6_pktinfo	l_pktinfo6;
#define l_in6 l_pktinfo6.ipi6_addr
#endif
	} e_local;
};

struct aip_addr {
	uint8_t		length;
	union {
		uint8_t		bytes[16];
		uint32_t	ip;
		uint32_t	ip6[4];
		struct in_addr	in;
		struct in6_addr	in6;
	};
};

struct wg_aip {
	struct radix_node	 a_nodes[2];
	LIST_ENTRY(wg_aip)	 a_entry;
	struct aip_addr		 a_addr;
	struct aip_addr		 a_mask;
	struct wg_peer		*a_peer;
	sa_family_t		 a_af;
};

struct wg_packet {
	STAILQ_ENTRY(wg_packet)	 p_serial;
	STAILQ_ENTRY(wg_packet)	 p_parallel;
	struct wg_endpoint	 p_endpoint;
	struct noise_keypair	*p_keypair;
	uint64_t		 p_nonce;
	struct mbuf		*p_mbuf;
	int			 p_mtu;
	sa_family_t		 p_af;
	enum wg_ring_state {
		WG_PACKET_UNCRYPTED,
		WG_PACKET_CRYPTED,
		WG_PACKET_DEAD,
	}			 p_state;
};

STAILQ_HEAD(wg_packet_list, wg_packet);

struct wg_queue {
	struct lock		 q_lock;
	struct wg_packet_list	 q_queue;
	size_t			 q_len;
};

struct wg_peer {
	TAILQ_ENTRY(wg_peer)		 p_entry;
	uint64_t			 p_id;
	struct wg_softc			*p_sc;

	struct noise_remote		*p_remote;
	struct cookie_maker		 p_cookie;

	struct lock			 p_endpoint_lock;
	struct wg_endpoint		 p_endpoint;

	struct wg_queue	 		 p_stage_queue;
	struct wg_queue	 		 p_encrypt_serial;
	struct wg_queue	 		 p_decrypt_serial;

	bool				 p_enabled;
	bool				 p_need_another_keepalive;
	uint16_t			 p_persistent_keepalive_interval;
	struct callout			 p_new_handshake;
	struct callout			 p_send_keepalive;
	struct callout			 p_retry_handshake;
	struct callout			 p_zero_key_material;
	struct callout			 p_persistent_keepalive;
	struct lock			 p_timer_lock;

	struct lock			 p_handshake_lock;
	struct timespec			 p_handshake_complete;
	int				 p_handshake_retries;

	struct task			 p_send;
	struct task			 p_recv;

	uint64_t			 p_tx_bytes;
	uint64_t			 p_rx_bytes;

	LIST_HEAD(, wg_aip)		 p_aips;
	size_t				 p_aips_num;
};

struct wg_socket {
	struct socket	*so_so4;
	struct socket	*so_so6;
	uint32_t	 so_user_cookie;
	in_port_t	 so_port;
};

struct wg_softc {
	LIST_ENTRY(wg_softc)	 sc_entry;
	struct ifnet		*sc_ifp;
	int			 sc_flags;

	struct ucred		*sc_ucred;
	struct wg_socket	 sc_socket;

	TAILQ_HEAD(,wg_peer)	 sc_peers;
	size_t			 sc_peers_num;

	struct noise_local	*sc_local;
	struct cookie_checker	 sc_cookie;

	struct radix_node_head	*sc_aip4;
	struct lock		 sc_aip4_lock;
	struct radix_node_head	*sc_aip4_mask;
	struct radix_node_head	*sc_aip6;
	struct radix_node_head	*sc_aip6_mask;
	struct lock		 sc_aip6_lock;

	struct task		 sc_handshake;
	struct wg_queue		 sc_handshake_queue;

	struct task		*sc_encrypt;
	struct task		*sc_decrypt;
	struct wg_queue		 sc_encrypt_parallel;
	struct wg_queue		 sc_decrypt_parallel;

	struct lock		 sc_lock;
	struct lock		 sc_net_lock;
};

#define BPF_MTAP_AF(_ifp, _m, _af) do { \
		bpf_mtap_family((_ifp)->if_bpf, (_m), (_af));	\
	} while (0)
	
static int clone_count;
static volatile unsigned long peer_counter = 0;
static const char wgname[] = "wg";

static struct lock wg_lock;

static LIST_HEAD(, wg_softc) wg_list = LIST_HEAD_INITIALIZER(wg_list);

static int wg_socket_init(struct wg_softc *, in_port_t);
static int wg_socket_bind(struct socket **, struct socket **, in_port_t *);
static void wg_socket_set(struct wg_softc *, struct socket *, struct socket *);
static void wg_socket_uninit(struct wg_softc *);
static int wg_socket_set_sockopt(struct socket *, struct socket *, int, void *, size_t);
static int wg_socket_set_cookie(struct wg_softc *, uint32_t);
static int wg_send(struct wg_softc *, struct wg_endpoint *, struct mbuf *);
static void wg_timers_enable(struct wg_peer *);
static void wg_timers_disable(struct wg_peer *);
static void wg_timers_set_persistent_keepalive(struct wg_peer *, uint16_t);
static void wg_timers_get_last_handshake(struct wg_peer *, struct wg_timespec64 *);
static void wg_timers_event_data_sent(struct wg_peer *);
static void wg_timers_event_data_received(struct wg_peer *);
static void wg_timers_event_any_authenticated_packet_sent(struct wg_peer *);
static void wg_timers_event_any_authenticated_packet_received(struct wg_peer *);
static void wg_timers_event_any_authenticated_packet_traversal(struct wg_peer *);
static void wg_timers_event_handshake_initiated(struct wg_peer *);
static void wg_timers_event_handshake_complete(struct wg_peer *);
static void wg_timers_event_session_derived(struct wg_peer *);
static void wg_timers_event_want_initiation(struct wg_peer *);
static void wg_timers_run_send_initiation(struct wg_peer *, bool);
static void wg_timers_run_retry_handshake(void *);
static void wg_timers_run_send_keepalive(void *);
static void wg_timers_run_new_handshake(void *);
static void wg_timers_run_zero_key_material(void *);
static void wg_timers_run_persistent_keepalive(void *);
static int wg_aip_add(struct wg_softc *, struct wg_peer *, sa_family_t, const void *, uint8_t);
static struct wg_peer *wg_aip_lookup(struct wg_softc *, sa_family_t, void *);
static void wg_aip_remove_all(struct wg_softc *, struct wg_peer *);
static struct wg_peer *wg_peer_alloc(struct wg_softc *, const uint8_t [WG_KEY_SIZE]);
static void wg_peer_free_deferred(struct noise_remote *);
static void wg_peer_destroy(struct wg_peer *);
static void wg_peer_destroy_all(struct wg_softc *);
static void wg_peer_send_buf(struct wg_peer *, uint8_t *, size_t);
static void wg_send_initiation(struct wg_peer *);
static void wg_send_response(struct wg_peer *);
static void wg_send_cookie(struct wg_softc *, struct cookie_macs *, uint32_t, struct wg_endpoint *);
static void wg_peer_set_endpoint(struct wg_peer *, struct wg_endpoint *);
static void wg_peer_clear_src(struct wg_peer *);
static void wg_peer_get_endpoint(struct wg_peer *, struct wg_endpoint *);
static void wg_send_buf(struct wg_softc *, struct wg_endpoint *, uint8_t *, size_t);
static void wg_send_keepalive(struct wg_peer *);
static void wg_handshake(struct wg_softc *, struct wg_packet *);
static void wg_encrypt(struct wg_softc *, struct wg_packet *);
static void wg_decrypt(struct wg_softc *, struct wg_packet *);
static void wg_softc_handshake_receive(void*, int);
static void wg_softc_decrypt(void*, int);
static void wg_softc_encrypt(void*, int);
static void wg_encrypt_dispatch(struct wg_softc *);
static void wg_decrypt_dispatch(struct wg_softc *);
static void wg_deliver_out(void*, int);
static void wg_deliver_in(void*, int);
static struct wg_packet *wg_packet_alloc(struct mbuf *);
static void wg_packet_free(struct wg_packet *);
static void wg_queue_init(struct wg_queue *, const char *);
static void wg_queue_deinit(struct wg_queue *);
static size_t wg_queue_len(struct wg_queue *);
static int wg_queue_enqueue_handshake(struct wg_queue *, struct wg_packet *);
static struct wg_packet *wg_queue_dequeue_handshake(struct wg_queue *);
static void wg_queue_push_staged(struct wg_queue *, struct wg_packet *);
static void wg_queue_enlist_staged(struct wg_queue *, struct wg_packet_list *);
static void wg_queue_delist_staged(struct wg_queue *, struct wg_packet_list *);
static void wg_queue_purge(struct wg_queue *);
static int wg_queue_both(struct wg_queue *, struct wg_queue *, struct wg_packet *);
static struct wg_packet *wg_queue_dequeue_serial(struct wg_queue *);
static struct wg_packet *wg_queue_dequeue_parallel(struct wg_queue *);
static void wg_so_upcall(struct socket *, void*, int);
static void wg_input(struct mbuf*, struct sockaddr*, struct wg_softc*);
static void wg_peer_send_staged(struct wg_peer *);
static int wg_clone_create(struct if_clone *, int, caddr_t, caddr_t);
static inline int determine_af_and_pullup(struct mbuf **m, sa_family_t *af);
static int wg_xmit(struct ifnet *, struct mbuf *, sa_family_t, uint32_t);
static void wg_start(struct ifnet *, struct ifaltq_subque*);
static int wg_output(struct ifnet *, struct mbuf *, struct sockaddr *, struct rtentry *);
static int wg_clone_destroy(struct ifnet *);
static bool wgc_privileged(struct wg_softc *);
static int wgc_get(struct wg_softc *, struct wg_data_io *);
static int wgc_set(struct wg_softc *, struct wg_data_io *);
static int wg_up(struct wg_softc *);
static void wg_down(struct wg_softc *);
static void wg_init(void *);
static int wg_ioctl(struct ifnet *, u_long, caddr_t, struct ucred*);
static int wg_module_init(void);
static void wg_module_deinit(void);
static struct if_clone wg_cloner = 
	IF_CLONE_INITIALIZER("wg", wg_clone_create, wg_clone_destroy, 0, IF_MAXUNIT);

static struct wg_peer *
wg_peer_alloc(struct wg_softc *sc, const uint8_t pub_key[WG_KEY_SIZE])
{
	wg_debug_func();
	struct wg_peer *peer;

	if ((peer = WG_MALLOC(sizeof(*peer))) == NULL)
		goto free_none;

	if ((peer->p_remote = noise_remote_alloc(sc->sc_local, peer, pub_key)) == NULL)
		goto free_peer;

	peer->p_tx_bytes = 0;
	peer->p_rx_bytes = 0;

	peer->p_id = peer_counter++;
	peer->p_sc = sc;

	cookie_maker_init(&peer->p_cookie, pub_key);

	lockinit(&peer->p_endpoint_lock, "wg_peer_endpoint", 0, LK_CANRECURSE);

	wg_queue_init(&peer->p_stage_queue, "stageq");
	wg_queue_init(&peer->p_encrypt_serial, "txq");
	wg_queue_init(&peer->p_decrypt_serial, "rxq");

	peer->p_enabled = false;
	peer->p_need_another_keepalive = false;
	peer->p_persistent_keepalive_interval = 0;
	callout_init_mp(&peer->p_new_handshake);
	callout_init_mp(&peer->p_send_keepalive);
	callout_init_mp(&peer->p_retry_handshake);
	callout_init_mp(&peer->p_persistent_keepalive);
	callout_init_mp(&peer->p_zero_key_material);

	lockinit(&peer->p_handshake_lock, "peer handshake", 0, LK_CANRECURSE);
	lockinit(&peer->p_timer_lock, "peer timer", 0, LK_CANRECURSE);
	bzero(&peer->p_handshake_complete, sizeof(peer->p_handshake_complete));
	peer->p_handshake_retries = 0;

	WG_TASK_INIT(&peer->p_send, wg_deliver_out, peer);
	WG_TASK_INIT(&peer->p_recv, wg_deliver_in, peer);

	LIST_INIT(&peer->p_aips);
	peer->p_aips_num = 0;

	return (peer);

free_peer:
	WG_FREE(peer);
free_none:
	return NULL;
}

static void
wg_peer_free_deferred(struct noise_remote *r)
{
	wg_debug_func();
	struct wg_peer *peer = noise_remote_arg(r);

	/* While there are no references remaining, we may still have
	 * p_{send,recv} executing (think empty queue, but wg_deliver_{in,out}
	 * needs to check the queue. We should wait for them and then free. */
	WG_TASK_DRAIN(&peer->p_recv);
	WG_TASK_DRAIN(&peer->p_send);

	wg_queue_deinit(&peer->p_decrypt_serial);
	wg_queue_deinit(&peer->p_encrypt_serial);
	wg_queue_deinit(&peer->p_stage_queue);

	lockuninit(&peer->p_endpoint_lock);
	lockuninit(&peer->p_handshake_lock);
	lockuninit(&peer->p_timer_lock);

	cookie_maker_free(&peer->p_cookie);

	WG_FREE(peer);
}

static void
wg_peer_destroy(struct wg_peer *peer)
{
	wg_debug_func();
	struct wg_softc *sc = peer->p_sc;

	/* Disable remote and timers. This will prevent any new handshakes
	 * occuring. */
	noise_remote_disable(peer->p_remote);
	wg_timers_disable(peer);

	/* Now we can remove all allowed IPs so no more packets will be routed
	 * to the peer. */
	wg_aip_remove_all(sc, peer);

	/* Remove peer from the interface, then free. Some references may still
	 * exist to p_remote, so noise_remote_free will wait until they're all
	 * put to call wg_peer_free_deferred. */
	sc->sc_peers_num--;
	TAILQ_REMOVE(&sc->sc_peers, peer, p_entry);
	DPRINTF(sc, "Peer %" PRIu64 " destroyed\n", peer->p_id);
	noise_remote_free(peer->p_remote, wg_peer_free_deferred);
}

static void
wg_peer_destroy_all(struct wg_softc *sc)
{
	wg_debug_func();
	struct wg_peer *peer, *tpeer;

	TAILQ_FOREACH_MUTABLE(peer, &sc->sc_peers, p_entry, tpeer)
		wg_peer_destroy(peer);
}

static void
wg_peer_set_endpoint(struct wg_peer *peer, struct wg_endpoint *e)
{
	wg_debug_func();
	KKASSERT(e->e_remote.r_sa.sa_family != 0);
	if (memcmp(e, &peer->p_endpoint, sizeof(*e)) == 0)
		return;

	lockmgr(&peer->p_endpoint_lock, LK_EXCLUSIVE);
	peer->p_endpoint = *e;
	lockmgr(&peer->p_endpoint_lock, LK_RELEASE);
}

static void
wg_peer_clear_src(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_endpoint_lock, LK_EXCLUSIVE);
	bzero(&peer->p_endpoint.e_local, sizeof(peer->p_endpoint.e_local));
	lockmgr(&peer->p_endpoint_lock, LK_RELEASE);
}

static void
wg_peer_get_endpoint(struct wg_peer *peer, struct wg_endpoint *e)
{
	wg_debug_func();
	lockmgr(&peer->p_endpoint_lock, LK_SHARED);
	*e = peer->p_endpoint;
	lockmgr(&peer->p_endpoint_lock, LK_RELEASE);
}

/* Allowed IP */
static int
wg_aip_add(struct wg_softc *sc, struct wg_peer *peer, sa_family_t af, const void *addr, uint8_t cidr)
{
	wg_debug_func();
	struct radix_node_head	*root;
	struct lock		 lk;
	struct radix_node	*node;
	struct wg_aip		*aip;
	int			 ret = 0;

	if ((aip = WG_MALLOC(sizeof(*aip))) == NULL)
		return (ENOBUFS);
	aip->a_peer = peer;
	aip->a_af = af;

	switch (af) {
	case AF_INET:
		if (cidr > 32) cidr = 32;
		root = sc->sc_aip4;
		lk = sc->sc_aip4_lock;
		aip->a_addr.in = *(const struct in_addr *)addr;
		aip->a_mask.ip = htonl(~((1LL << (32 - cidr)) - 1) & 0xffffffff);
		aip->a_addr.ip &= aip->a_mask.ip;
		aip->a_addr.length = aip->a_mask.length = offsetof(struct aip_addr, in) + sizeof(struct in_addr);
		break;
#ifdef INET6
	case AF_INET6:
		if (cidr > 128) cidr = 128;
		root = sc->sc_aip6;
		lk = sc->sc_aip6_lock;
		aip->a_addr.in6 = *(const struct in6_addr *)addr;
		in6_prefixlen2mask(&aip->a_mask.in6, cidr);
		for (int i = 0; i < 4; i++)
			aip->a_addr.ip6[i] &= aip->a_mask.ip6[i];
		aip->a_addr.length = aip->a_mask.length = offsetof(struct aip_addr, in6) + sizeof(struct in6_addr);
		break;
#endif
	default:
		WG_FREE(aip);
		return (EAFNOSUPPORT);
	}

	lockmgr(&lk, LK_EXCLUSIVE);
	node = root->rnh_addaddr((char*)&aip->a_addr, (char*)&aip->a_mask, root, (void *)aip->a_nodes);
	if (node == aip->a_nodes) {
		LIST_INSERT_HEAD(&peer->p_aips, aip, a_entry);
		peer->p_aips_num++;
	} else if (!node) {
		node = root->rnh_lookup((char*)&aip->a_addr, (char*)&aip->a_mask, root);
	}
	
	if (!node) {
		WG_FREE(aip);
		return (ENOMEM);
	} else if (node != aip->a_nodes) {
		WG_FREE(aip);
		aip = (struct wg_aip *)node;
		if (aip->a_peer != peer) {
			LIST_REMOVE(aip, a_entry);
			aip->a_peer->p_aips_num--;
			aip->a_peer = peer;
			LIST_INSERT_HEAD(&peer->p_aips, aip, a_entry);
			aip->a_peer->p_aips_num++;
		}
	}
	lockmgr(&lk, LK_RELEASE);
	return (ret);
}

static struct wg_peer *
wg_aip_lookup(struct wg_softc *sc, sa_family_t af, void *a)
{
	wg_debug_func();
	struct radix_node_head	*root;
	struct lock		 *lk;
	struct radix_node	*node;
	struct wg_peer		*peer;
	struct aip_addr		 addr;

	switch (af) {
	case AF_INET:

		root = sc->sc_aip4;
		lk = &sc->sc_aip4_lock;
		memcpy(&addr.in, a, sizeof(addr.in));
		addr.length = offsetof(struct aip_addr, in) + sizeof(struct in_addr);
		break;
	case AF_INET6:
		root = sc->sc_aip6;
		lk = &sc->sc_aip6_lock;
		memcpy(&addr.in6, a, sizeof(addr.in6));
		addr.length = offsetof(struct aip_addr, in6) + sizeof(struct in6_addr);
		break;
	default:
		return NULL;
	}


	lockmgr(lk, LK_SHARED);
	node = root->rnh_matchaddr((char*)&addr, root);
	if (node != NULL) {
		peer = ((struct wg_aip *)node)->a_peer;
		noise_remote_ref(peer->p_remote);
	} else {
		peer = NULL;
	}
	lockmgr(lk, LK_RELEASE);

	return (peer);
}

static void
wg_aip_remove_all(struct wg_softc *sc, struct wg_peer *peer)
{
	wg_debug_func();
	struct wg_aip		*aip, *taip;

	lockmgr(&sc->sc_aip4_lock, LK_EXCLUSIVE);
	LIST_FOREACH_MUTABLE(aip, &peer->p_aips, a_entry, taip) {
		if (aip->a_af == AF_INET) {
			if (sc->sc_aip4->rnh_deladdr((char*)&aip->a_addr, (char*)&aip->a_mask, sc->sc_aip4) == NULL)
				panic("failed to delete aip %p", aip);
			LIST_REMOVE(aip, a_entry);
			peer->p_aips_num--;
			WG_FREE(aip);
		}
	}
	lockmgr(&sc->sc_aip4_lock, LK_RELEASE);

	lockmgr(&sc->sc_aip6_lock, LK_EXCLUSIVE);
	LIST_FOREACH_MUTABLE(aip, &peer->p_aips, a_entry, taip) {
		if (aip->a_af == AF_INET6) {
			if (sc->sc_aip6->rnh_deladdr((char*)&aip->a_addr, (char*)&aip->a_mask, sc->sc_aip6) == NULL)
				panic("failed to delete aip %p", aip);
			LIST_REMOVE(aip, a_entry);
			peer->p_aips_num--;
			WG_FREE(aip);
		}
	}
	lockmgr(&sc->sc_aip6_lock, LK_RELEASE);

	if (!LIST_EMPTY(&peer->p_aips) || peer->p_aips_num != 0)
		panic("wg_aip_remove_all could not delete all %p", peer);
}

static int
wg_socket_init(struct wg_softc *sc, in_port_t port)
{
	wg_debug_func();
	struct thread *td = curthread;
	struct ucred *cred = sc->sc_ucred;
	struct socket *so4 = NULL, *so6 = NULL;
	int rc;

	if (!cred)
		return (EBUSY);

	rc = socreate(AF_INET, &so4, SOCK_DGRAM, IPPROTO_UDP, td);
	if (rc)
		goto out;
	so4->so_upcall = wg_so_upcall;
	so4->so_upcallarg = sc;
	atomic_set_int(&so4->so_rcv.ssb_flags, SSB_UPCALL);   

#ifdef INET6
	rc = socreate(AF_INET6, &so6, SOCK_DGRAM, IPPROTO_UDP, td);
	if (rc)
		goto out;
	so6->so_upcall = wg_so_upcall;
	so6->so_upcallarg = sc;
	atomic_set_int(&so6->so_rcv.ssb_flags, SSB_UPCALL);   
#endif

	if (sc->sc_socket.so_user_cookie) {
		rc = wg_socket_set_sockopt(so4, so6, SO_USER_COOKIE, &sc->sc_socket.so_user_cookie, sizeof(sc->sc_socket.so_user_cookie));
		if (rc)
			goto out;
	}

	rc = wg_socket_bind(&so4, &so6, &port);
	if (!rc) {
		sc->sc_socket.so_port = port;
		wg_socket_set(sc, so4, so6);
	}
out:
	if (rc) {
		if (so4 != NULL)
			soclose(so4, 0);
		if (so6 != NULL)
			soclose(so6, 0);
	}
	return (rc);
}

static int wg_socket_set_sockopt(struct socket *so4, struct socket *so6, int name, void *val, size_t len)
{
	wg_debug_func();
	int ret4 = 0, ret6 = 0;
	struct sockopt sopt = {
		.sopt_dir = SOPT_SET,
		.sopt_level = SOL_SOCKET,
		.sopt_name = name,
		.sopt_val = val,
		.sopt_valsize = len
	};

	if (so4)
		ret4 = sosetopt(so4, &sopt);
	if (so6)
		ret6 = sosetopt(so6, &sopt);
	return (ret4 ?: ret6);
}

static int wg_socket_set_cookie(struct wg_softc *sc, uint32_t user_cookie)
{
	wg_debug_func();
	struct wg_socket *so = &sc->sc_socket;
	int ret;

	ret = wg_socket_set_sockopt(so->so_so4, so->so_so6, SO_USER_COOKIE, &user_cookie, sizeof(user_cookie));
	if (!ret)
		so->so_user_cookie = user_cookie;
	return (ret);
}

static void
wg_socket_uninit(struct wg_softc *sc)
{
	wg_debug_func();
	wg_socket_set(sc, NULL, NULL);
}

static void
wg_socket_set(struct wg_softc *sc, struct socket *new_so4, struct socket *new_so6)
{
	wg_debug_func();
	struct wg_socket *so = &sc->sc_socket;
	struct socket *so4, *so6;

	lockmgr(&sc->sc_net_lock, LK_EXCLUSIVE);
	so4 = load_ptr(so->so_so4);
	so6 = load_ptr(so->so_so6);
	store_ptr(so->so_so4, new_so4);
	store_ptr(so->so_so6, new_so6);
	if (so4)
		soclose(so4, 0);
	if (so6)
		soclose(so6, 0);
	lockmgr(&sc->sc_net_lock, LK_RELEASE);
}

static int
wg_socket_bind(struct socket **in_so4, struct socket **in_so6, in_port_t *requested_port)
{
	wg_debug_func();
	struct socket *so4 = *in_so4, *so6 = *in_so6;
	int ret4 = 0, ret6 = 0;
	in_port_t port = *requested_port;
	struct sockaddr_in sin = {
		.sin_len = sizeof(struct sockaddr_in),
		.sin_family = AF_INET,
		.sin_port = htons(port)
	};
	struct sockaddr_in6 sin6 = {
		.sin6_len = sizeof(struct sockaddr_in6),
		.sin6_family = AF_INET6,
		.sin6_port = htons(port)
	};

	if (so4) {
		ret4 = sobind(so4, (struct sockaddr *)&sin, curthread);
		if (ret4 && ret4 != EADDRNOTAVAIL)
			return (ret4);
		if (!ret4 && !sin.sin_port) {
			struct sockaddr_in *bound_sin;
			int ret = so_pru_sockaddr(so4, (struct sockaddr **)&bound_sin);
			if (ret)
				return (ret);
			port = ntohs(bound_sin->sin_port);
			sin6.sin6_port = bound_sin->sin_port;
			kfree(bound_sin, M_SONAME);
		}
	}

	if (so6) {
		ret6 = sobind(so6, (struct sockaddr *)&sin6, curthread);
		if (ret6 && ret6 != EADDRNOTAVAIL)
			return (ret6);
		if (!ret6 && !sin6.sin6_port) {
			struct sockaddr_in6 *bound_sin6;
			int ret = so_pru_sockaddr(so6, (struct sockaddr **)&bound_sin6);
			if (ret)
				return (ret);
			port = ntohs(bound_sin6->sin6_port);
			kfree(bound_sin6, M_SONAME);
		}
	}

	if (ret4 && ret6)
		return (ret4);
	*requested_port = port;
	if (ret4 && !ret6 && so4) {
		soclose(so4, 0);
		*in_so4 = NULL;
	} else if (ret6 && !ret4 && so6) {
		soclose(so6, 0);
		*in_so6 = NULL;
	}
	return (0);
}

static int
wg_send(struct wg_softc *sc, struct wg_endpoint *e, struct mbuf *m)
{
	wg_debug_func();
	struct sockaddr *sa;
	struct wg_socket *so = &sc->sc_socket;
	struct socket *so4, *so6;
	struct mbuf *control = NULL;
	int ret = 0;
	size_t len = m->m_pkthdr.len;

	/* Get local control address before locking */
	if (e->e_remote.r_sa.sa_family == AF_INET) {
		if (e->e_local.l_in.s_addr != INADDR_ANY)
			control = sbcreatecontrol((caddr_t)&e->e_local.l_in,
			    sizeof(struct in_addr), IP_SENDSRCADDR,
			    IPPROTO_IP);
#ifdef INET6
	} else if (e->e_remote.r_sa.sa_family == AF_INET6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&e->e_local.l_in6))
			control = sbcreatecontrol((caddr_t)&e->e_local.l_pktinfo6,
			    sizeof(struct in6_pktinfo), IPV6_PKTINFO,
			    IPPROTO_IPV6);
#endif
	} else {
		m_freem(m);
		return (EAFNOSUPPORT);
	}

	/* Get remote address */
	sa = &e->e_remote.r_sa;

	lockmgr(&sc->sc_net_lock, LK_EXCLUSIVE);
	so4 = load_ptr(so->so_so4);
	so6 = load_ptr(so->so_so6);
	if (e->e_remote.r_sa.sa_family == AF_INET && so4 != NULL)
		ret = so_pru_sosend(so4, sa, NULL, m, control, 0, curthread);
	else if (e->e_remote.r_sa.sa_family == AF_INET6 && so6 != NULL)
		ret = so_pru_sosend(so6, sa, NULL, m, control, 0, curthread);
	else {
		ret = ENOTCONN;
		m_freem(control);
		m_freem(m);
	}
	lockmgr(&sc->sc_net_lock, LK_RELEASE);
	if (ret == 0) {
		IFNET_STAT_INC(sc->sc_ifp, opackets, 1);
		IFNET_STAT_INC(sc->sc_ifp, obytes, len);
	}
	return (ret);
}

static void
wg_send_buf(struct wg_softc *sc, struct wg_endpoint *e, uint8_t *buf, size_t len)
{
	wg_debug_func();
	struct mbuf	*m;
	int		 ret = 0;
	bool		 retried = false;

retry:
	MGETHDR(m, M_NOWAIT, MT_DATA);
	if (!m) {
		ret = ENOMEM;
		goto out;
	}
	m_copyback(m, 0, len, buf);

	if (ret == 0) {
		ret = wg_send(sc, e, m);
		/* Retry if we couldn't bind to e->e_local */
		if (ret == EADDRNOTAVAIL && !retried) {
			bzero(&e->e_local, sizeof(e->e_local));
			retried = true;
			goto retry;
		}
	} else {
		ret = wg_send(sc, e, m);
	}
out:
	if (ret)
		DPRINTF(sc, "Unable to send packet: %d\n", ret);
}

/* Timers */
static void
wg_timers_enable(struct wg_peer *peer)
{
	wg_debug_func();
	atomic_store_rel_bool(&peer->p_enabled, true);
	wg_timers_run_persistent_keepalive(peer);
}

static void
wg_timers_disable(struct wg_peer *peer)
{
	wg_debug_func();
	atomic_store_rel_bool(&peer->p_enabled, false);
	atomic_store_rel_bool(&peer->p_need_another_keepalive, false);

	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	callout_stop(&peer->p_new_handshake);
	callout_stop(&peer->p_send_keepalive);
	callout_stop(&peer->p_retry_handshake);
	callout_stop(&peer->p_persistent_keepalive);
	callout_stop(&peer->p_zero_key_material);
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_set_persistent_keepalive(struct wg_peer *peer, uint16_t interval)
{
	wg_debug_func();
	if (interval != peer->p_persistent_keepalive_interval) {
		atomic_store_rel_16(&peer->p_persistent_keepalive_interval, interval);
		if (atomic_load_acq_bool(&peer->p_enabled))
			wg_timers_run_persistent_keepalive(peer);
	}
}

static void
wg_timers_get_last_handshake(struct wg_peer *peer, struct wg_timespec64 *time)
{
	wg_debug_func();
	lockmgr(&peer->p_handshake_lock, LK_SHARED);
	time->tv_sec = peer->p_handshake_complete.tv_sec;
	time->tv_nsec = peer->p_handshake_complete.tv_nsec;
	lockmgr(&peer->p_handshake_lock, LK_RELEASE);
}

static void
wg_timers_event_data_sent(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	if (atomic_load_acq_bool(&peer->p_enabled) && !callout_pending(&peer->p_new_handshake))
		callout_reset(&peer->p_new_handshake, MSEC_2_TICKS(
		    NEW_HANDSHAKE_TIMEOUT * 1000 +
		    karc4random() % REKEY_TIMEOUT_JITTER),
		    wg_timers_run_new_handshake, peer);
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_data_received(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	if (atomic_load_acq_bool(&peer->p_enabled)) {
		if (!callout_pending(&peer->p_send_keepalive))
			callout_reset(&peer->p_send_keepalive,
			    MSEC_2_TICKS(KEEPALIVE_TIMEOUT * 1000),
			    wg_timers_run_send_keepalive, peer);
		else
			atomic_store_rel_bool(&peer->p_need_another_keepalive, true);
	}
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_any_authenticated_packet_sent(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	callout_stop(&peer->p_send_keepalive);
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_any_authenticated_packet_received(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	callout_stop(&peer->p_new_handshake);
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_any_authenticated_packet_traversal(struct wg_peer *peer)
{
	wg_debug_func();
	uint16_t interval;
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	interval = atomic_load_acq_16(&peer->p_persistent_keepalive_interval);
	if (atomic_load_acq_bool(&peer->p_enabled) && interval > 0)
		callout_reset(&peer->p_persistent_keepalive,
		     MSEC_2_TICKS(interval * 1000),
		     wg_timers_run_persistent_keepalive, peer);
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_handshake_initiated(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	if (atomic_load_acq_bool(&peer->p_enabled))
		callout_reset(&peer->p_retry_handshake, MSEC_2_TICKS(
		    REKEY_TIMEOUT * 1000 +
		    karc4random() % REKEY_TIMEOUT_JITTER),
		    wg_timers_run_retry_handshake, peer);
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_handshake_complete(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	if (atomic_load_acq_bool(&peer->p_enabled)) {
		lockmgr(&peer->p_handshake_lock, LK_EXCLUSIVE);
		callout_stop(&peer->p_retry_handshake);
		peer->p_handshake_retries = 0;
		getnanotime(&peer->p_handshake_complete);
		lockmgr(&peer->p_handshake_lock, LK_RELEASE);
		wg_timers_run_send_keepalive(peer);
	}
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_session_derived(struct wg_peer *peer)
{
	wg_debug_func();
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	if (atomic_load_acq_bool(&peer->p_enabled))
		callout_reset(&peer->p_zero_key_material,
		    MSEC_2_TICKS(REJECT_AFTER_TIME * 3 * 1000),
		    wg_timers_run_zero_key_material, peer);
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_event_want_initiation(struct wg_peer *peer)
{
	wg_debug_func();
	if (atomic_load_acq_bool(&peer->p_enabled))
		wg_timers_run_send_initiation(peer, false);
}

static void
wg_timers_run_send_initiation(struct wg_peer *peer, bool is_retry)
{
	wg_debug_func();
	if (!is_retry)
		peer->p_handshake_retries = 0;
	if (noise_remote_initiation_expired(peer->p_remote) == ETIMEDOUT)
		wg_send_initiation(peer);
}

static void
wg_timers_run_retry_handshake(void *_peer)
{
	wg_debug_func();
	struct wg_peer *peer = _peer;

	lockmgr(&peer->p_handshake_lock, LK_EXCLUSIVE);
	if (peer->p_handshake_retries <= MAX_TIMER_HANDSHAKES) {
		peer->p_handshake_retries++;
		lockmgr(&peer->p_handshake_lock, LK_RELEASE);

		DPRINTF(peer->p_sc, "Handshake for peer %" PRIu64 " did not complete "
		    "after %d seconds, retrying (try %d)\n", peer->p_id,
		    REKEY_TIMEOUT, peer->p_handshake_retries + 1);
		wg_peer_clear_src(peer);
		wg_timers_run_send_initiation(peer, true);
	} else {
		lockmgr(&peer->p_handshake_lock, LK_RELEASE);

		DPRINTF(peer->p_sc, "Handshake for peer %" PRIu64 " did not complete "
		    "after %d retries, giving up\n", peer->p_id,
		    MAX_TIMER_HANDSHAKES + 2);

		wg_queue_purge(&peer->p_stage_queue);
		lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
		callout_stop(&peer->p_send_keepalive);
		if (atomic_load_acq_bool(&peer->p_enabled) &&
		    !callout_pending(&peer->p_zero_key_material))
			callout_reset(&peer->p_zero_key_material,
			    MSEC_2_TICKS(REJECT_AFTER_TIME * 3 * 1000),
			    wg_timers_run_zero_key_material, peer);
		lockmgr(&peer->p_timer_lock, LK_RELEASE);
	}
}

static void
wg_timers_run_send_keepalive(void *_peer)
{
	wg_debug_func();
	struct wg_peer *peer = _peer;

	wg_send_keepalive(peer);
	lockmgr(&peer->p_timer_lock, LK_EXCLUSIVE);
	if (atomic_load_acq_bool(&peer->p_enabled) &&
	    atomic_load_acq_bool(&peer->p_need_another_keepalive)) {
		atomic_store_rel_bool(&peer->p_need_another_keepalive, false);
		callout_reset(&peer->p_send_keepalive,
		    MSEC_2_TICKS(KEEPALIVE_TIMEOUT * 1000),
		    wg_timers_run_send_keepalive, peer);
	}
	lockmgr(&peer->p_timer_lock, LK_RELEASE);
}

static void
wg_timers_run_new_handshake(void *_peer)
{
	wg_debug_func();
	struct wg_peer *peer = _peer;

	DPRINTF(peer->p_sc, "Retrying handshake with peer %" PRIu64 " because we "
	    "stopped hearing back after %d seconds\n",
	    peer->p_id, NEW_HANDSHAKE_TIMEOUT);

	wg_peer_clear_src(peer);
	wg_timers_run_send_initiation(peer, false);
}

static void
wg_timers_run_zero_key_material(void *_peer)
{
	wg_debug_func();
	struct wg_peer *peer = _peer;

	DPRINTF(peer->p_sc, "Zeroing out keys for peer %" PRIu64 ", since we "
	    "haven't received a new one in %d seconds\n",
	    peer->p_id, REJECT_AFTER_TIME * 3);
	noise_remote_keypairs_clear(peer->p_remote);
}

static void
wg_timers_run_persistent_keepalive(void *_peer)
{
	wg_debug_func();
	struct wg_peer *peer = _peer;

	if (atomic_load_acq_16(&peer->p_persistent_keepalive_interval) > 0)
		wg_send_keepalive(peer);
}

/* TODO Handshake */
static void
wg_peer_send_buf(struct wg_peer *peer, uint8_t *buf, size_t len)
{
	wg_debug_func();
	struct wg_endpoint endpoint;

	atomic_add_64(&peer->p_tx_bytes, len);
	wg_timers_event_any_authenticated_packet_traversal(peer);
	wg_timers_event_any_authenticated_packet_sent(peer);
	wg_peer_get_endpoint(peer, &endpoint);
	wg_send_buf(peer->p_sc, &endpoint, buf, len);
}

static void
wg_send_initiation(struct wg_peer *peer)
{
	wg_debug_func();
	struct wg_pkt_initiation pkt;

	if (noise_create_initiation(peer->p_remote, &pkt.s_idx, pkt.ue,
	    pkt.es, pkt.ets) != 0)
		return;

	DPRINTF(peer->p_sc, "Sending handshake initiation to peer %" PRIu64 "\n", peer->p_id);

	pkt.t = WG_PKT_INITIATION;
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	    sizeof(pkt) - sizeof(pkt.m));
	wg_peer_send_buf(peer, (uint8_t *)&pkt, sizeof(pkt));
	wg_timers_event_handshake_initiated(peer);
}

static void
wg_send_response(struct wg_peer *peer)
{
	wg_debug_func();
	struct wg_pkt_response pkt;

	if (noise_create_response(peer->p_remote, &pkt.s_idx, &pkt.r_idx,
	    pkt.ue, pkt.en) != 0)
		return;

	DPRINTF(peer->p_sc, "Sending handshake response to peer %" PRIu64 "\n", peer->p_id);

	wg_timers_event_session_derived(peer);
	pkt.t = WG_PKT_RESPONSE;
	cookie_maker_mac(&peer->p_cookie, &pkt.m, &pkt,
	     sizeof(pkt)-sizeof(pkt.m));
	wg_peer_send_buf(peer, (uint8_t*)&pkt, sizeof(pkt));
}

static void
wg_send_cookie(struct wg_softc *sc, struct cookie_macs *cm, uint32_t idx,
    struct wg_endpoint *e)
{
	wg_debug_func();
	struct wg_pkt_cookie	pkt;

	DPRINTF(sc, "Sending cookie response for denied handshake message\n");

	pkt.t = WG_PKT_COOKIE;
	pkt.r_idx = idx;

	cookie_checker_create_payload(&sc->sc_cookie, cm, pkt.nonce,
	    pkt.ec, &e->e_remote.r_sa);
	wg_send_buf(sc, e, (uint8_t *)&pkt, sizeof(pkt));
}

static void
wg_send_keepalive(struct wg_peer *peer)
{
	wg_debug_func();
	struct wg_packet *pkt;
	struct mbuf *m;

	if (wg_queue_len(&peer->p_stage_queue) > 0)
		goto send;
	if ((m = m_gethdr(M_NOWAIT, MT_DATA)) == NULL)
		return;
	if ((pkt = wg_packet_alloc(m)) == NULL) {
		m_freem(m);
		return;
	}
	wg_queue_push_staged(&peer->p_stage_queue, pkt);
	DPRINTF(peer->p_sc, "Sending keepalive packet to peer %" PRIu64 "\n", peer->p_id);
send:
	wg_peer_send_staged(peer);
}

static void
wg_handshake(struct wg_softc *sc, struct wg_packet *pkt)
{
	wg_debug_func();
	struct wg_pkt_initiation	*init;
	struct wg_pkt_response		*resp;
	struct wg_pkt_cookie		*cook;
	struct wg_endpoint		*e;
	struct wg_peer			*peer;
	struct mbuf			*m;
	struct noise_remote		*remote = NULL;
	int				 res;
	bool				 underload = false;
	static long			 wg_last_underload;
	struct timeval			 now;

	underload = wg_queue_len(&sc->sc_handshake_queue) >= MAX_QUEUED_HANDSHAKES / 8;
	getmicrouptime(&now);
	if (underload) {
		wg_last_underload = now.tv_sec;
	} else if (wg_last_underload) {
		underload = wg_last_underload + UNDERLOAD_TIMEOUT > now.tv_sec;
		if (!underload) {
			wg_last_underload = 0;
		}
	}

	m = pkt->p_mbuf;
	e = &pkt->p_endpoint;

	if ((pkt->p_mbuf = m = m_pullup(m, m->m_pkthdr.len)) == NULL)
		goto error;
		
	switch (*mtod(m, uint32_t *)) {
	case WG_PKT_INITIATION:
		init = mtod(m, struct wg_pkt_initiation *);

		res = cookie_checker_validate_macs(&sc->sc_cookie, &init->m,
				init, sizeof(*init) - sizeof(init->m),
				underload, &e->e_remote.r_sa );

		if (res == EINVAL) {
			DPRINTF(sc, "Invalid initiation MAC\n");

			goto error;
		} else if (res == ECONNREFUSED) {
			DPRINTF(sc, "Handshake ratelimited\n");

			goto error;
		} else if (res == EAGAIN) {
			wg_send_cookie(sc, &init->m, init->s_idx, e);

			goto error;
		} else if (res != 0) {
			panic("unexpected response: %d\n", res);
		}

		if (noise_consume_initiation(sc->sc_local, &remote,
		    init->s_idx, init->ue, init->es, init->ets) != 0) {
			DPRINTF(sc, "Invalid handshake initiation\n");
			goto error;
		}

		peer = noise_remote_arg(remote);

		DPRINTF(sc, "Receiving handshake initiation from peer %" PRIu64 "\n", peer->p_id);

		wg_peer_set_endpoint(peer, e);
		wg_send_response(peer);
		break;
	case WG_PKT_RESPONSE:
		resp = mtod(m, struct wg_pkt_response *);

		res = cookie_checker_validate_macs(&sc->sc_cookie, &resp->m,
				resp, sizeof(*resp) - sizeof(resp->m),
				underload, &e->e_remote.r_sa);

		if (res == EINVAL) {
			DPRINTF(sc, "Invalid response MAC\n");
			goto error;
		} else if (res == ECONNREFUSED) {
			DPRINTF(sc, "Handshake ratelimited\n");
			goto error;
		} else if (res == EAGAIN) {
			wg_send_cookie(sc, &resp->m, resp->s_idx, e);
			goto error;
		} else if (res != 0) {
			panic("unexpected response: %d\n", res);
		}

		if (noise_consume_response(sc->sc_local, &remote,
		    resp->s_idx, resp->r_idx, resp->ue, resp->en) != 0) {
			DPRINTF(sc, "Invalid handshake response\n");
			goto error;
		}

		peer = noise_remote_arg(remote);
		DPRINTF(sc, "Receiving handshake response from peer %" PRIu64 "\n", peer->p_id);

		wg_peer_set_endpoint(peer, e);
		wg_timers_event_session_derived(peer);
		wg_timers_event_handshake_complete(peer);
		break;
	case WG_PKT_COOKIE:
		cook = mtod(m, struct wg_pkt_cookie *);

		if ((remote = noise_remote_index(sc->sc_local, cook->r_idx)) == NULL) {
			DPRINTF(sc, "Unknown cookie index\n");
			goto error;
		}

		peer = noise_remote_arg(remote);

		if (cookie_maker_consume_payload(&peer->p_cookie,
		    cook->nonce, cook->ec) == 0) {
			DPRINTF(sc, "Receiving cookie response\n");
		} else {
			DPRINTF(sc, "Could not decrypt cookie response\n");
			goto error;
		}

		goto not_authenticated;
	default:
		panic("invalid packet in handshake queue");
	}

	wg_timers_event_any_authenticated_packet_received(peer);
	wg_timers_event_any_authenticated_packet_traversal(peer);

not_authenticated:
	atomic_add_64(&peer->p_rx_bytes, m->m_pkthdr.len);
	IFNET_STAT_INC(sc->sc_ifp, ipackets, 1);
	IFNET_STAT_INC(sc->sc_ifp, ibytes, m->m_pkthdr.len);
error:
	if (remote != NULL)
		noise_remote_put(remote);
	wg_packet_free(pkt);
}

static void
wg_softc_handshake_receive(void *ctx, int pending)
{
	wg_debug_func();
	struct wg_softc *sc = (struct wg_softc*)ctx;
	struct wg_packet *pkt;
	while ((pkt = wg_queue_dequeue_handshake(&sc->sc_handshake_queue)) != NULL)
		wg_handshake(sc, pkt);
}

static void
wg_mbuf_reset(struct mbuf *m)
{
	wg_debug_func();
	M_ASSERTPKTHDR(m);
	int remove_flags =
		M_PROTOFLAGS | M_BCAST | M_MCAST | M_VLANTAG |
		M_HASH | M_CKHASH |
		M_LENCHECKED
		;
	m->m_flags &= ~remove_flags;
	m_tag_init(m);
	m->m_pkthdr.csum_flags = 0;
}

static inline unsigned int
calculate_padding(struct wg_packet *pkt)
{
	wg_debug_func();
	unsigned int padded_size, last_unit = pkt->p_mbuf->m_pkthdr.len;

	if (__predict_false(!pkt->p_mtu))
		return (last_unit + (WG_PKT_PADDING - 1)) & ~(WG_PKT_PADDING - 1);

	if (__predict_false(last_unit > pkt->p_mtu))
		last_unit %= pkt->p_mtu;

	padded_size = (last_unit + (WG_PKT_PADDING - 1)) & ~(WG_PKT_PADDING - 1);
	if (pkt->p_mtu < padded_size)
		padded_size = pkt->p_mtu;
	return padded_size - last_unit;
}

static void
wg_encrypt(struct wg_softc *sc, struct wg_packet *pkt)
{
	wg_debug_func();
	static const uint8_t	 padding[WG_PKT_PADDING] = { 0 };
	struct wg_pkt_data	*data;
	struct wg_peer		*peer;
	struct noise_remote	*remote;
	struct mbuf		*m;
	uint32_t		 idx;
	unsigned int		 padlen;
	enum wg_ring_state	 state = WG_PACKET_DEAD;

	remote = noise_keypair_remote(pkt->p_keypair);
	peer = noise_remote_arg(remote);
	m = pkt->p_mbuf;

	/* Pad the packet */
	padlen = calculate_padding(pkt);
	if (padlen != 0 && !m_append(m, padlen, padding))
		goto out;

	/* Do encryption */
	if (noise_keypair_encrypt(pkt->p_keypair, &idx, pkt->p_nonce, m) != 0)
		goto out;

	/* Put header into packet */
	M_PREPEND(m, sizeof(struct wg_pkt_data), M_NOWAIT);
	if (m == NULL)
		goto out;
	data = mtod(m, struct wg_pkt_data *);
	data->t = WG_PKT_DATA;
	data->r_idx = idx;
	data->nonce = htole64(pkt->p_nonce);

	wg_mbuf_reset(m);
	state = WG_PACKET_CRYPTED;
out:
	pkt->p_mbuf = m;
	cpu_mfence();
	pkt->p_state = state;
	WG_TASK_ENQUEUE(&peer->p_send);
	noise_remote_put(remote);
}

static void
wg_decrypt(struct wg_softc *sc, struct wg_packet *pkt)
{
	wg_debug_func();
	struct wg_peer		*peer, *allowed_peer;
	struct noise_remote	*remote;
	struct mbuf		*m;
	int			 len;
	enum wg_ring_state	 state = WG_PACKET_DEAD;

	remote = noise_keypair_remote(pkt->p_keypair);
	peer = noise_remote_arg(remote);
	m = pkt->p_mbuf;

	/* Read nonce and then adjust to remove the header. */
	pkt->p_nonce = le64toh(mtod(m, struct wg_pkt_data *)->nonce);
	m_adj(m, sizeof(struct wg_pkt_data));

	if (noise_keypair_decrypt(pkt->p_keypair, pkt->p_nonce, m) != 0)
		goto out;

	/* A packet with length 0 is a keepalive packet */
	if (__predict_false(m->m_pkthdr.len == 0)) {
		DPRINTF(sc, "Receiving keepalive packet from peer "
		    "%" PRIu64 "\n", peer->p_id);
		state = WG_PACKET_CRYPTED;
		goto out;
	}

	/*
	 * We can let the network stack handle the intricate validation of the
	 * IP header, we just worry about the sizeof and the version, so we can
	 * read the source address in wg_aip_lookup.
	 */

	if (determine_af_and_pullup(&m, &pkt->p_af) == 0) {
		if (pkt->p_af == AF_INET) {
			struct ip *ip = mtod(m, struct ip *);
			allowed_peer = wg_aip_lookup(sc, AF_INET, &ip->ip_src);
			len = ntohs(ip->ip_len);
			if (len >= sizeof(struct ip) && len < m->m_pkthdr.len)
				m_adj(m, len - m->m_pkthdr.len);
		} else if (pkt->p_af == AF_INET6) {
			struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
			allowed_peer = wg_aip_lookup(sc, AF_INET6, &ip6->ip6_src);
			len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
			if (len < m->m_pkthdr.len)
				m_adj(m, len - m->m_pkthdr.len);
		} else
			panic("determine_af_and_pullup returned unexpected value");
	} else {
		DPRINTF(sc, "Packet is neither ipv4 nor ipv6 from peer %" PRIu64 "\n", peer->p_id);
		goto out;
	}

	/* We only want to compare the address, not dereference, so drop the ref. */
	if (allowed_peer != NULL)
		noise_remote_put(allowed_peer->p_remote);

	if (__predict_false(peer != allowed_peer)) {
		DPRINTF(sc, "Packet has unallowed src IP from peer %" PRIu64 "\n", peer->p_id);
		goto out;
	}

	wg_mbuf_reset(m);
	state = WG_PACKET_CRYPTED;
out:
	pkt->p_mbuf = m;
	cpu_mfence();
	pkt->p_state = state;
	WG_TASK_ENQUEUE(&peer->p_recv);
	noise_remote_put(remote);
}

static void
wg_softc_decrypt(void *ctx, int pending)
{
	wg_debug_func();
	struct wg_softc *sc = (struct wg_softc*)ctx;
	struct wg_packet *pkt;
	while ((pkt = wg_queue_dequeue_parallel(&sc->sc_decrypt_parallel)) != NULL)
		wg_decrypt(sc, pkt);
}

static void
wg_softc_encrypt(void *ctx, int pending)
{
	wg_debug_func();
	struct wg_softc *sc = (struct wg_softc*)ctx;
	struct wg_packet *pkt;
	while ((pkt = wg_queue_dequeue_parallel(&sc->sc_encrypt_parallel)) != NULL)
		wg_encrypt(sc, pkt);
}

static void
wg_encrypt_dispatch(struct wg_softc *sc)
{
	wg_debug_func();
	for (int i = 0; i < ncpus; i++) {
		if (atomic_load_acq_int(&sc->sc_encrypt[i].ta_pending)) {
			wg_debug_task("skip [%d]", i);
			continue;
		}
		WG_SC_TASK_ENQUEUE(sc, &sc->sc_encrypt[i]);
	}
}

static void
wg_decrypt_dispatch(struct wg_softc *sc)
{
	wg_debug_func();
	for (int i = 0; i < ncpus; i++) {
		if (atomic_load_acq_int(&sc->sc_decrypt[i].ta_pending)) {
			wg_debug_task("skip [%d]", i);
			continue;
		}
		WG_SC_TASK_ENQUEUE(sc, &sc->sc_decrypt[i]);
	}
}

static void
wg_deliver_out(void *ctx, int pending)
{
	wg_debug_func();
	struct wg_peer *peer = (struct wg_peer*)ctx;
	struct wg_endpoint	 endpoint;
	struct wg_softc		*sc = peer->p_sc;
	struct wg_packet	*pkt;
	struct mbuf		*m;
	int			 rc, len;

	wg_peer_get_endpoint(peer, &endpoint);

	while ((pkt = wg_queue_dequeue_serial(&peer->p_encrypt_serial)) != NULL) {
		if (pkt->p_state != WG_PACKET_CRYPTED)
			goto error;

		m = pkt->p_mbuf;
		pkt->p_mbuf = NULL;

		len = m->m_pkthdr.len;

		wg_timers_event_any_authenticated_packet_traversal(peer);
		wg_timers_event_any_authenticated_packet_sent(peer);
		rc = wg_send(sc, &endpoint, m);
		if (rc == 0) {
			if (len > (sizeof(struct wg_pkt_data) + NOISE_AUTHTAG_LEN))
				wg_timers_event_data_sent(peer);
			atomic_add_64(&peer->p_tx_bytes, len);
		} else if (rc == EADDRNOTAVAIL) {
			wg_peer_clear_src(peer);
			wg_peer_get_endpoint(peer, &endpoint);
			goto error;
		} else {
			goto error;
		}
		wg_packet_free(pkt);
		if (noise_keep_key_fresh_send(peer->p_remote))
			wg_timers_event_want_initiation(peer);
		continue;
error:
		IFNET_STAT_INC(sc->sc_ifp, oerrors, 1);
		wg_packet_free(pkt);
	}
}

static void
wg_deliver_in(void *ctx, int pending)
{
	wg_debug_func();
	struct wg_peer *peer = (struct wg_peer*)ctx;
	struct wg_softc		*sc = peer->p_sc;
	struct ifnet		*ifp = sc->sc_ifp;
	struct wg_packet	*pkt;
	struct mbuf		*m;

	while ((pkt = wg_queue_dequeue_serial(&peer->p_decrypt_serial)) != NULL) {
		if (pkt->p_state != WG_PACKET_CRYPTED)
			goto error;

		m = pkt->p_mbuf;
		if (noise_keypair_nonce_check(pkt->p_keypair, pkt->p_nonce) != 0)
			goto error;

		if (noise_keypair_received_with(pkt->p_keypair) == ECONNRESET)
			wg_timers_event_handshake_complete(peer);

		wg_timers_event_any_authenticated_packet_received(peer);
		wg_timers_event_any_authenticated_packet_traversal(peer);
		wg_peer_set_endpoint(peer, &pkt->p_endpoint);

		atomic_add_64(&peer->p_rx_bytes, m->m_pkthdr.len +
			sizeof(struct wg_pkt_data) + NOISE_AUTHTAG_LEN);
		IFNET_STAT_INC(sc->sc_ifp, ipackets, 1);
		IFNET_STAT_INC(sc->sc_ifp, ibytes, m->m_pkthdr.len +
		    sizeof(struct wg_pkt_data) + NOISE_AUTHTAG_LEN);

		if (m->m_pkthdr.len == 0)
			goto done;

		KKASSERT(pkt->p_af == AF_INET || pkt->p_af == AF_INET6);
		pkt->p_mbuf = NULL;

		m->m_pkthdr.rcvif = ifp;

		lockmgr(&sc->sc_net_lock, LK_EXCLUSIVE);
		BPF_MTAP_AF(ifp, m, pkt->p_af);

		if (pkt->p_af == AF_INET)
			netisr_queue(NETISR_IP, m);
		if (pkt->p_af == AF_INET6)
			netisr_queue(NETISR_IPV6, m);
		lockmgr(&sc->sc_net_lock, LK_RELEASE);

		wg_timers_event_data_received(peer);

done:
		if (noise_keep_key_fresh_recv(peer->p_remote))
			wg_timers_event_want_initiation(peer);
		wg_packet_free(pkt);
		continue;
error:
		IFNET_STAT_INC(ifp, ierrors, 1);
		wg_packet_free(pkt);
	}
}

static struct wg_packet *
wg_packet_alloc(struct mbuf *m)
{
	wg_debug_func();
	struct wg_packet *pkt;

	if ((pkt = WG_MALLOC(sizeof(*pkt))) == NULL) {
		return (NULL);
	}
	pkt->p_mbuf = m;
	return (pkt);
}

static void
wg_packet_free(struct wg_packet *pkt)
{
	wg_debug_func();
	if (pkt->p_keypair != NULL)
		noise_keypair_put(pkt->p_keypair);
	if (pkt->p_mbuf != NULL)
		m_freem(pkt->p_mbuf);
	WG_FREE(pkt);
}

static void
wg_queue_init(struct wg_queue *queue, const char *name)
{
	wg_debug_func();
	lockinit(&queue->q_lock, name, 0, LK_CANRECURSE);
	STAILQ_INIT(&queue->q_queue);
	queue->q_len = 0;
}

static void
wg_queue_deinit(struct wg_queue *queue)
{
	wg_debug_func();
	wg_queue_purge(queue);
	lockuninit(&queue->q_lock);
}

static size_t
wg_queue_len(struct wg_queue *queue)
{
	wg_debug_func();
	size_t len;
	lockmgr(&queue->q_lock, LK_SHARED);
	len = queue->q_len;
	lockmgr(&queue->q_lock, LK_RELEASE);
	return (len);
}

static int
wg_queue_enqueue_handshake(struct wg_queue *hs, struct wg_packet *pkt)
{
	wg_debug_func();
	int ret = 0;
	lockmgr(&hs->q_lock, LK_EXCLUSIVE);
	if (hs->q_len < MAX_QUEUED_HANDSHAKES) {
		STAILQ_INSERT_TAIL(&hs->q_queue, pkt, p_parallel);
		hs->q_len++;
	} else {
		ret = ENOBUFS;
	}
	lockmgr(&hs->q_lock, LK_RELEASE);
	if (ret != 0)
		wg_packet_free(pkt);
	return (ret);
}

static struct wg_packet *
wg_queue_dequeue_handshake(struct wg_queue *hs)
{
	wg_debug_func();
	struct wg_packet *pkt;
	lockmgr(&hs->q_lock, LK_EXCLUSIVE);
	if ((pkt = STAILQ_FIRST(&hs->q_queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&hs->q_queue, p_parallel);
		hs->q_len--;
	}
	lockmgr(&hs->q_lock, LK_RELEASE);
	return (pkt);
}

static void
wg_queue_push_staged(struct wg_queue *staged, struct wg_packet *pkt)
{
	wg_debug_func();
	struct wg_packet *old = NULL;

	lockmgr(&staged->q_lock, LK_EXCLUSIVE);
	if (staged->q_len >= MAX_STAGED_PKT) {
		old = STAILQ_FIRST(&staged->q_queue);
		STAILQ_REMOVE_HEAD(&staged->q_queue, p_parallel);
		staged->q_len--;
	}
	STAILQ_INSERT_TAIL(&staged->q_queue, pkt, p_parallel);
	staged->q_len++;
	lockmgr(&staged->q_lock, LK_RELEASE);

	if (old != NULL)
		wg_packet_free(old);
}

static void
wg_queue_enlist_staged(struct wg_queue *staged, struct wg_packet_list *list)
{
	wg_debug_func();
	struct wg_packet *pkt, *tpkt;
	STAILQ_FOREACH_MUTABLE(pkt, list, p_parallel, tpkt)
		wg_queue_push_staged(staged, pkt);
}

static void
wg_queue_delist_staged(struct wg_queue *staged, struct wg_packet_list *list)
{
	wg_debug_func();
	lockmgr(&staged->q_lock, LK_EXCLUSIVE);
	*list = staged->q_queue;
	STAILQ_INIT(&staged->q_queue);
	staged->q_len = 0;
	lockmgr(&staged->q_lock, LK_RELEASE);
}

static void
wg_queue_purge(struct wg_queue *staged)
{
	wg_debug_func();
	struct wg_packet_list list;
	struct wg_packet *pkt, *tpkt;
	wg_queue_delist_staged(staged, &list);
	STAILQ_FOREACH_MUTABLE(pkt, &list, p_parallel, tpkt)
		wg_packet_free(pkt);
}

static int
wg_queue_both(struct wg_queue *parallel, struct wg_queue *serial, struct wg_packet *pkt)
{
	wg_debug_func();
	int ret = 0;
	pkt->p_state = WG_PACKET_UNCRYPTED;

	lockmgr(&serial->q_lock, LK_EXCLUSIVE);
	if (serial->q_len < MAX_QUEUED_PKT) {
		serial->q_len++;
		STAILQ_INSERT_TAIL(&serial->q_queue, pkt, p_serial);
	} else {
		lockmgr(&serial->q_lock, LK_RELEASE);
		wg_packet_free(pkt);
		ret = ENOBUFS;
		goto out;
	}
	lockmgr(&serial->q_lock, LK_RELEASE);

	lockmgr(&parallel->q_lock, LK_EXCLUSIVE);
	if (parallel->q_len < MAX_QUEUED_PKT) {
		parallel->q_len++;
		STAILQ_INSERT_TAIL(&parallel->q_queue, pkt, p_parallel);
	} else {
		lockmgr(&parallel->q_lock, LK_RELEASE);
		pkt->p_state = WG_PACKET_DEAD;
		ret = ENOBUFS;
		goto out;
	}
	lockmgr(&parallel->q_lock, LK_RELEASE);
out:
	return (ret);
}

static struct wg_packet *
wg_queue_dequeue_serial(struct wg_queue *serial)
{
	wg_debug_func();
	struct wg_packet *pkt = NULL;
	lockmgr(&serial->q_lock, LK_EXCLUSIVE);
	if (serial->q_len > 0 && STAILQ_FIRST(&serial->q_queue)->p_state != WG_PACKET_UNCRYPTED) {
		serial->q_len--;
		pkt = STAILQ_FIRST(&serial->q_queue);
		STAILQ_REMOVE_HEAD(&serial->q_queue, p_serial);
	}
	lockmgr(&serial->q_lock, LK_RELEASE);
	return (pkt);
}

static struct wg_packet *
wg_queue_dequeue_parallel(struct wg_queue *parallel)
{
	wg_debug_func();
	struct wg_packet *pkt = NULL;
	lockmgr(&parallel->q_lock, LK_EXCLUSIVE);
	if (parallel->q_len > 0) {
		parallel->q_len--;
		pkt = STAILQ_FIRST(&parallel->q_queue);
		STAILQ_REMOVE_HEAD(&parallel->q_queue, p_parallel);
	}
	lockmgr(&parallel->q_lock, LK_RELEASE);
	return (pkt);
}

static void
wg_so_upcall(struct socket *so, void *arg, int waitflag)
{
	wg_debug_func();
	struct sockaddr	*sa;
	struct sockbuf	 sb;
	struct mbuf	 *m;
	int		 flags;
	
	flags = MSG_DONTWAIT;
	for(;;){
		sa = NULL;
		sbinit(&sb, 100000000);
		if(so_pru_soreceive(so, &sa, NULL, &sb, NULL, &flags))
			break;
		if (sb.sb_mb == NULL)
			break;

		/* Don't trust the various socket layers to get the
		packet header and length correct (eg. kern/15175) */
		sb.sb_mb->m_pkthdr.len = 0;
		for (m = sb.sb_mb; m != NULL; m = m->m_next)
			sb.sb_mb->m_pkthdr.len += m->m_len;
		wg_input(sb.sb_mb, sa, arg);
		if (sa != NULL)
			kfree(sa, M_SONAME);
	}
	if (sa != NULL)
		kfree(sa, M_SONAME);
}

static void
wg_input(struct mbuf *m, struct sockaddr *sa, struct wg_softc *sc)
{
	wg_debug_func();
	const struct sockaddr_in	*sin;
#ifdef INET6
	const struct sockaddr_in6	*sin6;
#endif
	struct noise_remote		*remote;
	struct wg_pkt_data		*data;
	struct wg_packet		*pkt;
	struct wg_peer			*peer;
	struct mbuf			*defragged;

	defragged = m_defrag(m, M_NOWAIT);
	if (defragged)
		m = defragged;
	m = m_unshare(m, M_NOWAIT);
	if (!m) {
		IFNET_STAT_INC(sc->sc_ifp, ierrors, 1);
		return;
	}

	/* Pullup enough to read packet type */
	if ((m = m_pullup(m, sizeof(uint32_t))) == NULL) {
		IFNET_STAT_INC(sc->sc_ifp, ierrors, 1);
		return;
	}

	if ((pkt = wg_packet_alloc(m)) == NULL) {
		IFNET_STAT_INC(sc->sc_ifp, ierrors, 1);
		m_freem(m);
		return;
	}

	/* Save send/recv address and port for later. */
	if (sa->sa_family == AF_INET) {
		sin = (const struct sockaddr_in *)sa;
		pkt->p_endpoint.e_remote.r_sin = sin[0];
		//pkt->p_endpoint.e_local.l_in = sin[1].sin_addr;
		wg_debug_input_ip("local",pkt->p_endpoint.e_local.l_in);
		wg_debug_input_ip("remote",pkt->p_endpoint.e_remote.r_sin.sin_addr);
#ifdef INET6
	} else if (sa->sa_family == AF_INET6) {
		sin6 = (const struct sockaddr_in6 *)sa;
		pkt->p_endpoint.e_remote.r_sin6 = sin6[0];
		pkt->p_endpoint.e_local.l_in6 = sin6[1].sin6_addr;
#endif
	} else
		goto error;

	if ((m->m_pkthdr.len == sizeof(struct wg_pkt_initiation) &&
		*mtod(m, uint32_t *) == WG_PKT_INITIATION) ||
	    (m->m_pkthdr.len == sizeof(struct wg_pkt_response) &&
		*mtod(m, uint32_t *) == WG_PKT_RESPONSE) ||
	    (m->m_pkthdr.len == sizeof(struct wg_pkt_cookie) &&
		*mtod(m, uint32_t *) == WG_PKT_COOKIE)) {

		if (wg_queue_enqueue_handshake(&sc->sc_handshake_queue, pkt) != 0) {
			IFNET_STAT_INC(sc->sc_ifp, ierrors, 1);
			DPRINTF(sc, "Dropping handshake packet\n");
		}
		WG_SC_TASK_ENQUEUE(sc, &sc->sc_handshake);
	} else if (m->m_pkthdr.len >= sizeof(struct wg_pkt_data) +
	    NOISE_AUTHTAG_LEN && *mtod(m, uint32_t *) == WG_PKT_DATA) {

		/* Pullup whole header to read r_idx below. */
		if ((pkt->p_mbuf = m_pullup(m, sizeof(struct wg_pkt_data))) == NULL)
			goto error;

		data = mtod(pkt->p_mbuf, struct wg_pkt_data *);
		if ((pkt->p_keypair = noise_keypair_lookup(sc->sc_local, data->r_idx)) == NULL)
			goto error;

		remote = noise_keypair_remote(pkt->p_keypair);
		peer = noise_remote_arg(remote);
		if (wg_queue_both(&sc->sc_decrypt_parallel, &peer->p_decrypt_serial, pkt) != 0)
			IFNET_STAT_INC(sc->sc_ifp, iqdrops, 1);
		wg_decrypt_dispatch(sc);
		noise_remote_put(remote);
	} else {
		goto error;
	}
	return;
error:
	IFNET_STAT_INC(sc->sc_ifp, ierrors, 1);
	wg_packet_free(pkt);
}

static void
wg_peer_send_staged(struct wg_peer *peer)
{
	wg_debug_func();
	struct wg_packet_list	 list;
	struct noise_keypair	*keypair;
	struct wg_packet	*pkt, *tpkt;
	struct wg_softc		*sc = peer->p_sc;

	wg_queue_delist_staged(&peer->p_stage_queue, &list);

	if (STAILQ_EMPTY(&list))
		return;

	if ((keypair = noise_keypair_current(peer->p_remote)) == NULL)
		goto error;

	STAILQ_FOREACH(pkt, &list, p_parallel) {
		if (noise_keypair_nonce_next(keypair, &pkt->p_nonce) != 0)
			goto error_keypair;
	}
	STAILQ_FOREACH_MUTABLE(pkt, &list, p_parallel, tpkt) {
		pkt->p_keypair = noise_keypair_ref(keypair);
		if (wg_queue_both(&sc->sc_encrypt_parallel, &peer->p_encrypt_serial, pkt) != 0)
			IFNET_STAT_INC(sc->sc_ifp, oqdrops, 1);
	}
	wg_encrypt_dispatch(sc);
	noise_keypair_put(keypair);
	return;

error_keypair:
	noise_keypair_put(keypair);
error:
	wg_queue_enlist_staged(&peer->p_stage_queue, &list);
	wg_timers_event_want_initiation(peer);
}

static inline void
xmit_err(struct ifnet *ifp, struct mbuf *m, sa_family_t af)
{
	wg_debug_func();
	IFNET_STAT_INC(ifp, oerrors, 1);
	if (!m)
		return;
	if (af == AF_INET)
		icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, 0, 0);
	else if (af == AF_INET6)
		icmp6_error(m, ICMP6_DST_UNREACH, 0, 0);
	else
		m_freem(m);
}

static int
wg_xmit(struct ifnet *ifp, struct mbuf *m, sa_family_t af, uint32_t mtu)
{
	wg_debug_func();
	struct wg_packet	*pkt = NULL;
	struct wg_softc		*sc = ifp->if_softc;
	struct wg_peer		*peer;
	int			 rc = 0;
	sa_family_t		 peer_af;

	/* Work around lifetime issue in the ipv6 mld code. */
	if (__predict_false((ifp->if_link_state & LINK_STATE_DOWN) || !sc)) {
		rc = ENXIO;
		goto err_xmit;
	}

	if ((pkt = wg_packet_alloc(m)) == NULL) {
		rc = ENOBUFS;
		goto err_xmit;
	}
	
	pkt->p_mtu = mtu;
	pkt->p_af = af;

	if (af == AF_INET) {
		peer = wg_aip_lookup(sc, AF_INET, &mtod(m, struct ip *)->ip_dst);
	} else if (af == AF_INET6) {
		peer = wg_aip_lookup(sc, AF_INET6, &mtod(m, struct ip6_hdr *)->ip6_dst);
	} else {
		rc = EAFNOSUPPORT;
		goto err_xmit;
	}

	BPF_MTAP_AF(ifp, m, pkt->p_af);

	if (__predict_false(peer == NULL)) {
		if (af == AF_INET)
			wg_debug_output_ip("no peer for", mtod(m, struct ip*)->ip_dst);
		rc = 0;
		goto err_xmit;
	}

	peer_af = peer->p_endpoint.e_remote.r_sa.sa_family;
	if (__predict_false(peer_af != AF_INET && peer_af != AF_INET6)) {
		DPRINTF(sc, "No valid endpoint has been configured or "
			    "discovered for peer %" PRIu64 "\n", peer->p_id);
		rc = EHOSTUNREACH;
		goto err_peer;
	}

	wg_queue_push_staged(&peer->p_stage_queue, pkt);
	wg_peer_send_staged(peer);
	noise_remote_put(peer->p_remote);
	return (0);

err_peer:
	noise_remote_put(peer->p_remote);
err_xmit:
	if (pkt) {
		pkt->p_mbuf = NULL;
		wg_packet_free(pkt);
	}
	xmit_err(ifp, m, af);
	return (rc);
}

static inline int
determine_af_and_pullup(struct mbuf **m, sa_family_t *af)
{
	wg_debug_func();
	u_char ipv;

	if ((*m)->m_pkthdr.len >= sizeof(struct ip6_hdr))
		*m = m_pullup(*m, sizeof(struct ip6_hdr));
	else if ((*m)->m_pkthdr.len >= sizeof(struct ip))
		*m = m_pullup(*m, sizeof(struct ip));
	else
		return (EAFNOSUPPORT);
	if (*m == NULL)
		return (ENOBUFS);
	ipv = mtod(*m, struct ip *)->ip_v;
	if (ipv == 4)
		*af = AF_INET;
	else if (ipv == 6 && (*m)->m_pkthdr.len >= sizeof(struct ip6_hdr))
		*af = AF_INET6;
	else
		return (EAFNOSUPPORT);
	return (0);
}

static void
wg_start(struct ifnet *ifp, struct ifaltq_subque *ifsq)
{
	wg_debug_func();
}

static int
wg_output(struct ifnet *ifp, struct mbuf *m, struct sockaddr *dst, struct rtentry *rt)
{
	wg_debug_func();
	sa_family_t parsed_af;
	uint32_t af, mtu;
	int ret;
	struct mbuf *defragged;

	if (dst->sa_family == AF_UNSPEC)
		memcpy(&af, dst->sa_data, sizeof(af));
	else
		af = dst->sa_family;
	if (af == AF_UNSPEC) {
		ret = EAFNOSUPPORT;
		goto err_xmit;
	}

	defragged = m_defrag(m, M_NOWAIT);
	if (defragged)
		m = defragged;
	m = m_unshare(m, M_NOWAIT);
	if (!m) {
		ret = ENOBUFS;
		goto err_xmit;
	}

	ret = determine_af_and_pullup(&m, &parsed_af);
	if (ret)
		goto err_xmit;

	if (parsed_af != af) {
		ret = EAFNOSUPPORT;
		goto err_xmit;
	}

	mtu = (rt != NULL && rt->rt_rmx.rmx_mtu > 0) ? rt->rt_rmx.rmx_mtu : ifp->if_mtu;
	return (wg_xmit(ifp, m, parsed_af, mtu));

err_xmit:
	xmit_err(ifp, m, AF_UNSPEC);
	return (ret);
}

static int
wgc_set(struct wg_softc *sc, struct wg_data_io *wgd)
{
	wg_debug_func();
	struct wg_interface_io	*iface_u, iface_io;
	struct wg_peer_io	*peer_u, peer_io;
	struct wg_aip_io	*aip_u, aip_io;
	struct wg_peer		*peer=NULL;
	struct noise_remote	*remote=NULL;
	struct ifnet		*ifp;
	uint8_t			 public[WG_KEY_SIZE], private[WG_KEY_SIZE];
	size_t			 i, j;
	bool			 need_insert;
	int			 ret = 0;

	lockmgr(&sc->sc_lock, LK_EXCLUSIVE);
	if (wgd->wgd_size == 0 || wgd->wgd_interface == NULL) {
		ret = EFAULT;
		goto error;
	}

	if (wgd->wgd_size >= UINT32_MAX / 2) {
		ret = E2BIG;
		goto error;
	}

	ifp = sc->sc_ifp;
	iface_u = wgd->wgd_interface;
	if ((ret = copyin(iface_u, &iface_io, sizeof(iface_io))) != 0)
		goto error;

	if (iface_io.i_flags & WG_IO_INTERFACE_REPLACE_PEERS)
		wg_peer_destroy_all(sc);

	if (iface_io.i_flags & WG_IO_INTERFACE_PORT) {
		if (iface_io.i_port > UINT16_MAX) {
			ret = EINVAL;
			goto error;
		}
		if (iface_io.i_port != sc->sc_socket.so_port) {
			if ((ifp->if_flags & IFF_RUNNING) != 0) {
				if ((ret = wg_socket_init(sc, iface_io.i_port)) != 0)
					goto error;
			} else
				sc->sc_socket.so_port = iface_io.i_port;
		}
	}

	if (iface_io.i_flags & WG_IO_INTERFACE_COOKIE) {
		if (iface_io.i_cookie > UINT16_MAX) {
			ret = EINVAL;
			goto error;
		}
		if ((ret = wg_socket_set_cookie(sc, iface_io.i_cookie)))
			goto error;
	}

	if (iface_io.i_flags & WG_IO_INTERFACE_PRIVATE &&
		(noise_local_keys(sc->sc_local, NULL, private) ||
		timingsafe_bcmp(private, iface_io.i_private, WG_KEY_SIZE))){
		if (curve25519_generate_public(public, iface_io.i_private)) {
			/* Peer conflict: remove conflicting peer. */
			if ((remote = noise_remote_lookup(sc->sc_local,
				public)) != NULL) {
				wg_peer_destroy(noise_remote_arg(remote));
				noise_remote_put(remote);
			}
			/*
			 * Set the private key and invalidate all existing
			 * handshakes.
			 */
			/* Note: we might be removing the private key. */
			noise_local_private(sc->sc_local, iface_io.i_private);
			if (noise_local_keys(sc->sc_local, NULL, NULL) == 0)
				cookie_checker_update(&sc->sc_cookie, public);
			else
				cookie_checker_update(&sc->sc_cookie, NULL);
		}
	}

	if (iface_io.i_flags & WG_IO_INTERFACE_COOKIE) {
		if (iface_io.i_cookie > UINT32_MAX) {
			ret = EINVAL;
			goto error;
		}
		if ((ret = wg_socket_set_cookie(sc, iface_io.i_cookie)) != 0)
			goto error;
	}

	peer_u = &iface_u->i_peers[0];
	for(i=0; i<iface_io.i_peers_count; i++) {
		need_insert = false;
		if ((ret = copyin(peer_u, &peer_io, sizeof(peer_io))) != 0)
			goto error;

		if (!(peer_io.p_flags & WG_IO_PEER_PUBLIC)) {
			ret = EINVAL;
			goto error;
		}

		if (noise_local_keys(sc->sc_local, public, NULL) == 0 &&
			bcmp(public, peer_io.p_public, WG_KEY_SIZE) == 0)
			goto next_peer;

		if ((remote = noise_remote_lookup(sc->sc_local, peer_io.p_public)) != NULL)
			peer = noise_remote_arg(remote);

		if (peer_io.p_flags & WG_IO_PEER_REMOVE) {
			if (remote != NULL) {
				wg_peer_destroy(peer);
				noise_remote_put(remote);
			}
			goto next_peer;
		}

		if (peer_io.p_flags & WG_IO_PEER_REPLACE_AIPS && peer != NULL)
			wg_aip_remove_all(sc, peer);

		if (peer == NULL) {
			if ((peer = wg_peer_alloc(sc, peer_io.p_public)) == NULL) {
				ret = ENOMEM;
				goto error;
			}
			need_insert = true;
		}

		if (peer_io.p_flags & WG_IO_PEER_ENDPOINT) {
			memcpy(&peer->p_endpoint.e_remote, &peer_io.p_endpoint,
				sizeof(peer->p_endpoint.e_remote));
		}

		if (peer_io.p_flags & WG_IO_PEER_PSK)
			noise_remote_set_psk(peer->p_remote, peer_io.p_psk);

		if (peer_io.p_pki > UINT16_MAX) {
			ret = EINVAL;
			goto error;
		}
		wg_timers_set_persistent_keepalive(peer, peer_io.p_pki);

		aip_u = &peer_u->p_aips[0];
		for (j=0; j<peer_io.p_aips_count; j++) {
			if ((ret = copyin(aip_u, &aip_io, sizeof(aip_io))) != 0)
				goto error;
			if (aip_io.a_cidr > 32 ) {
				ret = EINVAL;
				goto error;
			}
			if (aip_io.a_af != AF_INET
#ifdef INET
				&& aip_io.a_af != AF_INET6
#endif
			) {
				aip_u++;
				continue;
			}

			if ((ret = wg_aip_add(sc, peer, aip_io.a_af,
				&aip_io.a_addr, aip_io.a_cidr)) != 0) {
wg_debug("ret = %d", ret);
				goto error;
			}
			aip_u++;
		}

		if (need_insert) {
			if ((ret = noise_remote_enable(peer->p_remote)) != 0)
				goto error;

			TAILQ_INSERT_TAIL(&sc->sc_peers, peer, p_entry);
			sc->sc_peers_num++;
			if (sc->sc_ifp->if_link_state & LINK_STATE_UP) {
				wg_timers_enable(peer);
			}
		}

		if (remote != NULL)
			noise_remote_put(remote);
		peer_u = (struct wg_peer_io *)aip_u;
		continue;
next_peer:
		aip_u = &peer_u->p_aips[0];
		aip_u += peer_io.p_aips_count;
		peer_u = (struct wg_peer_io *)aip_u;

	}
	goto ok;

error:
	if (need_insert && peer != NULL) /* If we fail, only destroy if it was new. */
		wg_peer_destroy(peer);
	if (remote != NULL)
		noise_remote_put(remote);
ok:
	explicit_bzero(&iface_io, sizeof(iface_io));
	explicit_bzero(&peer_io, sizeof(peer_io));
	explicit_bzero(&aip_io, sizeof(aip_io));
	explicit_bzero(&public, sizeof(public));
	explicit_bzero(&private, sizeof(private));
	lockmgr(&sc->sc_lock, LK_RELEASE);
	return (ret);
}

static int
wgc_get(struct wg_softc *sc, struct wg_data_io *wgd)
{
	wg_debug_func();
	struct wg_interface_io	*iface_u, iface_io;
	struct wg_peer_io	*peer_u, peer_io;
	struct wg_aip_io	*aip_u, aip_io;
	struct wg_peer *peer;
	struct wg_aip *aip;
	size_t size, peer_count, aip_count;
	int ret=0;

	lockmgr(&sc->sc_lock, LK_SHARED);
	size = sizeof(struct wg_interface_io);
	size += (sizeof(struct wg_peer_io)) * sc->sc_peers_num;
	TAILQ_FOREACH(peer, &sc->sc_peers, p_entry) {
		size += sizeof(struct wg_aip_io) * peer->p_aips_num;
	}
	if (wgd->wgd_size < size)
		goto ret_size;

	iface_u = wgd->wgd_interface;
	bzero(&iface_io, sizeof(iface_io));

	if (sc->sc_socket.so_port != 0){
		iface_io.i_port = sc->sc_socket.so_port;
		iface_io.i_flags |= WG_IO_INTERFACE_PORT;
	}
	if (sc->sc_socket.so_user_cookie != 0){
		iface_io.i_cookie = sc->sc_socket.so_user_cookie;
		iface_io.i_flags |= WG_IO_INTERFACE_COOKIE;

	}
	if (noise_local_keys(sc->sc_local, iface_io.i_public, iface_io.i_private) == 0){
		iface_io.i_flags |= WG_IO_INTERFACE_PUBLIC;
		if(wgc_privileged(sc))
			iface_io.i_flags |= WG_IO_INTERFACE_PRIVATE;
		else 
			explicit_bzero(iface_io.i_private, sizeof(iface_io.i_private));
	}

	peer_count = 0;
	peer_u = &iface_u->i_peers[0];
	TAILQ_FOREACH(peer, &sc->sc_peers, p_entry) {
		bzero(&peer_io, sizeof(peer_io));

		peer_io.p_pki = peer->p_persistent_keepalive_interval;
		peer_io.p_txbytes = atomic_load_acq_64(&peer->p_tx_bytes);
		peer_io.p_rxbytes = atomic_load_acq_64(&peer->p_rx_bytes);
		wg_timers_get_last_handshake(peer, &peer_io.p_last_handshake);

		peer_io.p_flags |= WG_IO_PEER_ENDPOINT;
		memcpy(&peer_io.p_endpoint, &peer->p_endpoint.e_remote,
			sizeof(peer_io.p_endpoint));

		peer_io.p_flags |= WG_IO_PEER_PUBLIC;
		if (noise_remote_keys(peer->p_remote, peer_io.p_public,
			peer_io.p_psk) == 0 ) {
			if(wgc_privileged(sc))
				peer_io.p_flags |= WG_IO_PEER_PSK;
			else 
				explicit_bzero(peer_io.p_psk, sizeof(peer_io.p_psk));
		}

		aip_count = 0;
		aip_u = &peer_u->p_aips[0];
		LIST_FOREACH(aip, &peer->p_aips, a_entry) {
			bzero(&aip_io, sizeof(aip_io));
			if (aip->a_af == AF_INET) {
				aip_io.a_af = aip->a_af;
				aip_io.a_cidr = bitcount32(aip->a_mask.ip);
				memcpy(&aip_io.a_addr.in, &aip->a_addr.in,
					sizeof(aip_io.a_addr.in));
			}
#ifdef INET6
			else if (aip->a_af == AF_INET6) {
				aip_io.a_af = aip->a_af;
				aip_io.a_cidr = in6_mask2len(&aip->a_mask.in6, NULL);
				memcpy(&aip_io.a_addr.in6, &aip->a_addr.in6,
					sizeof(aip_io.a_addr.in6));
			}
#endif
			if ((ret = copyout(&aip_io, aip_u, sizeof(aip_io))) != 0)
				goto error;
			aip_u++;
			aip_count++;
		}

		peer_io.p_aips_count = aip_count;

		if ((ret = copyout(&peer_io, peer_u, sizeof(peer_io))) != 0)
			goto error;
		peer_u = (struct wg_peer_io*)aip_u;
		peer_count ++;
	}
	iface_io.i_peers_count = peer_count;
	ret = copyout(&iface_io, iface_u, sizeof(iface_io));
error:
ret_size:
	lockmgr(&sc->sc_lock, LK_RELEASE);
	explicit_bzero(&iface_io, sizeof(iface_io));
	explicit_bzero(&peer_io, sizeof(peer_io));
	wgd->wgd_size = size;
	return (ret);
}

static int
wg_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data, struct ucred *cred)
{
	wg_debug_func();
	struct wg_data_io *wgd = (struct wg_data_io *)data;
	struct ifreq *ifr = (struct ifreq *)data;
	struct wg_softc *sc;
	int ret = 0;

	lockmgr(&wg_lock, LK_SHARED);
	sc = ifp->if_softc;
	if (!sc) {
		ret = ENXIO;
		goto out;
	}

	switch (cmd) {
	case SIOCSWG:
		ret = priv_check(curthread, PRIV_NET_WG);
		if (ret == 0)
			ret = wgc_set(sc, wgd);
		break;
	case SIOCGWG:
		ret = wgc_get(sc, wgd);
		break;
	/* Interface IOCTLs */
	case SIOCSIFADDR:
		/*
		 * This differs from *BSD norms, but is more uniform with how
		 * WireGuard behaves elsewhere.
		 */
		break;
	case SIOCSIFFLAGS:
		if (ifp->if_flags & IFF_UP)
			ret = wg_up(sc);
		else
			wg_down(sc);
		break;
	case SIOCSIFMTU:
		if (ifr->ifr_mtu <= 0 || ifr->ifr_mtu > MAX_MTU)
			ret = EINVAL;
		else
			ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	default:
		ret = ENOTTY;
	}

out:
	lockmgr(&wg_lock, LK_RELEASE);
	return (ret);
}

static int
wg_up(struct wg_softc *sc)
{
	wg_debug_func();
	struct ifnet *ifp = sc->sc_ifp;
	struct wg_peer *peer;
	int rc = EBUSY;

	lockmgr(&sc->sc_lock, LK_EXCLUSIVE);
	/* ifnet's being removed, no more wg_up(). */
	if ((sc->sc_flags & WGF_DYING) != 0)
		goto out;

	/* Silent success if we're already running. */
	rc = 0;
	if (ifp->if_flags & IFF_RUNNING)
		goto out;
	ifp->if_flags |= IFF_RUNNING;

	rc = wg_socket_init(sc, sc->sc_socket.so_port);
	if (rc == 0) {
		TAILQ_FOREACH(peer, &sc->sc_peers, p_entry)
			wg_timers_enable(peer);
		IF_LINK_STATE_CHANGE(sc->sc_ifp, LINK_STATE_UP);
	} else {
		ifp->if_flags &= ~IFF_RUNNING;
		DPRINTF(sc, "Unable to initialize sockets: %d\n", rc);
	}
out:
	lockmgr(&sc->sc_lock, LK_RELEASE);
	return (rc);
}

static void
wg_down(struct wg_softc *sc)
{
	wg_debug_func();
	struct ifnet *ifp = sc->sc_ifp;
	struct wg_peer *peer;

	lockmgr(&sc->sc_lock, LK_EXCLUSIVE);
	if (!(ifp->if_flags & IFF_RUNNING)) {
		lockmgr(&sc->sc_lock, LK_RELEASE);
		return;
	}
	ifp->if_flags &= ~IFF_RUNNING;

	TAILQ_FOREACH(peer, &sc->sc_peers, p_entry) {
		wg_queue_purge(&peer->p_stage_queue);
		wg_timers_disable(peer);
	}

	wg_queue_purge(&sc->sc_handshake_queue);

	TAILQ_FOREACH(peer, &sc->sc_peers, p_entry) {
		noise_remote_handshake_clear(peer->p_remote);
		noise_remote_keypairs_clear(peer->p_remote);
	}

	IF_LINK_STATE_CHANGE(sc->sc_ifp, LINK_STATE_DOWN);
	wg_socket_uninit(sc);

	lockmgr(&sc->sc_lock, LK_RELEASE);
}

static int
wg_clone_create(struct if_clone *ifc, int unit, caddr_t params, caddr_t data)
{
	wg_debug_func();
	struct wg_softc *sc;
	struct ifnet *ifp;

	if ((sc = WG_MALLOC(sizeof(*sc))) == NULL)
		goto free_none;

	if ((sc->sc_local = noise_local_alloc(sc)) == NULL)
		goto free_sc;

	if ((sc->sc_encrypt = WG_MALLOC(sizeof(struct task)*ncpus)) == NULL)
		goto free_local;

	if ((sc->sc_decrypt = WG_MALLOC(sizeof(struct task)*ncpus)) == NULL)
		goto free_encrypt;

	if (!rn_inithead((void **)&sc->sc_aip4_mask, NULL, 0))
		goto free_decrypt;

	if (!rn_inithead((void **)&sc->sc_aip4, sc->sc_aip4_mask, offsetof(struct aip_addr, in) * NBBY))
		goto free_aip4_mask;

	if (!rn_inithead((void **)&sc->sc_aip6_mask, NULL, 0))
		goto free_aip4;

	if (!rn_inithead((void **)&sc->sc_aip6, sc->sc_aip6_mask, offsetof(struct aip_addr, in6) * NBBY))
		goto free_aip6_mask;
		
	atomic_add_int(&clone_count, 1);
	ifp = sc->sc_ifp = if_alloc(IFT_WIREGUARD);

	sc->sc_ucred = crhold(curthread->td_ucred);
	sc->sc_socket.so_port = 0;

	TAILQ_INIT(&sc->sc_peers);
	sc->sc_peers_num = 0;

	cookie_checker_init(&sc->sc_cookie);

	lockinit(&sc->sc_aip4_lock, "wg softc aip4 lock", 0, LK_CANRECURSE);
	lockinit(&sc->sc_aip6_lock, "wg softc aip6 lock", 0, LK_CANRECURSE);

	WG_TASK_INIT(&sc->sc_handshake, wg_softc_handshake_receive, sc);
	wg_queue_init(&sc->sc_handshake_queue, "hsq");

	for (int i = 0; i < ncpus; i++) {
		WG_TASK_INIT(&sc->sc_encrypt[i], wg_softc_encrypt, sc);
		WG_TASK_INIT(&sc->sc_decrypt[i], wg_softc_decrypt, sc);
	}

	wg_queue_init(&sc->sc_encrypt_parallel, "encp");
	wg_queue_init(&sc->sc_decrypt_parallel, "decp");

	lockinit(&sc->sc_lock, "wg softc lock", 0, LK_CANRECURSE);
	lockinit(&sc->sc_net_lock, "wg softc net lock", 0, LK_CANRECURSE);

	ifp->if_softc = sc;
	if_initname(ifp, wgname, unit);

	ifp->if_mtu = DEFAULT_MTU;
	ifq_set_maxlen(&ifp->if_snd, ifqmaxlen);
	ifp->if_flags = IFF_NOARP | IFF_MULTICAST;
	ifp->if_init = wg_init;
	ifp->if_start = wg_start;
	ifp->if_output = wg_output;
	ifp->if_ioctl = wg_ioctl;
	if_attach(ifp, NULL);
	bpfattach(ifp, DLT_NULL, sizeof(uint32_t));
	lockmgr(&wg_lock, LK_EXCLUSIVE);
	LIST_INSERT_HEAD(&wg_list, sc, sc_entry);
	lockmgr(&wg_lock, LK_RELEASE);
	return (0);
free_aip6_mask:
	WG_FREE(sc->sc_aip6_mask);
free_aip4:
	WG_FREE(sc->sc_aip4);
free_aip4_mask:
	WG_FREE(sc->sc_aip4_mask);
free_decrypt:
	WG_FREE(sc->sc_decrypt);
free_encrypt:
	WG_FREE(sc->sc_encrypt);
free_local:
	noise_local_free(sc->sc_local, NULL);
free_sc:
	WG_FREE(sc);
free_none:
	return (ENOMEM);
}

static void
wg_clone_deferred_free(struct noise_local *l)
{
	wg_debug_func();
	struct wg_softc *sc = noise_local_arg(l);

	WG_FREE(sc);
	atomic_add_int(&clone_count, -1);
}

static int
wg_radix_freeentry(struct radix_node *rn, void *arg)
{
	wg_debug_func();
	struct radix_node_head *head = arg;
	struct radix_node *x;
	x = rn_delete((char*)(rn+2), NULL, head);
	if (x != NULL)
		Free(x);
	return 0;
}

static void 
wg_radix_free(struct wg_softc *sc)
{
	wg_debug_func();
	lockmgr(&sc->sc_aip4_lock, LK_EXCLUSIVE);
	lockmgr(&sc->sc_aip6_lock, LK_EXCLUSIVE);
	sc->sc_aip4->rnh_walktree(sc->sc_aip4, wg_radix_freeentry,
		sc->sc_aip4);
	sc->sc_aip4->rnh_walktree(sc->sc_aip4_mask, wg_radix_freeentry,
		sc->sc_aip4_mask);
	sc->sc_aip6->rnh_walktree(sc->sc_aip6, wg_radix_freeentry,
		sc->sc_aip6);
	sc->sc_aip6_mask->rnh_walktree(sc->sc_aip6_mask, wg_radix_freeentry,
		sc->sc_aip6_mask);
	Free(sc->sc_aip4);
	Free(sc->sc_aip4_mask);
	Free(sc->sc_aip6);
	Free(sc->sc_aip6_mask);
	lockmgr(&sc->sc_aip4_lock, LK_RELEASE);
	lockmgr(&sc->sc_aip6_lock, LK_RELEASE);
	lockuninit(&sc->sc_aip4_lock);
	lockuninit(&sc->sc_aip6_lock);
	    
}
static int
wg_clone_destroy(struct ifnet *ifp)
{
	wg_debug_func();
	struct wg_softc *sc = ifp->if_softc;
	struct ucred *cred;

	lockmgr(&wg_lock, LK_EXCLUSIVE);
	ifp->if_softc = NULL;
	LIST_REMOVE(sc, sc_entry);
	lockmgr(&wg_lock, LK_RELEASE);

	lockmgr(&sc->sc_lock, LK_EXCLUSIVE);
	sc->sc_flags |= WGF_DYING;
	cred = sc->sc_ucred;
	sc->sc_ucred = NULL;
	IF_LINK_STATE_CHANGE(sc->sc_ifp, LINK_STATE_DOWN);
	if_purgeaddrs_nolink(sc->sc_ifp);
	wg_socket_uninit(sc);
	wg_peer_destroy_all(sc);

	WG_TASK_DRAIN(&sc->sc_handshake);
	for (int i = 0; i < ncpus; i++) {
		WG_TASK_DRAIN(&sc->sc_encrypt[i]);
		WG_TASK_DRAIN(&sc->sc_decrypt[i]);
	}
	WG_FREE(sc->sc_encrypt);
	WG_FREE(sc->sc_decrypt);
	wg_queue_deinit(&sc->sc_handshake_queue);
	wg_queue_deinit(&sc->sc_encrypt_parallel);
	wg_queue_deinit(&sc->sc_decrypt_parallel);

	wg_radix_free(sc);

	cookie_checker_free(&sc->sc_cookie);

	if (cred != NULL)
		crfree(cred);
	if_detach(sc->sc_ifp);
	if_free(sc->sc_ifp);

	lockuninit(&sc->sc_net_lock);

	lockmgr(&sc->sc_lock, LK_RELEASE);
	lockuninit(&sc->sc_lock);

	noise_local_free(sc->sc_local, wg_clone_deferred_free);
	return 0;
}

static bool
wgc_privileged(struct wg_softc *sc)
{
	wg_debug_func();
	struct thread *td;

	td = curthread;
	return (priv_check(td, PRIV_NET_WG) == 0);
}

static void
wg_init(void *xsc)
{
	wg_debug_func();
	struct wg_softc *sc;

	sc = xsc;
	wg_up(sc);
}

static int
wg_module_init(void)
{
	wg_debug_func();
	int ret = ENOMEM;

	lockinit(&wg_lock, "wg lock", 0, LK_CANRECURSE);
	if (if_clone_attach(&wg_cloner) != 0)
		goto free_none;
	if (cookie_init() != 0)
		goto free_none;
	return (0);
free_none:
	return (ret);
}

static void
wg_module_deinit(void)
{
	wg_debug_func();
	struct wg_softc *sc, *tsc;
	LIST_FOREACH_MUTABLE(sc, &wg_list, sc_entry, tsc) 
		wg_clone_destroy(sc->sc_ifp);
	if_clone_detach(&wg_cloner);
	KKASSERT(LIST_EMPTY(&wg_list));
	cookie_deinit();
	lockuninit(&wg_lock);
}

static int
wg_module_event_handler(module_t mod, int what, void *arg)
{
	wg_debug_func();
	switch (what) {
		case MOD_LOAD:
			wg_module_init();
			break;
		case MOD_UNLOAD:
			wg_module_deinit();
			break;
		default:
			return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t wg_moduledata = {
	wgname,
	wg_module_event_handler,
	NULL
};

DECLARE_MODULE(wg, wg_moduledata, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(wg, WIREGUARD_VERSION);

