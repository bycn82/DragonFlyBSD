// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/wg/if_wg.h>
#include <netinet/in.h>
#include "containers.h"

#define IPC_SUPPORTS_KERNEL_INTERFACE

static int get_dgram_socket(void)
{
	static int sock = -1;
	if (sock < 0)
		sock = socket(AF_INET, SOCK_DGRAM, 0);
	return sock;
}

static int kernel_get_wireguard_interfaces(struct string_list *list)
{
	struct ifgroupreq ifgr = { .ifgr_name = "wg" };
	struct ifg_req *ifg;
	int s = get_dgram_socket(), ret = 0;

	if (s < 0)
		return -errno;

	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0)
		return errno == ENOENT ? 0 : -errno;

	ifgr.ifgr_groups = calloc(1, ifgr.ifgr_len);
	if (!ifgr.ifgr_groups)
		return -errno;
	if (ioctl(s, SIOCGIFGMEMB, (caddr_t)&ifgr) < 0) {
		ret = -errno;
		goto out;
	}

	for (ifg = ifgr.ifgr_groups; ifg && ifgr.ifgr_len > 0; ++ifg) {
		if ((ret = string_list_add(list, ifg->ifgrq_member)) < 0)
			goto out;
		ifgr.ifgr_len -= sizeof(struct ifg_req);
	}
out:
	free(ifgr.ifgr_groups);
	return ret;
}

static int kernel_get_device(struct wgdevice **device, const char *iface)
{
	struct wg_data_io wgd = { .wgd_size = 0 };
	struct wg_interface_io *iface_io;
	struct wg_peer_io *peer_io;
	struct wg_aip_io *aip_io;

	struct wgdevice *dev;
	struct wgpeer *peer;
	struct wgallowedip *aip;
	int s = get_dgram_socket(), ret;

	if (s < 0)
		return -errno;

	*device = NULL;
	dev = NULL;
	strlcpy(wgd.wgd_name, iface, sizeof(wgd.wgd_name));

	/* get size */
	if (ioctl(s, SIOCGWG, (caddr_t)&wgd) < 0)
		goto out;

	if (!(iface_io = wgd.wgd_interface = malloc(wgd.wgd_size)))
		goto out;

	if (ioctl(s, SIOCGWG, (caddr_t)&wgd) < 0)
		goto out;

	if (!(dev = calloc(1, sizeof(*dev))))
		goto out;

	strlcpy(dev->name, iface, sizeof(dev->name));
	if (iface_io->i_flags & WG_IO_INTERFACE_PORT) {
		dev->listen_port = iface_io->i_port;
		dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
	}

	if (iface_io->i_flags & WG_IO_INTERFACE_PUBLIC) {
		memcpy(dev->public_key, iface_io->i_public, sizeof(dev->public_key));
		dev->flags |= WGDEVICE_HAS_PUBLIC_KEY;
	}

	if (iface_io->i_flags & WG_IO_INTERFACE_PRIVATE) {
		memcpy(dev->private_key, iface_io->i_private, sizeof(dev->private_key));
		dev->flags |= WGDEVICE_HAS_PRIVATE_KEY;
	}


	peer_io = &iface_io->i_peers[0];
	for (size_t i = 0; i < iface_io->i_peers_count; ++i) {
		peer = calloc(1, sizeof(*peer));
		if (!peer)
			goto out;

		if (dev->first_peer == NULL)
			dev->first_peer = peer;
		else
			dev->last_peer->next_peer = peer;
		dev->last_peer = peer;

		memcpy(&peer->endpoint, &peer_io->p_endpoint, sizeof(peer->endpoint));

		if (peer_io->p_flags & WG_IO_PEER_PUBLIC) {
			memcpy(peer->public_key, peer_io->p_public, sizeof(peer->public_key));
			peer->flags |= WGPEER_HAS_PUBLIC_KEY;
		}

		if (peer_io->p_flags & WG_IO_PEER_PSK) {
			memcpy(peer->preshared_key, peer_io->p_psk, sizeof(peer->preshared_key));
			if (!key_is_zero(peer->preshared_key))
				peer->flags |= WGPEER_HAS_PRESHARED_KEY;
		}

		if (peer_io->p_pki > 0) {
			peer->persistent_keepalive_interval = peer_io->p_pki;
			peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
		}


		peer->rx_bytes = peer_io->p_rxbytes;
		peer->tx_bytes = peer_io->p_txbytes;

		peer->last_handshake_time.tv_sec = peer_io->p_last_handshake.tv_sec;
		peer->last_handshake_time.tv_nsec = peer_io->p_last_handshake.tv_nsec;

		aip_io = &peer_io->p_aips[0];
		for (size_t j = 0; j < peer_io->p_aips_count; ++j) {
			aip = calloc(1, sizeof(*aip));
			if (!aip)
				goto out;

			if (peer->first_allowedip == NULL)
				peer->first_allowedip = aip;
			else
				peer->last_allowedip->next_allowedip = aip;
			peer->last_allowedip = aip;

			aip->family = aip_io->a_af;
			if (aip_io->a_af == AF_INET) {
				memcpy(&aip->ip4, &aip_io->a_addr, sizeof(aip->ip4));
				aip->cidr = aip_io->a_cidr;
			} else if (aip_io->a_af == AF_INET6) {
				memcpy(&aip->ip6, &aip_io->a_addr, sizeof(aip->ip6));
				aip->cidr = aip_io->a_cidr;
			}
			++aip_io;
		}
		peer_io = (struct wg_peer_io *)aip_io;
	}

out:
	*device = dev;
	errno = 0;
	ret = -errno;
	free(wgd.wgd_interface);
	return ret;
}

static int kernel_set_device(struct wgdevice *dev)
{
	struct wg_data_io wgd = { .wgd_size = sizeof(struct wg_interface_io) };
	struct wg_interface_io *iface_io;
	struct wg_peer_io *peer_io;
	struct wg_aip_io *aip_io;
	struct wgpeer *peer;
	struct wgallowedip *aip;
	int s = get_dgram_socket(), ret;
	size_t peer_count, aip_count;

	if (s < 0)
		return -errno;

	for_each_wgpeer(dev, peer) {
		wgd.wgd_size += sizeof(*peer_io);
		for_each_wgallowedip(peer, aip)
			wgd.wgd_size += sizeof(*aip_io);
	}
	iface_io = wgd.wgd_interface = calloc(1, wgd.wgd_size);
	if (!wgd.wgd_interface)
		return -errno;
	strlcpy(wgd.wgd_name, dev->name, sizeof(wgd.wgd_name));

	if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY) {
		memcpy(iface_io->i_private, dev->private_key, sizeof(iface_io->i_private));
		iface_io->i_flags |= WG_IO_INTERFACE_PRIVATE;
	}

	if (dev->flags & WGDEVICE_HAS_LISTEN_PORT) {
		iface_io->i_port = dev->listen_port;
		iface_io->i_flags |= WG_IO_INTERFACE_PORT;
	}

	if (dev->flags & WGDEVICE_REPLACE_PEERS)
		iface_io->i_flags |= WG_IO_INTERFACE_REPLACE_PEERS;

	peer_count = 0;
	peer_io = &iface_io->i_peers[0];
	for_each_wgpeer(dev, peer) {
		peer_io->p_flags = WG_IO_PEER_PUBLIC;
		memcpy(peer_io->p_public, peer->public_key, sizeof(peer_io->p_public));
		
printf("-----peer sa family %d\n", peer->endpoint.addr.sa_family);
		if((peer->endpoint.addr.sa_family == AF_INET ||
				peer->endpoint.addr.sa_family == AF_INET6) &&
				peer->endpoint.addr.sa_len <= sizeof(peer_io->p_endpoint)) {
			memcpy(&peer_io->p_endpoint, &peer->endpoint, sizeof(peer->endpoint));
			peer_io->p_flags |= WG_IO_PEER_ENDPOINT;
		}
printf("-----peer sa family %d\n", peer->endpoint.addr.sa_family);
printf("-----peer_io sa family %d\n", peer_io->p_endpoint.p_sa.sa_family);

		if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
			memcpy(peer_io->p_psk, peer->preshared_key, sizeof(peer_io->p_psk));
			peer_io->p_flags |= WG_IO_PEER_PSK;
		}

		peer_io->p_pki = 0;
		if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
			peer_io->p_pki = peer->persistent_keepalive_interval;

		if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS)
			peer_io->p_flags |= WG_IO_PEER_REPLACE_AIPS;

		if (peer->flags & WGPEER_REMOVE_ME)
			peer_io->p_flags |= WG_IO_PEER_REMOVE;

		aip_count = 0;
		aip_io = &peer_io->p_aips[0];
		for_each_wgallowedip(peer, aip) {
			aip_io->a_af = aip->family;
			aip_io->a_cidr = aip->cidr;

			if (aip->family == AF_INET)
				memcpy(&aip_io->a_addr, &aip->ip4, sizeof(aip->ip4));
			else if (aip->family == AF_INET6)
				memcpy(&aip_io->a_addr, &aip->ip6, sizeof(aip->ip6));
			else
				continue;
			++aip_count;
			++aip_io;
		}
		peer_io->p_aips_count = aip_count;
		++peer_count;
		peer_io = (struct wg_peer_io *)aip_io;
	}
	iface_io->i_peers_count = peer_count;

	if (ioctl(s, SIOCSWG, (caddr_t)&wgd) < 0)
		goto out;
	errno = 0;

out:
	ret = -errno;
	free(wgd.wgd_interface);
	return ret;
}
