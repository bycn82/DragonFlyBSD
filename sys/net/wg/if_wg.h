/* SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019 Matt Dunwoodie <ncon@noconroy.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef __IF_WG_H__
#define __IF_WG_H__

#define WG_KEY_SIZE	32
struct wg_timespec64 {
	uint64_t	tv_sec;
	uint64_t	tv_nsec;
};

struct wg_aip_io {
	sa_family_t		a_af;
	uint32_t		a_cidr;
	union wg_aip_addr{
		struct in_addr	in;
#ifdef INET6
		struct in6_addr	in6;
#endif
	}	a_addr;
};

struct wg_peer_io {
	int			p_flags;
	uint8_t			p_public[WG_KEY_SIZE];
	uint8_t			p_psk[WG_KEY_SIZE];
	uint16_t		p_pka;
	sa_family_t		p_af;
	union {
		struct sockaddr_in	p_sin;
#ifdef INET6
		struct sockaddr_in6	p_sin6;
#endif
	}			p_endpoint;
	uint64_t		p_txbytes;
	uint64_t		p_rxbytes;
	struct wg_timespec64	p_last_handshake;
	size_t			p_aips_count;
	struct wg_aip_io	p_aips[];
};

#define WG_IO_PEER_PUBLIC		(1 << 0)
#define WG_IO_PEER_PSK			(1 << 1)
#define WG_IO_PEER_ENDPOINT		(1 << 2)
#define WG_IO_PEER_REPLACE_AIPS		(1 << 3)
#define WG_IO_PEER_REMOVE		(1 << 4)
#define WG_IO_PEER_PKI			(1 << 5)

struct wg_interface_io {
	uint8_t			i_flags;
	uint32_t		i_cookie;
	in_port_t		i_port;
	uint8_t			i_public[WG_KEY_SIZE];
	uint8_t			i_private[WG_KEY_SIZE];
	size_t			i_peers_count;
	struct wg_peer_io	i_peers[];
};
#define WG_IO_INTERFACE_PUBLIC		(1 << 0)
#define WG_IO_INTERFACE_PRIVATE		(1 << 1)
#define WG_IO_INTERFACE_PORT		(1 << 2)
#define WG_IO_INTERFACE_COOKIE		(1 << 3)
#define WG_IO_INTERFACE_REPLACE_PEERS	(1 << 4)

struct wg_data_io {
	char	 wgd_name[IFNAMSIZ];
	size_t	 wgd_size;
	struct wg_interface_io *wgd_interface;
};


#define SIOCSWG _IOWR('i', 210, struct wg_data_io)
#define SIOCGWG _IOWR('i', 211, struct wg_data_io)

#endif /* __IF_WG_H__ */

