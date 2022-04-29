#include <sys/param.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/wg/if_wg.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <err.h>
#include <resolv.h>

#include "ifconfig.h"

struct wg_data_io	 wg_data = { 0 };
struct wg_interface_io	*wg_interface = NULL;
struct wg_peer_io	*wg_peer = NULL;
struct wg_aip_io	*wg_aip = NULL;

#define WG_KEY_SIZE_BASE64 (4 * ((WG_KEY_SIZE + 2) / 3)+1)
#define WG_ERROR_REPORT(_ret, _s) { \
	if (_ret){\
		errno = _ret; \
		err(1, "`%s` %s", __FUNCTION__, _s);\
		if (wg_interface) { \
			free(wg_interface); \
			wg_interface = NULL;\
		} \
	}\
}

static char 
*wg_bytes(uint64_t b)
{
	static char buf[64];
	char *p = "KMGT";
	int i;
	for (i=0; i<4; i++)
		if (b<(1ULL<<(10*(i+1))))
			break;
	if (i==0)
		sprintf(buf, "%lu B", b);
	else
		sprintf(buf, "%.2f %cB", (double)b/(1ULL<<(10*i)), p[i-1]);
	return buf;
}

static char 
*wg_ago(uint64_t s) 
{
	struct timespec now;
	static char buf[128];
	size_t offset = 0;
	uint64_t t;

#define _S(_t) (_t<=1?"":"s")
	timespec_get(&now, TIME_UTC);
	s = now.tv_sec - s;
	s = 122;

	t = s / (365*24*60*60);
	s = s % (365*24*60*60);
	if (t)
		offset += snprintf(buf+offset, 
			sizeof(buf)-offset, "%lu year%s, ", t, _S(t));
	t = s / (24*60*60);
	s = s % (24*60*60);
	if (t)
		offset += snprintf(buf+offset, 
			sizeof(buf)-offset, "%lu day%s, ", t, _S(t));
	t = s / (60*60);
	s = s % (60*60);
	if (t)
		offset += snprintf(buf+offset, 
			sizeof(buf)-offset, "%lu hour%s, ", t, _S(t));
	t = s / (60);
	s = s % (60);
	if (t)
		offset += snprintf(buf+offset, 
			sizeof(buf)-offset, "%lu minute%s, ", t, _S(t));

	offset += snprintf(buf+offset, 
		sizeof(buf)-offset, "%lu second%s", s, _S(s));

	return buf;
#undef _S
}

static int
wg_key_to_b64(const char *key, char *b64) {
	if (b64_ntop(key, WG_KEY_SIZE, b64, WG_KEY_SIZE_BASE64) < 0)
		return EINVAL;
	return 0;
}

static int
wg_b64_to_key(const char *b64, char *key) {
	if (strlen(b64) != WG_KEY_SIZE_BASE64-1)
		return EINVAL;
	if ((b64_pton(b64, key, WG_KEY_SIZE) < 0))
		return EINVAL;
	return 0;
}

static int
wg_print(char *indent) {
	struct wg_peer_io *peer;
	struct wg_aip_io *aip;
	char ibuf[INET6_ADDRSTRLEN+1], hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	char b64[WG_KEY_SIZE_BASE64];
	char *peer_indent = "     ";
	size_t i, j;
	int ret = 0;

	if (!wg_interface)
		goto err;

	if (wg_interface->i_flags & WG_IO_INTERFACE_PUBLIC) {
		if((ret = wg_key_to_b64(wg_interface->i_public, b64)))
			goto err;
		printf("%spublic key: %s\n", indent, b64);
	}

	if (wg_interface->i_flags & WG_IO_INTERFACE_PRIVATE) {
		if((ret = wg_key_to_b64(wg_interface->i_private, b64)))
			goto err;
		printf("%sprivate key: %s\n", indent, b64);
	}

	if (wg_interface->i_flags & WG_IO_INTERFACE_PORT)
		printf("%slistening port: %hu\n", indent, wg_interface->i_port);

	if (wg_interface->i_flags & WG_IO_INTERFACE_REPLACE_PEERS)
		printf("%sremove all peers\n", indent);

	peer = &wg_interface->i_peers[0];
	for (i=0; i<wg_interface->i_peers_count; i++) {

		if (peer->p_flags & WG_IO_PEER_PUBLIC) {
			if((ret = wg_key_to_b64(peer->p_public, b64)))
				goto err;
			printf("%speer %s\n", indent, b64);
		}

		if (peer->p_flags & WG_IO_PEER_ENDPOINT)  {
			if (getnameinfo(&peer->p_endpoint.p_sa,
				peer->p_endpoint.p_sa.sa_len,
				hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
				NI_NUMERICHOST | NI_NUMERICSERV) == 0)
				printf("%s%sendpoint %s:%s\n", indent, peer_indent, hbuf, sbuf);
			else
				printf("%s%sendpoint unable to print\n", indent, peer_indent);
		}

		if (peer->p_flags & WG_IO_PEER_REPLACE_AIPS)
			printf("%s%sreplace allowed ips\n", indent, peer_indent);

		if (peer->p_flags & WG_IO_PEER_PSK) {
			if((ret = wg_key_to_b64(peer->p_psk, b64)))
				goto err;
			printf("%s%spreshared key: %s\n", indent, peer_indent, b64);
		}

		if (peer->p_rxbytes != 0 || peer->p_txbytes != 0) {
			printf("%s%stransfer: ", indent, peer_indent);
			printf("%s received, ", wg_bytes(peer->p_rxbytes));
			printf("%s send\n", wg_bytes(peer->p_txbytes));
		}

		if (peer->p_last_handshake.tv_sec != 0)
			printf("%s%slastest handshake: %s ago\n", indent, peer_indent,
				wg_ago(peer->p_last_handshake.tv_sec));

		if (peer->p_pki > 0)
			printf("%s%spersistent keepalive: every %d seconds\n",
				indent, peer_indent, peer->p_pki);

		aip = &peer->p_aips[0];
		if (peer->p_aips_count > 0)
			printf("%s%sallowed ips: ", indent, peer_indent);
		for (j=0; j<peer->p_aips_count; j++) {
			if (aip->a_af == AF_INET || aip->a_af == AF_INET6) {
				bzero(ibuf, sizeof(ibuf));
				inet_ntop(aip->a_af, &aip->a_addr,
					ibuf, sizeof(ibuf));
				printf("%s/%d ", ibuf, aip->a_cidr);
			}
			aip++;
		}
		if (peer->p_aips_count > 0)
			printf("\n");
		peer = (struct wg_peer_io *)aip;
	}
err:
	return ret;
}

static void
wg_status(int s)
{
	int ret=0;

	strlcpy(wg_data.wgd_name, name, sizeof(wg_data.wgd_name));
	if (ioctl(s, SIOCGWG, (caddr_t)&wg_data) < 0)
		return;
	if (!(wg_interface = wg_data.wgd_interface = malloc(wg_data.wgd_size))) {
		ret = errno;
		goto err;
	}
	if (ioctl(s, SIOCGWG, (caddr_t)&wg_data) < 0)  {
		ret = errno;
		goto err;
	}
	ret = wg_print("\t");
err:
	free(wg_interface);
	WG_ERROR_REPORT(ret, "");
}

static int
wg_alloc(size_t n)
{
	size_t peer_offset=0, aip_offset=0;

	if (wg_interface == NULL) {
		wg_data.wgd_size = sizeof(*wg_interface);
		if ((wg_interface = wg_data.wgd_interface
			= calloc(1, wg_data.wgd_size)) == NULL) // set to zeros!
			return ENOMEM;
	}

	if (!n)
		return 0;

	if (wg_peer != NULL)
		peer_offset = (caddr_t)wg_peer - (caddr_t)wg_interface;
	if (wg_aip != NULL)
		aip_offset = (caddr_t)wg_aip - (caddr_t)wg_interface;

	wg_data.wgd_size += n;
	if ((wg_interface = wg_data.wgd_interface
		= realloc(wg_interface, wg_data.wgd_size)) == NULL)
		return ENOMEM;
	
	if (wg_peer != NULL) 
		wg_peer = (struct wg_peer_io *) ((caddr_t)wg_interface + peer_offset);
	if (wg_aip != NULL)
		wg_aip = (struct wg_aip_io *) ((caddr_t)wg_interface + aip_offset);

	bzero((caddr_t)wg_interface + wg_data.wgd_size - n, n);
	return 0;

}

static
DECL_CMD_FUNC(wg_set_key, val, d)
{
	int ret=0;

	if((ret = wg_alloc(0)))
		goto err;
	wg_interface->i_flags |= WG_IO_INTERFACE_PRIVATE;
	if((ret = wg_b64_to_key(val, wg_interface->i_private)))
		goto err;
err:
	WG_ERROR_REPORT(ret, "");
}

static
DECL_CMD_FUNC(wg_set_port, val, d)
{
	const char *errmsg = NULL;
	int ret = 0;

	if((ret = wg_alloc(0)))
		WG_ERROR_REPORT(ret, "");
	wg_interface->i_flags |= WG_IO_INTERFACE_PORT;
	wg_interface->i_port = strtonum(val, 0, 65535, &errmsg);
	if (errmsg)
		WG_ERROR_REPORT(EINVAL, errmsg);
}

static
DECL_CMD_FUNC(wg_remove_all_peers, val, d)
{
	int ret=0;

	if((ret = wg_alloc(0)))
		goto err;
	wg_interface->i_flags |= WG_IO_INTERFACE_REPLACE_PEERS;
err:
	WG_ERROR_REPORT(ret, "");
}

static
DECL_CMD_FUNC(wg_set_peer, val, d)
{
	int ret=0;

	if((ret = wg_alloc(sizeof(*wg_peer))))
		goto err;
	if (wg_aip) 
		wg_peer = (struct wg_peer_io *)wg_aip;
	else
		wg_peer = &wg_interface->i_peers[0];
	wg_aip = &wg_peer->p_aips[0];
	wg_interface->i_peers_count++;
	wg_peer->p_flags |= WG_IO_PEER_PUBLIC;
	if((ret = wg_b64_to_key(val, wg_peer->p_public)))
		goto err;
err:
	WG_ERROR_REPORT(ret, "");
}

static
DECL_CMD_FUNC(wg_remove_peer, val, d)
{
	wg_set_peer(val, d, s, afp);
	wg_peer->p_flags |= WG_IO_PEER_REMOVE;
}

static
DECL_CMD_FUNC(wg_set_psk, val, d)
{
	int ret = 0;

	if (wg_peer == NULL)
		WG_ERROR_REPORT(EINVAL, "peer not set");
	wg_peer->p_flags |= WG_IO_PEER_PSK;
	ret = wg_b64_to_key(val, wg_peer->p_psk);
	WG_ERROR_REPORT(ret, "peer not set");
}

static
DECL_CMD_FUNC(wg_set_pki, val, d)
{
	const char *errmsg = NULL;

	if (wg_peer == NULL)
		WG_ERROR_REPORT(EINVAL, "peer not set");
	wg_peer->p_pki = strtonum(val, 0, 43200, &errmsg);
	if (errmsg)
		WG_ERROR_REPORT(EINVAL, errmsg);
}

static
DECL_CMD_FUNC(wg_set_endpoint, val, d)
{
	int ret = 0;
	struct addrinfo *ai;
	char *host, *port, *colon;

	if (wg_peer == NULL)
		WG_ERROR_REPORT(EINVAL, "peer not set");

	host = strdup(val);
	colon = rindex(host, ':');
	if (colon == NULL)
		WG_ERROR_REPORT(EINVAL, "bad endpoint format [ip:port]" );
	*colon = '\0';
	port = colon + 1;

	if ((ret = getaddrinfo(host, port, NULL, &ai)) != 0)
		WG_ERROR_REPORT(ret, gai_strerror(ret));

	wg_peer->p_flags |= WG_IO_PEER_ENDPOINT;
	memcpy(&wg_peer->p_endpoint.p_sa, ai->ai_addr, ai->ai_addrlen);
	freeaddrinfo(ai);
}	

static
DECL_CMD_FUNC(wg_set_aip, val, d)
{
	int res, ret=0;

	if (wg_peer == NULL)
		WG_ERROR_REPORT(EINVAL, "peer not set");

	if((ret = wg_alloc(sizeof(*wg_aip))))
		goto err;
	
	if ((res = inet_net_pton(AF_INET, val, &wg_aip->a_addr,
	    sizeof(wg_aip->a_addr.in))) != -1) {
		wg_aip->a_af = AF_INET;
	} else if ((res = inet_net_pton(AF_INET6, val, &wg_aip->a_addr,
	    sizeof(wg_aip->a_addr.in6))) != -1) {
		wg_aip->a_af = AF_INET6;
	} else {
		WG_ERROR_REPORT(EINVAL, "bad address");
	}

	wg_aip->a_cidr = res;
	wg_peer->p_aips_count++;
	wg_aip++;
err:
	WG_ERROR_REPORT(ret, "");
}

static
DECL_CMD_FUNC(wg_remove_aips, val, d)
{
	if (wg_peer == NULL)
		WG_ERROR_REPORT(EINVAL, "peer not set");
	wg_peer->p_flags |= WG_IO_PEER_REPLACE_AIPS;
}

static void
wg_finish(int s, void *arg)
{
	strlcpy(wg_data.wgd_name, name, sizeof(wg_data.wgd_name));
	if (ioctl(s, SIOCSWG, (caddr_t)&wg_data) < 0) {
		free(wg_interface);
		return;
	}
	printf("interface: %s\n", name);
	wg_print("    ");
	free(wg_interface);
}

static struct afswtch af_wg = {
	.af_name	= "af_wg",
	.af_af		= AF_UNSPEC,
	.af_other_status = wg_status,
};
static struct cmd wg_cmds[] = {
	DEF_CMD_ARG("key", wg_set_key),
	DEF_CMD_ARG("public-key", wg_set_key),
	DEF_CMD_ARG("port", wg_set_port),
	DEF_CMD("-peers", 0, wg_remove_all_peers),

	DEF_CMD_ARG("peer", wg_set_peer),
	DEF_CMD_ARG("-peer", wg_remove_peer),

	DEF_CMD_ARG("psk", wg_set_psk),
	DEF_CMD_ARG("preshared-key", wg_set_psk),

	DEF_CMD_ARG("keep", wg_set_pki),
	DEF_CMD_ARG("keepalive", wg_set_pki),

	DEF_CMD_ARG("aip", wg_set_aip),
	DEF_CMD_ARG("allowed-ip", wg_set_aip),
	DEF_CMD("-aips", 0, wg_remove_aips),
	DEF_CMD("-allowed-ips", 0, wg_remove_aips),

	DEF_CMD_ARG("ep", wg_set_endpoint),
	DEF_CMD_ARG("endpoint", wg_set_endpoint),

};

static __constructor(101) void
wg_ctor(void) 
{
	size_t i;

	for (i=0; i<nitems(wg_cmds); i++)
		cmd_register(&wg_cmds[i]);
	af_register(&af_wg);
	callback_register(wg_finish, NULL);

}

