/*
 * Copyright (c) 1992 Regents of the University of California.
 * All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * The send and receive functions were originally implemented in udp.c and
 * moved here. Also it is likely some more cleanup can be done, especially
 * once we will implement the support for tcp.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <string.h>
#include <stdbool.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>

#include <netinet/ip.h>
#include <netinet/ip_var.h>

#include "stand.h"
#include "net.h"

/*
 * Fragment re-assembly queue.
 */
struct ip_reasm {
	struct in_addr	ip_src;
	struct in_addr	ip_dst;
	uint16_t	ip_id;
	uint8_t		ip_proto;
	uint8_t		ip_ttl;
	size_t		ip_total_size;
	ip_queue_t	ip_queue;
	void		*ip_pkt;
	struct ip	*ip_hdr;
	STAILQ_ENTRY(ip_reasm) ip_next;
};

STAILQ_HEAD(ire_list, ip_reasm) ire_list = STAILQ_HEAD_INITIALIZER(ire_list);

/* Caller must leave room for ethernet and ip headers in front!! */
ssize_t
sendip(struct iodesc *d, void *pkt, size_t len, uint8_t proto)
{
	ssize_t cc;
	struct ip *ip;
	uchar_t *ea;

#ifdef NET_DEBUG
	if (debug) {
		printf("sendip: proto: %x d=%p called.\n", proto, (void *)d);
		printf("saddr: %s:%d ", inet_ntoa(d->myip), ntohs(d->myport));
		printf("daddr: %s:%d\n", inet_ntoa(d->destip), ntohs(d->destport));
	}
#endif

	ip = (struct ip *)pkt - 1;
	len += sizeof (*ip);

	bzero(ip, sizeof (*ip));

	ip->ip_v = IPVERSION;			/* half-char */
	ip->ip_hl = sizeof (*ip) >> 2;		/* half-char */
	ip->ip_len = htons(len);
	ip->ip_p = proto;			/* char */
	ip->ip_ttl = IPDEFTTL;			/* char */
	ip->ip_src = d->myip;
	ip->ip_dst = d->destip;
	ip->ip_sum = in_cksum(ip, sizeof (*ip)); /* short, but special */

	if (ip->ip_dst.s_addr == INADDR_BROADCAST || ip->ip_src.s_addr == 0 ||
	    netmask == 0 || SAMENET(ip->ip_src, ip->ip_dst, netmask))
		ea = arpwhohas(d, ip->ip_dst);
	else
		ea = arpwhohas(d, gateip);

	cc = sendether(d, ip, len, ea, ETHERTYPE_IP);
	if (cc == -1)
		return (-1);
	if (cc != len)
		panic("sendip: bad write (%zd != %zd)", cc, len);
	return (cc - sizeof (*ip));
}

static void
ip_reasm_free(struct ip_reasm *ipr)
{
	struct io_buffer *iob;

	while ((iob = STAILQ_FIRST(&ipr->ip_queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&ipr->ip_queue, io_next);
		/* let iob know its not in any queue */
		iob->io_queue = NULL;
		free_iob(iob);
	}
	free(ipr->ip_pkt);
	free(ipr);
}

static bool
ip_reasm_add(struct ip_reasm *ipr, struct io_buffer *iob, struct ip *ip)
{
	struct io_buffer *ipq;
	uint16_t off_q, off_ip;

	STAILQ_FOREACH(ipq, &ipr->ip_queue, io_next) {
		struct ip *hdr = ipq->io_tail;
		off_q = ntohs(hdr->ip_off) & IP_OFFMASK;
		off_ip = ntohs(ip->ip_off) & IP_OFFMASK;

		if (off_q == off_ip) {	/* duplicate */
			free_iob(iob);
			return (true);
		}

		if (off_ip < off_q) {
			/*
			 * Everything in queue has larger offset,
			 * drop out of loop and insert to HEAD.
			 */
			break;
		}

		/*
		 * p in queue is smaller than ip, check if we need to put
		 * ip after ipq or after ipq->next.
		 */
		struct io_buffer *next = STAILQ_NEXT(ipq, io_next);
		if (next == NULL) {
			/* insert after ipq */
			iob->io_queue = &ipr->ip_queue;
			STAILQ_INSERT_AFTER(&ipr->ip_queue, ipq, iob, io_next);
			return (true);
		}

		hdr = next->io_tail;
		off_q = ntohs(hdr->ip_off) & IP_OFFMASK;
		if (off_ip < off_q) {
			/* next fragment offset is larger, insert after ipq. */
			iob->io_queue = &ipr->ip_queue;
			STAILQ_INSERT_AFTER(&ipr->ip_queue, ipq, iob, io_next);
			return (true);
		}
		/* next fragment offset is smaller, loop */
	}
	iob->io_queue = &ipr->ip_queue;
	STAILQ_INSERT_HEAD(&ipr->ip_queue, iob, io_next);
	return (true);
}

/*
 * Check if our reassembly queue is complete.
 */
static int
ip_reasm_check(struct ip_reasm *ipr, size_t *sizep)
{
	struct ip *hdr;
	struct io_buffer *ipq;
	size_t n;
	uint16_t fragoffset;

	hdr = NULL;
	n = 0;

	STAILQ_FOREACH(ipq, &ipr->ip_queue, io_next) {
		hdr = ipq->io_tail;

		fragoffset = (ntohs(hdr->ip_off) & IP_OFFMASK) * 8;
		if (fragoffset != n) {
#ifdef NET_DEBUG
			if (debug) {
				printf("%s: need more fragments %d %s -> ",
				    __func__, ntohs(hdr->ip_id),
				    inet_ntoa(hdr->ip_src));
				printf("%s offset=%d MF=%d\n",
				    inet_ntoa(hdr->ip_dst),
				    fragoffset,
				    (ntohs(hdr->ip_off) & IP_MF) != 0);
			}
#endif
			errno = EAGAIN;
			return (-1);
		}

		n += ntohs(hdr->ip_len) - (hdr->ip_hl << 2);
	}

	if (hdr == NULL ||
	    (ntohs(hdr->ip_off) & IP_MF) != 0) {
		/* We should not really get here. */
		errno = EAGAIN;
		return (-1);
	}
	*sizep = n;
	return (0);
}

static struct io_buffer *
ip_reasm_complete(ip_queue_t *ipq, size_t len)
{
	struct io_buffer *iob, *pkt;
	struct ip *hdr;
	size_t n, size, hlen;
	void *ptr;

	pkt = STAILQ_FIRST(ipq);

	/*
	 * we take head space from first buffer from queue to
	 * get reserved space + data before ip packet referenced
	 * by io_tail member.
	 */
	hdr = pkt->io_tail;
	hlen = hdr->ip_hl << 2;

	size = len + hlen + (pkt->io_tail - pkt->io_head);
	iob = alloc_iob(size);
	/*
	 * copy buffer from our first packet, from beginning to
	 * ip header included.
	 */
	bcopy(pkt->io_head, iob->io_head, pkt->io_tail - pkt->io_head + hlen);
	iob_reserve(iob, pkt->io_data - pkt->io_head);
	/*
	 * Now iob->io_data points to our ethernet header.
	 */
	/* Move to IP header */
	iob_put(iob, ETHER_HDR_LEN);
	hdr = iob->io_tail;
	hdr->ip_len = htons(len + (hdr->ip_hl << 2));
	hdr->ip_off = 0;
	hdr->ip_sum = 0;
	hdr->ip_sum = in_cksum(hdr, hdr->ip_hl << 2);

	ptr = iob->io_tail;
	n = hlen;

	while ((pkt = STAILQ_FIRST(ipq)) != NULL) {
		STAILQ_REMOVE_HEAD(ipq, io_next);
		hdr = pkt->io_tail;

		/* move to ip data */
		hlen = hdr->ip_hl << 2;
		iob_put(pkt, hlen);
		size = ntohs(hdr->ip_len) - hlen;
		bcopy(pkt->io_tail, ptr + n, size);
		n += size;

		pkt->io_queue = NULL;
		free_iob(pkt);
	}

	return (iob);
}

/*
 * Check and process what we got.
 */
static ssize_t
process_dgram(struct iodesc *d, uint8_t proto, struct io_buffer *iob,
    void **payload, ssize_t n)
{
	struct ip *ip = *payload;

	switch (ip->ip_p) {
	case IPPROTO_UDP:
		return (process_udp(d, iob, payload, n));

	case IPPROTO_TCP:
		printf("%s: IPPROTO_TCP\n", __func__);
		break;

	case IPPROTO_ICMP:
		return (process_icmp(d, iob, payload, n));
		break;
	}

	free_iob(iob);
	errno = EAGAIN; /* Call me again. */
	return (-1);
}

/*
 * Receive a IP packet and validate it is for us.
 */
static ssize_t
readipv4(struct iodesc *d, struct io_buffer **iobp, void **payload,
    ssize_t n, uint8_t proto)
{
	struct ip *ip = *payload;
	size_t hlen, len;
	struct ip_reasm *ipr;
	struct io_buffer *iob = *iobp;
	bool morefrag, isfrag;
	uint16_t fragoffset;

	if (n < sizeof (*ip)) {
		free_iob(iob);
		errno = EAGAIN;	/* Call me again. */
		return (-1);
	}

	hlen = ip->ip_hl << 2;
	if (hlen < sizeof (*ip) ||
	    in_cksum(ip, hlen) != 0) {
#ifdef NET_DEBUG
		if (debug)
			printf("%s: short hdr or bad cksum.\n", __func__);
#endif
		free_iob(iob);
		errno = EAGAIN;	/* Call me again. */
		return (-1);
	}

	if (n < ntohs(ip->ip_len)) {
#ifdef NET_DEBUG
		if (debug) {
			printf("%s: bad length %zd < %d.\n",
			    __func__, n, ntohs(ip->ip_len));
		}
#endif
		free_iob(iob);
		errno = EAGAIN;	/* Call me again. */
		return (-1);
	}

	fragoffset = (ntohs(ip->ip_off) & IP_OFFMASK) * 8;
	morefrag = (ntohs(ip->ip_off) & IP_MF) == 0 ? false : true;
	isfrag = morefrag || fragoffset != 0;

	/* Unfragmented packet. */
	if (!isfrag) {
#ifdef NET_DEBUG
		if (debug) {
			printf("%s: unfragmented saddr %s -> ",
			    __func__, inet_ntoa(ip->ip_src));
			printf("%s\n", inet_ntoa(ip->ip_dst));
		}
#endif
		return (process_dgram(d, proto, iob, payload, n));
	}

	STAILQ_FOREACH(ipr, &ire_list, ip_next) {
		if (ipr->ip_src.s_addr == ip->ip_src.s_addr &&
		    ipr->ip_dst.s_addr == ip->ip_dst.s_addr &&
		    ipr->ip_id == ip->ip_id &&
		    ipr->ip_proto == ip->ip_p)
			break;
	}

	/* Allocate new reassembly entry */
	if (ipr == NULL) {
		if ((ipr = calloc(1, sizeof (*ipr))) == NULL) {
			free_iob(iob);
			return (-1);
		}

		ipr->ip_src = ip->ip_src;
		ipr->ip_dst = ip->ip_dst;
		ipr->ip_id = ip->ip_id;
		ipr->ip_proto = ip->ip_p;
		ipr->ip_ttl = MAXTTL;
		STAILQ_INIT(&ipr->ip_queue);
		STAILQ_INSERT_TAIL(&ire_list, ipr, ip_next);
#ifdef NET_DEBUG
		if (debug) {
			printf("%s: new reassembly ID=%d %s -> ",
			    __func__, ntohs(ip->ip_id), inet_ntoa(ip->ip_src));
			printf("%s\n", inet_ntoa(ip->ip_dst));
		}
#endif
	}

	/*
	 * NOTE: with ip_reasm_add() ptr will be stored in reassembly
	 * queue and we can not free it without destroying the queue.
	 */
	if (!ip_reasm_add(ipr, iob, ip)) {
		/* Error. Clean it up and start again. */
		STAILQ_REMOVE(&ire_list, ipr, ip_reasm, ip_next);
		free(ipr);
		free_iob(iob);
		return (-1);
	}

	/*
	 * Walk the packet list in reassembly queue, if we got all the
	 * fragments, build the packet.
	 */
	int rv = ip_reasm_check(ipr, &len);
	if (rv != 0) {
		/* Nope, still missing some. */
		return (rv);
	}

	/*
	 * Allocate iob and copy over all fragments.
	 */
	iob = ip_reasm_complete(&ipr->ip_queue, len);
	STAILQ_REMOVE(&ire_list, ipr, ip_reasm, ip_next);
	ip_reasm_free(ipr);
	if (iob == NULL) {
		return (-1);
	}

	*iobp = iob;
	*payload = iob->io_tail;

#ifdef NET_DEBUG
	if (debug) {
		printf("%s: completed fragments ID=%d %s -> ",
		    __func__, ntohs(ip->ip_id), inet_ntoa(ip->ip_src));
		printf("%s\n", inet_ntoa(ip->ip_dst));
	}
#endif
	return (process_dgram(d, proto, iob, payload, n));
}

/*
 * Receive a IP packet.
 */
ssize_t
readip(struct iodesc *d, struct io_buffer **pkt, void **payload, time_t tleft,
    uint8_t proto)
{
	time_t t;
	ssize_t ret = -1;

	t = getsecs();
	while ((getsecs() - t) < tleft) {
		ssize_t n;
		uint16_t etype;	/* host order */
		struct io_buffer *iob = NULL;
		void *data = NULL;

		errno = 0;
		n = readether(d, &iob, &data, tleft, &etype);
		if (n == -1) {
			free_iob(iob);
			continue;
		}
		/* Ethernet address checks are done in readether() */
		if (etype == ETHERTYPE_IP) {
			struct ip *ip = data;

			if (ip->ip_v == IPVERSION) {	/* half char */
				errno = 0;

				ret = readipv4(d, &iob, &data, n, proto);
				if (ret >= 0) {
					*pkt = iob;
					*payload = data;
					return (ret);
				}

				/*
				 * Bubble up the error if it wasn't successful
				 */
				if (errno != EAGAIN)
					return (-1);
				continue;
			}
#ifdef NET_DEBUG
			if (debug) {
				printf("%s: IP version or proto. "
				    "ip_v=%d ip_p=%d\n",
				    __func__, ip->ip_v, ip->ip_p);
			}
#endif
			free_iob(iob);
			continue;
		}
		free_iob(iob);
	}
	/* We've exhausted tleft; timeout */
	errno = ETIMEDOUT;
#ifdef NET_DEBUG
	if (debug) {
		printf("%s: timeout\n", __func__);
	}
#endif
	return (-1);
}
