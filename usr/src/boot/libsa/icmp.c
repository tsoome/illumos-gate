/*
 * Copyright 2026 Edgecast Cloud LLC.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stand.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <net.h>

ssize_t process_icmp(struct iodesc *d, struct io_buffer *iob,
    void **payload, ssize_t n)
{
	struct ip *ip = *payload;
	struct icmp *icmp;
	struct ether_header *eh;
	uint8_t ea[ETHER_ADDR_LEN];

	eh = iob->io_data;
	bcopy(eh->ether_shost, ea, ETHER_ADDR_LEN);
	ip = iob_put(iob, ip->ip_hl << 2);
	icmp = iob->io_tail;

	switch (icmp->icmp_type) {
	case ICMP_ECHO:
		printf("ICMP_ECHO\n");
		icmp->icmp_type = ICMP_ECHOREPLY;
		icmp->icmp_cksum = 0;
		icmp->icmp_cksum = in_cksum(icmp,
		    ntohs(ip->ip_len) - (ip->ip_hl << 2));
		ip->ip_dst.s_addr = ip->ip_src.s_addr;
		ip->ip_src.s_addr = d->myip.s_addr;
		ip->ip_off = 0;
		ip->ip_sum = 0;
		ip->ip_sum = in_cksum(ip, ip->ip_hl << 2);
		sendether(d, ip, ntohs(ip->ip_len), ea, ETHERTYPE_IP);
		break;
	case ICMP_ECHOREPLY:
		printf("ICMP_ECHOREPLY\n");
		break;
	case ICMP_UNREACH:
		printf("ICMP_UNREACH: code %d\n", icmp->icmp_code);
		break;
	default:
		printf("%s: icmp_type: %d\n", __func__, icmp->icmp_type);
	}
	free_iob(iob);
	return (-1);
}
