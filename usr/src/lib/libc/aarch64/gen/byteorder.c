/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/isa_defs.h>
#include <sys/types.h>


uint64_t
htonll(uint64_t in)
{
	return __builtin_bswap64(in);
}

uint64_t
ntohll(uint64_t in)
{
	return __builtin_bswap64(in);
}

uint32_t
htonl(uint32_t in)
{
	return __builtin_bswap32(in);
}

uint32_t
ntohl(uint32_t in)
{
	return __builtin_bswap32(in);
}

uint16_t
htons(uint16_t in)
{
	return (in >> 8) | ((in & 0xff)<< 8);
}

uint16_t
ntohs(uint16_t in)
{
	return (in >> 8) | ((in & 0xff)<< 8);
}
