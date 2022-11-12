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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2022 Michael van der Westhuizen
 */

#ifndef _ASM_BYTEORDER_H
#define	_ASM_BYTEORDER_H

#include <sys/ccompile.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(__lint) && defined(__GNUC__)

/*
 * htonll(), ntohll(), htonl(), ntohl(), htons(), ntohs()
 * These functions reverse the byte order of the input parameter and returns
 * the result.  This is to convert the byte order from host byte order
 * (little endian) to network byte order (big endian), or vice versa.
 */


#if defined(__aarch64__)

extern __GNU_INLINE uint16_t
htons(uint16_t value)
{
	return (__builtin_bswap16(value));
}

extern __GNU_INLINE uint16_t
ntohs(uint16_t value)
{
	return (__builtin_bswap16(value));
}

extern __GNU_INLINE uint32_t
htonl(uint32_t value)
{
	return (__builtin_bswap32(value));
}

extern __GNU_INLINE uint32_t
ntohl(uint32_t value)
{
	return (__builtin_bswap32(value));
}

extern __GNU_INLINE uint64_t
htonll(uint64_t value)
{
	return (__builtin_bswap64(value));
}

extern __GNU_INLINE uint64_t
ntohll(uint64_t value)
{
	return (__builtin_bswap64(value));
}

#endif	/* __aarch64__ */

#endif	/* !__lint && __GNUC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _ASM_BYTEORDER_H */
