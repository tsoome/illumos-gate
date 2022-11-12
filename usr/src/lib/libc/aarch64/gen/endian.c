/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2015, Joyent, Inc.
 * Copyright 2017 Hayashi Naoyuki
 */

/*
 * General, no-op functions for endian(3C). The rest are in byteorder.s.
 */

#include <endian.h>

uint16_t
htole16(uint16_t in)
{
	return (in);
}

uint32_t
htole32(uint32_t in)
{
	return (in);
}

uint64_t
htole64(uint64_t in)
{
	return (in);
}

uint16_t
letoh16(uint16_t in)
{
	return (in);
}

uint16_t
le16toh(uint16_t in)
{
	return (in);
}

uint32_t
letoh32(uint32_t in)
{
	return (in);
}

uint32_t
le32toh(uint32_t in)
{
	return (in);
}

uint64_t
letoh64(uint64_t in)
{
	return (in);
}

uint64_t
le64toh(uint64_t in)
{
	return (in);
}

uint16_t
htobe16(uint16_t in)
{
	return __builtin_bswap16(in);
}

uint32_t
htobe32(uint32_t in)
{
	return __builtin_bswap32(in);
}

uint64_t
htobe64(uint64_t in)
{
	return __builtin_bswap64(in);
}

uint16_t
betoh16(uint16_t in)
{
	return __builtin_bswap16(in);
}

uint16_t
be16toh(uint16_t in)
{
	return __builtin_bswap16(in);
}

uint32_t
betoh32(uint32_t in)
{
	return __builtin_bswap32(in);
}

uint32_t
be32toh(uint32_t in)
{
	return __builtin_bswap32(in);
}

uint64_t
betoh64(uint64_t in)
{
	return __builtin_bswap64(in);
}

uint64_t
be64toh(uint64_t in)
{
	return __builtin_bswap64(in);
}
