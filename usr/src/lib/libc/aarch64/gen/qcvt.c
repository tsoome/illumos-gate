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

#include <sys/types.h>
#include <stdlib.h>
#include <floatingpoint.h>
#include "tsd.h"

char *
qecvt(number, ndigits, decpt, sign)
	long double	number;
	int		ndigits;
	int		*decpt;
	int		*sign;
{
	char *buf = tsdalloc(_T_ECVT, DECIMAL_STRING_LENGTH, NULL);

	return (qeconvert(&number, ndigits, decpt, sign, buf));
}

char *
qfcvt(number, ndigits, decpt, sign)
	long double	number;
	int		ndigits;
	int		*decpt;
	int		*sign;
{
	char *buf = tsdalloc(_T_ECVT, DECIMAL_STRING_LENGTH, NULL);

	return (qfconvert(&number, ndigits, decpt, sign, buf));
}

char *
qgcvt(number, ndigits, buffer)
	long double	number;
	int		ndigits;
	char		*buffer;
{
	return (qgconvert(&number, ndigits, 0, buffer));
}
