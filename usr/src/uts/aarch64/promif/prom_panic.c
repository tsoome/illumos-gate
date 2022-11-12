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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/frame.h>
#include <sys/controlregs.h>

void
prom_panic(char *s)
{
	const char fmt[] = "%s: prom_panic: %s\n";

	if (s == NULL)
		s = "unknown panic";

	prom_printf(fmt, "kernel", s);

	prom_printf("Call Stack\n");
	struct frame *fp = (struct frame *)__builtin_frame_address(0);

	for (;;) {
		write_s1e1r((uint64_t)fp);
		isb();
		uint64_t par = read_par_el1();
		if (par & 1)
			break;
		prom_printf("    0x%lx\n", (uintptr_t)fp->fr_savpc);
		fp = (struct frame *)fp->fr_savfp;
	}

	prom_reboot_prompt();
	prom_reboot(NULL);
}
