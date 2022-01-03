/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014 Roger Pau Monné <roger.pau@citrix.com>
 * All rights reserved.
 * Copyright (c) 2018 Netflix, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_BOOT_H_
#define _SYS_BOOT_H_

/*
 * Return a 'boothowto' value corresponding to the kernel arguments in
 * (kargs) and any relevant environment variables.
 * XXX Remove with 14807 implementation.
 */
static struct
{
	const char	*ev;
	int		mask;
} howto_names[] = {
	{ "boot_askname",	RB_ASKNAME},
	{ "boot_cdrom",		RB_CDROM},
	{ "boot_ddb",		RB_KDB},
	{ "boot_dfltroot",	RB_DFLTROOT},
	{ "boot_gdb",		RB_GDB},
	{ "boot_multicons",	RB_MULTIPLE},
	{ "boot_mute",		RB_MUTE},
	{ "boot_pause",		RB_PAUSE},
	{ "boot_serial",	RB_SERIAL},
	{ "boot_single",	RB_SINGLE},
	{ "boot_verbose",	RB_VERBOSE},
	{ NULL, 0}
};

#define PATH_KERNEL	"/boot/kernel/kernel"

int boot_env_to_howto(void);
void boot_howto_to_env(int howto);
int boot_parse_arg(const char *v);
int boot_parse_cmdline_delim(char *cmdline, const char *delim);
int boot_parse_cmdline(char *cmdline);
int boot_parse_args(int argc, char *argv[]);

#endif /* !_SYS_BOOT_H_ */
