/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2014 Pluribus Networks Inc.
 */

#ifndef _INOUT_H_
#define	_INOUT_H_

#include <sys/linker_set.h>

struct vcpu;
struct vmctx;
struct vm_exit;
#ifndef __FreeBSD__
struct vm_inout;
#endif

/*
 * inout emulation handlers return 0 on success and -1 on failure.
 */
typedef int (*inout_func_t)(struct vmctx *ctx, int in, int port,
			    int bytes, uint32_t *eax, void *arg);

struct inout_port {
	const char	*name;
	int		port;
	int		size;
	int		flags;
	inout_func_t	handler;
	void		*arg;
};
#define	IOPORT_F_IN		0x1
#define	IOPORT_F_OUT		0x2
#define	IOPORT_F_INOUT		(IOPORT_F_IN | IOPORT_F_OUT)

/*
 * The following flags are used internally and must not be used by
 * device models.
 */
#define	IOPORT_F_DEFAULT	0x80000000	/* claimed by default handler */

#define	INOUT_PORT(name, port, flags, handler)				\
	static struct inout_port __CONCAT(__inout_port, __LINE__) = {	\
		#name,							\
		(port),							\
		1,							\
		(flags),						\
		(handler),						\
		0							\
	};								\
	DATA_SET(inout_port_set, __CONCAT(__inout_port, __LINE__))

void	init_inout(void);
#ifdef __FreeBSD__
int	emulate_inout(struct vmctx *, struct vcpu *vcpu, struct vm_exit *vmexit);
#else
int	emulate_inout(struct vmctx *, struct vcpu *vcpu, struct vm_inout *inout);
#endif
int	register_inout(struct inout_port *iop);
int	unregister_inout(struct inout_port *iop);

#endif	/* _INOUT_H_ */
