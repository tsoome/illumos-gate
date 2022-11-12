/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#include <sys/salib.h>
#include <sys/errno.h>
#include <rpc/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "socket_inet.h"
#include "ipv4.h"
#include "clnt.h"
#include <rpc/rpc.h>
#include "brpc.h"
#include "pmap.h"
#include <sys/promif.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_sys.h>
#include "auth_inet.h"
#include <rpc/rpc_msg.h>
#include <sys/bootdebug.h>

struct rpc_createerr rpc_createerr;
