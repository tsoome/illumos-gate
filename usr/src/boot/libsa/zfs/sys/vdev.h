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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, 2020 by Delphix. All rights reserved.
 * Copyright (c) 2017, Intel Corporation.
 * Copyright (c) 2019, Datto Inc. All rights reserved.
 */

#ifndef _SYS_VDEV_H
#define	_SYS_VDEV_H

#if 0
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dmu.h>
#include <sys/space_map.h>
#endif
#include <fs/zfs.h>

#ifdef  __cplusplus
extern "C" {
#endif

extern int vdev_open(vdev_t *);
extern void vdev_open_children(vdev_t *);
extern void vdev_close(vdev_t *);

extern void vdev_set_state(vdev_t *vd, boolean_t isopen, vdev_state_t state,
    vdev_aux_t aux);

extern uint64_t vdev_psize_to_asize(vdev_t *vd, uint64_t psize);

extern boolean_t vdev_is_dead(vdev_t *vd);
extern boolean_t vdev_readable(vdev_t *vd);
extern boolean_t vdev_writeable(vdev_t *vd);

#ifdef  __cplusplus
}
#endif

#endif	/* _SYS_VDEV_H */
