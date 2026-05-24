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
 * Copyright (c) 2011, 2018 by Delphix. All rights reserved.
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright (c) 2014 Integros [integros.com]
 * Copyright (c) 2017, Intel Corporation.
 */

#ifndef _ZFEATURE_COMMON_H
#define	_ZFEATURE_COMMON_H

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum spa_feature {
	SPA_FEATURE_NONE = -1,
	SPA_FEATURE_ASYNC_DESTROY,
	SPA_FEATURE_EMPTY_BPOBJ,
	SPA_FEATURE_LZ4_COMPRESS,
	SPA_FEATURE_MULTI_VDEV_CRASH_DUMP,
	SPA_FEATURE_SPACEMAP_HISTOGRAM,
	SPA_FEATURE_ENABLED_TXG,
	SPA_FEATURE_HOLE_BIRTH,
	SPA_FEATURE_EXTENSIBLE_DATASET,
	SPA_FEATURE_EMBEDDED_DATA,
	SPA_FEATURE_BOOKMARKS,
	SPA_FEATURE_FS_SS_LIMIT,
	SPA_FEATURE_LARGE_BLOCKS,
	SPA_FEATURE_LARGE_DNODE,
	SPA_FEATURE_SHA512,
	SPA_FEATURE_SKEIN,
	SPA_FEATURE_EDONR,
	SPA_FEATURE_DEVICE_REMOVAL,
	SPA_FEATURE_OBSOLETE_COUNTS,
	SPA_FEATURE_POOL_CHECKPOINT,
	SPA_FEATURE_SPACEMAP_V2,
	SPA_FEATURE_ALLOCATION_CLASSES,
	SPA_FEATURE_RESILVER_DEFER,
	SPA_FEATURE_ENCRYPTION,
	SPA_FEATURE_BOOKMARK_V2,
	SPA_FEATURE_USEROBJ_ACCOUNTING,
	SPA_FEATURE_PROJECT_QUOTA,
	SPA_FEATURE_LOG_SPACEMAP,
	SPA_FEATURES
} spa_feature_t;

#ifdef  __cplusplus
}
#endif

#endif	/* _ZFEATURE_COMMON_H */
