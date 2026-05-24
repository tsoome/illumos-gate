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
 */
/*
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2016 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2011, 2017 by Delphix. All rights reserved.
 * Copyright (c) 2018 DilOS
 */

#include <sys/zfs_context.h>
#include <sys/dmu.h>

const dmu_object_type_info_t dmu_ot[DMU_OT_NUMTYPES] = {
	{ DMU_BSWAP_UINT8,  true,  false, false, "unallocated"		},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "object directory"	},
	{ DMU_BSWAP_UINT64, true,  true,  false, "object array"		},
	{ DMU_BSWAP_UINT8,  true,  false, false, "packed nvlist"	},
	{ DMU_BSWAP_UINT64, true,  false, false, "packed nvlist size"	},
	{ DMU_BSWAP_UINT64, true,  false, false, "bpobj"		},
	{ DMU_BSWAP_UINT64, true,  false, false, "bpobj header"		},
	{ DMU_BSWAP_UINT64, true,  false, false, "SPA space map header"	},
	{ DMU_BSWAP_UINT64, true,  false, false, "SPA space map"	},
	{ DMU_BSWAP_UINT64, true,  false, true,  "ZIL intent log"	},
	{ DMU_BSWAP_DNODE,  true,  false, true,  "DMU dnode"		},
	{ DMU_BSWAP_OBJSET, true,  true,  false, "DMU objset"		},
	{ DMU_BSWAP_UINT64, true,  true,  false, "DSL directory"	},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "DSL directory child map" },
	{ DMU_BSWAP_ZAP,    true,  true,  false, "DSL dataset snap map"	},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "DSL props"		},
	{ DMU_BSWAP_UINT64, true,  true,  false, "DSL dataset"		},
	{ DMU_BSWAP_ZNODE,  true,  false, false, "ZFS znode"		},
	{ DMU_BSWAP_OLDACL, true,  false, true,  "ZFS V0 ACL"		},
	{ DMU_BSWAP_UINT8,  false, false, true,  "ZFS plain file"	},
	{ DMU_BSWAP_ZAP,    true,  false, true,  "ZFS directory"	},
	{ DMU_BSWAP_ZAP,    true,  false, false, "ZFS master node"	},
	{ DMU_BSWAP_ZAP,    true,  false, true,  "ZFS delete queue"	},
	{ DMU_BSWAP_UINT8,  false, false, true,  "zvol object"		},
	{ DMU_BSWAP_ZAP,    true,  false, false, "zvol prop"		},
	{ DMU_BSWAP_UINT8,  false, false, true,  "other uint8[]"	},
	{ DMU_BSWAP_UINT64, false, false, true,  "other uint64[]"	},
	{ DMU_BSWAP_ZAP,    true,  false, false, "other ZAP"		},
	{ DMU_BSWAP_ZAP,    true,  false, false, "persistent error log"	},
	{ DMU_BSWAP_UINT8,  true,  false, false, "SPA history"		},
	{ DMU_BSWAP_UINT64, true,  false, false, "SPA history offsets"	},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "Pool properties"	},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "DSL permissions"	},
	{ DMU_BSWAP_ACL,    true,  false, true,  "ZFS ACL"		},
	{ DMU_BSWAP_UINT8,  true,  false, true,  "ZFS SYSACL"		},
	{ DMU_BSWAP_UINT8,  true,  false, true,  "FUID table"		},
	{ DMU_BSWAP_UINT64, true,  false, false, "FUID table size"	},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "DSL dataset next clones" },
	{ DMU_BSWAP_ZAP,    true,  false, false, "scan work queue"	},
	{ DMU_BSWAP_ZAP,    true,  false, true,  "ZFS user/group/project used"},
	{ DMU_BSWAP_ZAP,    true,  false, true,  "ZFS user/group/proj quota"},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "snapshot refcount tags" },
	{ DMU_BSWAP_ZAP,    true,  false, false, "DDT ZAP algorithm"	},
	{ DMU_BSWAP_ZAP,    true,  false, false, "DDT statistics"	},
	{ DMU_BSWAP_UINT8,  true,  false, true,  "System attributes"	},
	{ DMU_BSWAP_ZAP,    true,  false, true,  "SA master node"	},
	{ DMU_BSWAP_ZAP,    true,  false, true,  "SA attr registration"	},
	{ DMU_BSWAP_ZAP,    true,  false, true,  "SA attr layouts"	},
	{ DMU_BSWAP_ZAP,    true,  false, false, "scan translations"	},
	{ DMU_BSWAP_UINT8,  false, false, true,  "deduplicated block"	},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "DSL deadlist map"	},
	{ DMU_BSWAP_UINT64, true,  true,  false, "DSL deadlist map hdr"	},
	{ DMU_BSWAP_ZAP,    true,  true,  false, "DSL dir clones"	},
	{ DMU_BSWAP_UINT64, true,  false, false, "bpobj subobj"		}
};
