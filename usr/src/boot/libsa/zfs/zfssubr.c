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

#include <sys/cdefs.h>
#include <sys/abd.h>
#include <stdbool.h>
#include <lz4.h>

static uint64_t zfs_crc64_table[256];

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

int
ilog2(int n)
{
	int v;

	for (v = 0; v < 64; v++)
		if (n == (1 << v))
			return (v);
	return (-1);
}

static void
zfs_init_crc(void)
{
	int i, j;
	uint64_t *ct;

	/*
	 * Calculate the crc64 table (used for the zap hash
	 * function).
	 */
	if (zfs_crc64_table[128] != ZFS_CRC64_POLY) {
		memset(zfs_crc64_table, 0, sizeof (zfs_crc64_table));
		for (i = 0; i < 256; i++) {
			ct = zfs_crc64_table + i;
			for (*ct = i, j = 8; j > 0; j--)
				*ct = (*ct >> 1) ^
				    (-(*ct & 1) & ZFS_CRC64_POLY);
		}
	}
}

void
byteswap_uint64_array(void *vbuf, size_t size)
{
	uint64_t *buf = vbuf;
	size_t count = size >> 3;
	int i;

	ASSERT((size & 7) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_64(buf[i]);
}

static uint64_t
zap_hash(uint64_t salt, const char *name)
{
	const uint8_t *cp;
	uint8_t c;
	uint64_t crc = salt;

	ASSERT(crc != 0);
	ASSERT(zfs_crc64_table[128] == ZFS_CRC64_POLY);
	for (cp = (const uint8_t *)name; (c = *cp) != '\0'; cp++)
		crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ c) & 0xFF];

	/*
	 * Only use 28 bits, since we need 4 bits in the cookie for the
	 * collision differentiator.  We MUST use the high bits, since
	 * those are the onces that we first pay attention to when
	 * chosing the bucket.
	 */
	crc &= ~((1ULL << (64 - ZAP_HASHBITS)) - 1);

	return (crc);
}
