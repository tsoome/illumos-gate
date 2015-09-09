#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_gdb.h>
#include <mdb/mdb.h>

static const struct mdb_gdb_reginfo armv6_reginfo[] = {
	{ "r0",      4,   0, 1, },
	{ "r1",      4,   4, 1, },
	{ "r2",      4,   8, 1, },
	{ "r3",      4,  12, 1, },
	{ "r4",      4,  16, 1, },
	{ "r5",      4,  20, 1, },
	{ "r6",      4,  24, 1, },
	{ "r7",      4,  28, 1, },
	{ "r8",      4,  32, 1, },
	{ "r9",      4,  36, 1, },
	{ "r10",     4,  40, 1, },
	{ "r11",     4,  44, 1, },
	{ "r12",     4,  48, 1, },
	{ "r13",     4,  52, 1, },
	{ "r14",     4,  56, 1, },
	{ "pc",      4,  60, 1, },
	{ "f0",      4,  64, 1, },
	{ "f1",      4,  68, 1, },
	{ "f2",      4,  72, 1, },
	{ "f3",      4,  76, 1, },
	{ "f4",      4,  80, 1, },
	{ "f5",      4,  84, 1, },
	{ "f6",      4,  88, 1, },
	{ "f7",      4,  92, 1, },
	{ "fps",     4,  96, 1, },
	{ "cpsr",    4, 100, 1, },
	{ NULL,      0,   0, 0, },
};

struct mdb_gdb_tgt mdb_gdb_tgt_armv6 = {
	.reginfo  = armv6_reginfo,
	.dmodel   = MDB_TGT_MODEL_ILP32,
	.isa      = "armv6",
	.platform = "bcm2835",
};
