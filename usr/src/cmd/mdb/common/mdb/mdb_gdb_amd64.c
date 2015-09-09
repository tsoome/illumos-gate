#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_gdb.h>
#include <mdb/mdb.h>

static const struct mdb_gdb_reginfo amd64_reginfo[] = {
	{ "rax",     8,   0, 1, },
	{ "rdx",     8,   8, 1, },
	{ "rcx",     8,  16, 1, },
	{ "rbx",     8,  24, 1, },
	{ "rsi",     8,  32, 1, },
	{ "rdi",     8,  40, 1, },
	{ "rbp",     8,  48, 1, },
	{ "rsp",     8,  56, 1, },
	{ "r8",      8,  64, 1, },
	{ "r9",      8,  72, 1, },
	{ "r10",     8,  80, 1, },
	{ "r11",     8,  88, 1, },
	{ "r12",     8,  96, 1, },
	{ "r13",     8, 104, 1, },
	{ "r14",     8, 112, 1, },
	{ "r15",     8, 120, 1, },
	{ "rip",     8, 128, 1, },
	{ "eflags",  4, 136, 1, },
	{ "st0",    10, 140, 1, },
	{ "st1",    10, 150, 1, },
	{ "st2",    10, 160, 1, },
	{ "st3",    10, 170, 1, },
	{ "st4",    10, 180, 1, },
	{ "st5",    10, 190, 1, },
	{ "st6",    10, 200, 1, },
	{ "st7",    10, 210, 1, },
	{ "fctrl",   4, 220, 1, },
	{ "fstat",   4, 224, 1, },
	{ "ftag",    4, 228, 1, },
	{ "fiseg",   4, 232, 1, },
	{ "fioff",   4, 236, 1, },
	{ "foseg",   4, 240, 1, },
	{ "fooff",   4, 244, 1, },
	{ "fop",     4, 248, 1, },
	{ "xmm0",   16, 252, 1, },
	{ "xmm1",   16, 268, 1, },
	{ "xmm2",   16, 284, 1, },
	{ "xmm3",   16, 300, 1, },
	{ "xmm4",   16, 316, 1, },
	{ "xmm5",   16, 332, 1, },
	{ "xmm6",   16, 348, 1, },
	{ "xmm7",   16, 364, 1, },
	{ "xmm8",   16, 380, 1, },
	{ "xmm9",   16, 396, 1, },
	{ "xmm10",  16, 412, 1, },
	{ "xmm11",  16, 428, 1, },
	{ "xmm12",  16, 444, 1, },
	{ "xmm13",  16, 460, 1, },
	{ "xmm14",  16, 476, 1, },
	{ "xmm15",  16, 492, 1, },
	{ "mxcsr",   4, 508, 1, },
	{ NULL,      0,   0, 0, },
};

struct mdb_gdb_tgt mdb_gdb_tgt_amd64 = {
	.reginfo  = amd64_reginfo,
	.dmodel   = MDB_TGT_MODEL_LP64,
	.isa      = "amd64",
	.platform = "i86pc",
};
