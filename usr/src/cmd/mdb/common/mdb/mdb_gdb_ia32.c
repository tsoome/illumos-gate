#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_gdb.h>
#include <mdb/mdb.h>

#define	KREG_EFLAGS_ID_MASK	0x00200000
#define	KREG_EFLAGS_ID_SHIFT	21

#define	KREG_EFLAGS_VIP_MASK	0x00100000
#define	KREG_EFLAGS_VIP_SHIFT	20

#define	KREG_EFLAGS_VIF_MASK	0x00080000
#define	KREG_EFLAGS_VIF_SHIFT	19

#define	KREG_EFLAGS_AC_MASK	0x00040000
#define	KREG_EFLAGS_AC_SHIFT	18

#define	KREG_EFLAGS_VM_MASK	0x00020000
#define	KREG_EFLAGS_VM_SHIFT	17

#define	KREG_EFLAGS_RF_MASK	0x00010000
#define	KREG_EFLAGS_RF_SHIFT	16

#define	KREG_EFLAGS_NT_MASK	0x00004000
#define	KREG_EFLAGS_NT_SHIFT	14

#define	KREG_EFLAGS_IOPL_MASK	0x00003000
#define	KREG_EFLAGS_IOPL_SHIFT	12

#define	KREG_EFLAGS_OF_MASK	0x00000800
#define	KREG_EFLAGS_OF_SHIFT	11

#define	KREG_EFLAGS_DF_MASK	0x00000400
#define	KREG_EFLAGS_DF_SHIFT	10

#define	KREG_EFLAGS_IF_MASK	0x00000200
#define	KREG_EFLAGS_IF_SHIFT	9

#define	KREG_EFLAGS_TF_MASK	0x00000100
#define	KREG_EFLAGS_TF_SHIFT	8

#define	KREG_EFLAGS_SF_MASK	0x00000080
#define	KREG_EFLAGS_SF_SHIFT	7

#define	KREG_EFLAGS_ZF_MASK	0x00000040
#define	KREG_EFLAGS_ZF_SHIFT	6

#define	KREG_EFLAGS_AF_MASK	0x00000010
#define	KREG_EFLAGS_AF_SHIFT	4

#define	KREG_EFLAGS_PF_MASK	0x00000004
#define	KREG_EFLAGS_PF_SHIFT	2

#define	KREG_EFLAGS_CF_MASK	0x00000001
#define	KREG_EFLAGS_CF_SHIFT	0

static const struct mdb_gdb_reginfo ia32_reginfo[] = {
	{ "eax",     4,   0, 1, },
	{ "ecx",     4,   4, 1, },
	{ "edx",     4,   8, 1, },
	{ "ebx",     4,  12, 1, },
	{ "esp",     4,  16, 1, },
	{ "ebp",     4,  20, 1, },
	{ "esi",     4,  24, 1, },
	{ "edi",     4,  28, 1, },
	{ "eip",     4,  32, 1, },
	{ "eflags",  4,  36, 1, },
	{ "cs",      4,  40, 1, },
	{ "ss",      4,  44, 1, },
	{ "ds",      4,  48, 1, },
	{ "es",      4,  52, 1, },
	{ "fs",      4,  56, 1, },
	{ "gs",      4,  60, 1, },
	{ "st0",    10,  64, 1, },
	{ "st1",    10,  74, 1, },
	{ "st2",    10,  84, 1, },
	{ "st3",    10,  94, 1, },
	{ "st4",    10, 104, 1, },
	{ "st5",    10, 114, 1, },
	{ "st6",    10, 124, 1, },
	{ "st7",    10, 134, 1, },
	{ "fctrl",   4, 144, 1, },
	{ "fstat",   4, 148, 1, },
	{ "ftag",    4, 152, 1, },
	{ "fiseg",   4, 156, 1, },
	{ "fioff",   4, 160, 1, },
	{ "foseg",   4, 164, 1, },
	{ "fooff",   4, 168, 1, },
	{ "fop",     4, 172, 1, },
	{ "xmm0",   16, 176, 1, },
	{ "xmm1",   16, 192, 1, },
	{ "xmm2",   16, 208, 1, },
	{ "xmm3",   16, 224, 1, },
	{ "xmm4",   16, 240, 1, },
	{ "xmm5",   16, 256, 1, },
	{ "xmm6",   16, 272, 1, },
	{ "xmm7",   16, 288, 1, },
	{ "mxcsr",   4, 304, 1, },
	{ NULL,      0,   0, 0, },
};

static uint32_t get_reg(mdb_nv_t *regs, const char *name)
{
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(regs, name)))
		return mdb_nv_get_value(v);
	return 0;
}

static void print_regs(mdb_nv_t *regs)
{
	uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi, eip, eflags;
	uint32_t cs, ss, ds, es, fs, gs;

	eax = get_reg(regs, "eax");
	ecx = get_reg(regs, "ecx");
	edx = get_reg(regs, "edx");
	ebx = get_reg(regs, "ebx");
	esp = get_reg(regs, "esp");
	ebp = get_reg(regs, "ebp");
	esi = get_reg(regs, "esi");
	edi = get_reg(regs, "edi");
	eip = get_reg(regs, "eip");
	eflags = get_reg(regs, "eflags");
	cs = get_reg(regs, "cs");
	ss = get_reg(regs, "ss");
	ds = get_reg(regs, "ds");
	es = get_reg(regs, "es");
	fs = get_reg(regs, "fs");
	gs = get_reg(regs, "gs");

	mdb_printf("%%cs = 0x%04x\t\t%%eax = 0x%08p %A\n", cs, eax, eax);
	mdb_printf("%%ds = 0x%04x\t\t%%ebx = 0x%08p %A\n", ds, ebx, ebx);
	mdb_printf("%%ss = 0x%04x\t\t%%ecx = 0x%08p %A\n", ss, ecx, ecx);
	mdb_printf("%%es = 0x%04x\t\t%%edx = 0x%08p %A\n", es, edx, edx);
	mdb_printf("%%fs = 0x%04x\t\t%%esi = 0x%08p %A\n", fs, esi, esi);
	mdb_printf("%%gs = 0x%04x\t\t%%edi = 0x%08p %A\n\n", gs, edi, edi);

	mdb_printf(" %%eip = 0x%08p %A\n", eip, eip);
	mdb_printf(" %%ebp = 0x%08p\n", ebp);
	mdb_printf(" %%esp = 0x%08p\n\n", esp);
	mdb_printf("%%eflags = 0x%08x\n", eflags);

	mdb_printf("  id=%u vip=%u vif=%u ac=%u vm=%u rf=%u nt=%u iopl=0x%x\n",
	    (eflags & KREG_EFLAGS_ID_MASK) >> KREG_EFLAGS_ID_SHIFT,
	    (eflags & KREG_EFLAGS_VIP_MASK) >> KREG_EFLAGS_VIP_SHIFT,
	    (eflags & KREG_EFLAGS_VIF_MASK) >> KREG_EFLAGS_VIF_SHIFT,
	    (eflags & KREG_EFLAGS_AC_MASK) >> KREG_EFLAGS_AC_SHIFT,
	    (eflags & KREG_EFLAGS_VM_MASK) >> KREG_EFLAGS_VM_SHIFT,
	    (eflags & KREG_EFLAGS_RF_MASK) >> KREG_EFLAGS_RF_SHIFT,
	    (eflags & KREG_EFLAGS_NT_MASK) >> KREG_EFLAGS_NT_SHIFT,
	    (eflags & KREG_EFLAGS_IOPL_MASK) >> KREG_EFLAGS_IOPL_SHIFT);

	mdb_printf("  status=<%s,%s,%s,%s,%s,%s,%s,%s,%s>\n\n",
	    (eflags & KREG_EFLAGS_OF_MASK) ? "OF" : "of",
	    (eflags & KREG_EFLAGS_DF_MASK) ? "DF" : "df",
	    (eflags & KREG_EFLAGS_IF_MASK) ? "IF" : "if",
	    (eflags & KREG_EFLAGS_TF_MASK) ? "TF" : "tf",
	    (eflags & KREG_EFLAGS_SF_MASK) ? "SF" : "sf",
	    (eflags & KREG_EFLAGS_ZF_MASK) ? "ZF" : "zf",
	    (eflags & KREG_EFLAGS_AF_MASK) ? "AF" : "af",
	    (eflags & KREG_EFLAGS_PF_MASK) ? "PF" : "pf",
	    (eflags & KREG_EFLAGS_CF_MASK) ? "CF" : "cf");
}

struct mdb_gdb_tgt mdb_gdb_tgt_ia32 = {
	.reginfo  = ia32_reginfo,
	.dmodel   = MDB_TGT_MODEL_ILP32,
	.isa      = "i386",
	.platform = "i86pc",

	.print_regs = print_regs,
};
