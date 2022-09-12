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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Get the sparc version of the relocation engine */
#define	DO_RELOC_LIBLD_AARCH64

#include	<string.h>
#include	<stdio.h>
#include	<sys/elf_aarch64.h>
#include	<debug.h>
#include	<reloc.h>
#include	<aarch64/machdep_aarch64.h>

#include	"_libld.h"
/*
 * Search the GOT index list for a GOT entry with a matching reference and the
 * proper addend.
 */
static Gotndx *
ld_find_got_ndx(Alist *alp, Gotref gref, Ofl_desc *ofl, Rel_desc *rdesc)
{
	assert(0 && "Not implemented");
	return (NULL);
}

static Xword
ld_calc_got_offset(Rel_desc * rdesc, Ofl_desc * ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

static Word
ld_init_rel(Rel_desc *reld, Word *typedata, void *reloc)
{
	Rela	*rela = (Rela *)reloc;

	/* LINTED */
	reld->rel_rtype = (Word)ELF_R_TYPE(rela->r_info, M_MACH);
	reld->rel_roffset = rela->r_offset;
	reld->rel_raddend = rela->r_addend;
	*typedata = (Word)ELF_R_TYPE_DATA(rela->r_info);

	reld->rel_flags |= FLG_REL_RELA;

	return ((Word)ELF_R_SYM(rela->r_info));
}

static void
ld_mach_eflags(Ehdr *ehdr, Ofl_desc *ofl)
{
	ofl->ofl_dehdr->e_flags |= ehdr->e_flags;
}

static void
ld_mach_make_dynamic(Ofl_desc *ofl, size_t *cnt)
{
	if (!(ofl->ofl_flags & FLG_OF_RELOBJ)) {
		/*
		 * Create this entry if we are going to create a PLT table.
		 */
		if (ofl->ofl_pltcnt)
			(*cnt)++;		/* DT_PLTGOT */
	}
}

static void
ld_mach_update_odynamic(Ofl_desc *ofl, Dyn **dyn)
{
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) && ofl->ofl_pltcnt) {
		(*dyn)->d_tag = DT_PLTGOT;
		if (ofl->ofl_osplt)
			(*dyn)->d_un.d_ptr = ofl->ofl_osplt->os_shdr->sh_addr;
		else
			(*dyn)->d_un.d_ptr = 0;
		(*dyn)++;
	}
}

static Xword
ld_calc_plt_addr(Sym_desc *sdp, Ofl_desc *ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

static __unused void
plt_entry(Ofl_desc *ofl, Xword pltndx, Xword *roffset, Sxword *raddend)
{
	assert(0 && "Not implemented");
}

static uintptr_t
ld_perform_outreloc(Rel_desc *orsp, Ofl_desc *ofl, Boolean *remain_seen)
{
	assert(0 && "Not implemented");
	return (0);
}

static __unused Fixupret
tls_fixups(Ofl_desc *ofl, Rel_desc *arsp)
{
	assert(0 && "Not implemented");
	return (0);
}

static uintptr_t
ld_do_activerelocs(Ofl_desc *ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

static uintptr_t
ld_add_outrel(Word flags, Rel_desc *rsp, Ofl_desc *ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

/*
 * process relocation for a LOCAL symbol
 */
static uintptr_t
ld_reloc_local(Rel_desc *rsp, Ofl_desc *ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

static uintptr_t
ld_reloc_TLS(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

static uintptr_t
ld_assign_got(Ofl_desc *ofl, Sym_desc *sdp)
{
	assert(0 && "Not implemented");
	return (0);
}

static uintptr_t
ld_assign_got_ndx(Alist **alpp, Gotndx *pgnp, Gotref gref, Ofl_desc *ofl,
    Rel_desc *rsp, Sym_desc *sdp)
{
	assert(0 && "Not implemented");
	return (0);
}

static void
ld_assign_plt_ndx(Sym_desc * sdp, Ofl_desc *ofl)
{
	assert(0 && "Not implemented");
}


static uintptr_t
ld_allocate_got(Ofl_desc * ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

/*
 * Initializes .got[0] with the _DYNAMIC symbol value.
 */
static uintptr_t
ld_fillin_gotplt(Ofl_desc *ofl)
{
	assert(0 && "Not implemented");
	return (0);
}

/*
 * Template for generating "void (*)(void)" function
 * XXXARM
 */
static const uchar_t nullfunc_tmpl[] = {
/* 0x00 */	0x00,
};

/*
 * Return the ld_targ definition for this target.
 */
const Target *
ld_targ_init_aarch64(void)
{
	static const Target _ld_targ = {
		{			/* Target_mach */
			M_MACH,			/* m_mach */
			M_MACHPLUS,		/* m_machplus */
			M_FLAGSPLUS,		/* m_flagsplus */
			M_CLASS,		/* m_class */
			M_DATA,			/* m_data */

			M_SEGM_ALIGN,		/* m_segm_align */
			M_SEGM_ORIGIN,		/* m_segm_origin */
			M_SEGM_AORIGIN,		/* m_segm_aorigin */
			M_DATASEG_PERM,		/* m_dataseg_perm */
			M_STACK_PERM,		/* m_stack_perm */
			M_WORD_ALIGN,		/* m_word_align */
						/* m_def_interp */
			MSG_ORIG(MSG_PTH_RTLD_AARCH64),

			/* Relocation type codes */
			M_R_ARRAYADDR,		/* m_r_arrayaddr */
			M_R_COPY,		/* m_r_copy */
			M_R_GLOB_DAT,		/* m_r_glob_dat */
			M_R_JMP_SLOT,		/* m_r_jmp_slot */
			M_R_NUM,		/* m_r_num */
			M_R_NONE,		/* m_r_none */
			M_R_RELATIVE,		/* m_r_relative */
			M_R_REGISTER,		/* m_r_register */

			/* Relocation related constants */
			M_REL_DT_COUNT,		/* m_rel_dt_count */
			M_REL_DT_ENT,		/* m_rel_dt_ent */
			M_REL_DT_SIZE,		/* m_rel_dt_size */
			M_REL_DT_TYPE,		/* m_rel_dt_type */
			M_REL_SHT_TYPE,		/* m_rel_sht_type */

			/* GOT related constants */
			M_GOT_ENTSIZE,		/* m_got_entsize */
			M_GOT_XNumber,		/* m_got_xnumber */

			/* PLT related constants */
			M_PLT_ALIGN,		/* m_plt_align */
			M_PLT_ENTSIZE,		/* m_plt_entsize */
			M_PLT_RESERVSZ,		/* m_plt_reservsz */
			M_PLT_SHF_FLAGS,	/* m_plt_shf_flags */

			/* Section type of .eh_frame/.eh_frame_hdr sections */
			SHT_PROGBITS,		/* m_sht_unwind */

			M_DT_REGISTER,		/* m_dt_register */
		},
		{			/* Target_machid */
			M_ID_ARRAY,		/* id_array */
			M_ID_BSS,		/* id_bss */
			M_ID_CAP,		/* id_cap */
			M_ID_CAPINFO,		/* id_capinfo */
			M_ID_CAPCHAIN,		/* id_capchain */
			M_ID_DATA,		/* id_data */
			M_ID_DYNAMIC,		/* id_dynamic */
			M_ID_DYNSORT,		/* id_dynsort */
			M_ID_DYNSTR,		/* id_dynstr */
			M_ID_DYNSYM,		/* id_dynsym */
			M_ID_DYNSYM_NDX,	/* id_dynsym_ndx */
			M_ID_GOT,		/* id_got */
			M_ID_UNKNOWN,		/* id_gotdata (unused?) */
			M_ID_HASH,		/* id_hash */
			M_ID_INTERP,		/* id_interp */
			M_ID_UNKNOWN,		/* id_lbss (unused) */
			M_ID_LDYNSYM,		/* id_ldynsym */
			M_ID_NOTE,		/* id_note */
			M_ID_NULL,		/* id_null */
			M_ID_PLT,		/* id_plt */
			M_ID_REL,		/* id_rel */
			M_ID_STRTAB,		/* id_strtab */
			M_ID_SYMINFO,		/* id_syminfo */
			M_ID_SYMTAB,		/* id_symtab */
			M_ID_SYMTAB_NDX,	/* id_symtab_ndx */
			M_ID_TEXT,		/* id_text */
			M_ID_TLS,		/* id_tls */
			M_ID_TLSBSS,		/* id_tlsbss */
			M_ID_UNKNOWN,		/* id_unknown */
			M_ID_UNWIND,		/* id_unwind */
			M_ID_UNWINDHDR,		/* id_unwindhdr */
			M_ID_USER,		/* id_user */
			M_ID_VERSION,		/* id_version */
		},
		{			/* Target_nullfunc */
			nullfunc_tmpl,		/* nf_template */
			sizeof (nullfunc_tmpl),	/* nf_size */
		},
		{			/* Target_fillfunc */
			/*
			 * On sparc, special filling of executable sections
			 * is undesirable, and the default 0 fill supplied
			 * by libelf is preferred:
			 *
			 * -	0 fill is interpreted as UNIMP instructions,
			 *	which cause an illegal_instruction_trap. These
			 *	serve as a sentinel against poorly written
			 *	code. The sparc architecture manual discusses
			 *	this as providing a measure of runtime safety.
			 *
			 * -	The one place where a hole should conceivably
			 *	be filled with NOP instructions is in the
			 *	.init/.fini sections. However, the sparc
			 *	assembler sizes the sections it generates
			 *	to a multiple of the section alignment, and as
			 *	such, takes the filling task out of our hands.
			 *	Furthermore, the sparc assembler uses 0-fill
			 *	for this, forcing the authors of sparc
			 *	assembler for .init/.fini sections to be aware
			 *	of this case and explicitly supply NOP fill.
			 *	Hence, there is no role for the link-editor.
			 */
			NULL			/* ff_execfill */
		},
		{			/* Target_machrel */
			reloc_table,

			ld_init_rel,		/* mr_init_rel */
			ld_mach_eflags,		/* mr_mach_eflags */
			ld_mach_make_dynamic,	/* mr_mach_make_dynamic */
			ld_mach_update_odynamic, /* mr_mach_update_odynamic */
			ld_calc_plt_addr,	/* mr_calc_plt_addr */
			ld_perform_outreloc,	/* mr_perform_outreloc */
			ld_do_activerelocs,	/* mr_do_activerelocs */
			ld_add_outrel,		/* mr_add_outrel */
			NULL,	/* mr_reloc_register */
			ld_reloc_local,		/* mr_reloc_local */
			NULL,		/* mr_reloc_GOTOP */
			ld_reloc_TLS,		/* mr_reloc_TLS */
			ld_assign_got,		/* mr_assign_got */
			ld_find_got_ndx,	/* mr_find_got_ndx */
			ld_calc_got_offset,	/* mr_calc_got_offset */
			ld_assign_got_ndx,	/* mr_assign_got_ndx */
			ld_assign_plt_ndx,	/* mr_assign_plt_ndx */
			ld_allocate_got,	/* mr_allocate_got */
			ld_fillin_gotplt,	/* mr_fillin_gotplt */
		},
		{			/* Target_machsym */
			NULL,	/* ms_reg_check */
			NULL, /* ms_mach_sym_typecheck */
			NULL,	/* ms_is_regsym */
			NULL,	/* ms_reg_find */
			NULL	/* ms_reg_enter */
		}
	};

	return (&_ld_targ);
}
