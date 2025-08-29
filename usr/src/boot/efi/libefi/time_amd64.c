/*
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <efi.h>
#include <efilib.h>

#include <x86/specialreg.h>
#include <machine/cpufunc.h>

#include "platform/acfreebsd.h"
#include "acconfig.h"
#define	ACPI_SYSTEM_XFACE
#include "actypes.h"
#include "actbl.h"

/* Definitions for 8254 Programmable Interrupt Timer ports on AT 386 */
#define	PITCTR2_PORT	0x42		/* counter 2 port */
#define	PITCTL_PORT	0x43		/* PIT control port */
#define	PITAUX_PORT	0x61		/* PIT auxiliary port */

/* control port bits */

#define	PIT_CTRL_SELECT_2 0x80		/* Counter 2 */
#define	PIT_CTRL_READLOAD_WORD 0x30	/* Read/load the LSB then the MSB */

/* bits used in auxiliary control port for timer 2 */
#define	PITAUX_GATE2	0x01		/* aux port, PIT gate 2 input */
#define	PITAUX_OUT2	0x02		/* aux port, PIT clock out 2 enable */

typedef uint64_t (*get_time_ms_func_t) (void);
static get_time_ms_func_t get_time_ms_func;

static uint64_t tsc_rate = 5368; /* 800 MHz */
static uint64_t boot_time;

uint64_t
get_time_ms(void)
{
	return (get_time_ms_func());
}

static uint64_t
get_tsc(void)
{
	uint64_t v;
	unsigned int regs[4];

	do_cpuid(0, regs);
	v = rdtsc();
	do_cpuid(0, regs);
	return (v);
}

/*
 * Calculate TSC frequency using information from the CPUID leaf 0x15 'Time
 * Stamp Counter and Nominal Core Crystal Clock'.  If leaf 0x15 is not
 * functional, as it is on Skylake/Kabylake, try 0x16 'Processor Frequency
 * Information'.  Leaf 0x16 is described in the SDM as informational only, but
 * we can use this value until late calibration is complete.
 */
static bool
tsc_freq_cpuid(uint64_t *res)
{
	unsigned int regs[4];
	unsigned int cpu_high;

	do_cpuid(0, regs);
	cpu_high = regs[0];

	if (cpu_high < 0x15)
		return (false);
	do_cpuid(0x15, regs);
	if (regs[0] != 0 && regs[1] != 0 && regs[2] != 0) {
		*res = (uint64_t)regs[2] * regs[1] / regs[0];
		return (true);
	}

	if (cpu_high < 0x16)
		return (false);
	do_cpuid(0x16, regs);
	if (regs[0] != 0) {
		*res = (uint64_t)regs[0] * 1000000;
		return (true);
	}

	return (false);
}

static bool
pit_wait(void)
{
	bool ret = false;

	/* Disable timer2 gate and speaker.  */
	outb(PITAUX_PORT, inb(PITAUX_PORT) & ~(PITAUX_GATE2 | PITAUX_OUT2));

	/* Set tics.  */
	outb(PITCTL_PORT, PIT_CTRL_SELECT_2 | PIT_CTRL_READLOAD_WORD);
	/* 0xffff ticks: 55ms. */
	outb(PITCTR2_PORT, 0xff);
	outb(PITCTR2_PORT, 0xff);

	/* Enable timer2 gate, keep speaker disabled. */
	outb(PITAUX_PORT, (inb(PITAUX_PORT) & ~PITAUX_OUT2) | PITAUX_GATE2);

	if ((inb(PITAUX_PORT) & 0x20) == 0x00) {
		ret = true;
		/* Wait. */
		while ((inb(PITAUX_PORT) & 0x20) == 0x00)
			;
	}

	/* Disable timer2 gate and speaker.  */
	outb(PITAUX_PORT, inb(PITAUX_PORT) & ~(PITAUX_GATE2 | PITAUX_OUT2));

	return (ret);
}

static bool
tsc_freq_pit(uint64_t *res)
{
	uint64_t start_tsc, end_tsc, rate;

	start_tsc = get_tsc();
	if (!pit_wait())
		return (false);
	end_tsc = get_tsc();
	rate = 0;
	if (end_tsc > start_tsc)
		rate = (55ULL << 32) / (end_tsc - start_tsc);
	if (rate == 0)
		return (false);

	*res = rate;
	return (true);
}

static uint64_t
pmtimer_wait(uint32_t port, uint16_t tics)
{
	uint32_t start;
	uint64_t cur, end;
	uint64_t start_tsc, end_tsc;
	int failed = 0;

	/*
	 * We do not need high bits.
	 */
	cur = start = inl(port) & 0x00ffffffffUL;
	end = start + tics;
	start_tsc = get_tsc();

	while (true) {
		cur &= 0xffffffff00000000UL;
		cur |= inl(port) & 0x00ffffffffUL;
		end_tsc = get_tsc();

		/* check for bad values */
		if (cur == 0xffffff || cur == 0) {
			failed++;
			if (failed > 10)
				return (0);
		}
		if (cur < start)
			cur += 0x1000000;
		if (cur > end)
			return (end_tsc - start_tsc);
	}
}

static bool
tsc_freq_acpi(uint64_t *res)
{
	ACPI_TABLE_FADT *fadt = acpi_find_table(ACPI_SIG_FADT);
	uint64_t port;

	if (fadt == NULL)
		return (false);

	/*
	 * Check XPmTimerBlock, if 0, then PmTimerBlock.
	 */
	if (fadt->XPmTimerBlock.Address == 0) {
		port = fadt->PmTimerBlock;
	} else {
		if (fadt->XPmTimerBlock.SpaceId !=
		    ACPI_ADR_SPACE_SYSTEM_IO)
			return (false);
		port = fadt->XPmTimerBlock.Address;
	}

	if (port == 0)
		return (false);

	/* ACPI clock is 3.579545MHz. Wait for 1ms */
	uint64_t tsc = pmtimer_wait(port, 3580);
	if (tsc == 0)
		return (false);
	uint64_t rate = (1ULL << 32) / tsc;
	if (rate == 0)
		return (false);
	*res = rate;
	return (true);
}

static bool
tsc_freq_efi(uint64_t *res)
{
	uint64_t start_tsc, end_tsc;

	/* Use EFI Time Service to calibrate TSC */
	start_tsc = get_tsc();
	BS->Stall(1000);
	end_tsc = get_tsc();
	*res = (1ULL << 32) / (end_tsc - start_tsc);
	return (true);
}

static uint64_t
tsc_get_time_ms(void)
{
	uint64_t a = get_tsc() - boot_time;
	uint64_t ah = a >> 32;
	uint64_t al = a & 0xffffffff;

	return (((al * tsc_rate) >> 32) + ah * tsc_rate);
}

void
efi_time_init(void)
{
	boot_time = get_tsc();

	if (!tsc_freq_cpuid(&tsc_rate) &&
	    !tsc_freq_acpi(&tsc_rate) &&
	    !tsc_freq_pit(&tsc_rate))
		(void) tsc_freq_efi(&tsc_rate);

	get_time_ms_func = tsc_get_time_ms;
}

void
efi_time_fini(void)
{
}
