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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2017 Hayashi Naoyuki
 */

/*
 * XXXARM:
 *
 * NB: This driver, while clearly derived from asy(4D) is an almost verbatim
 * copy of the ns16550a driver.
 *
 * It is not clear why they have diverged (or if they must), this requires
 * investigation.
 *
 * I have taken a big hammer to symbol and type names to avoid collisions when
 * debugging, for clean diffs v. asy(4D), translate pl011 to asy, plasync to
 * async.  for clean diffs v. ns16550a translate pl011 to ns16550, plasync to
 * nsasync.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <sys/termio.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strtty.h>
#include <sys/debug.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/mkdev.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/strsun.h>
#include <sys/promif.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/policy.h>
#include "pl011.h"

#define UARTDR		0x00
#define UARTRSR		0x04
#define UARTECR		0x04
#define UARTFR		0x18
#define UARTIBRD	0x24
#define UARTFBRD	0x28
#define UARTLCR_H	0x2c
#define UARTCR		0x30
#define UARTIFLS	0x34
#define UARTIMSC	0x38	// interrupt mask set/clear
#define UARTRIS		0x3c	// interrupt raw status register
#define UARTMIS		0x40	// masked interrupt status register
#define UARTICR		0x44	// interrupt clear register

#define REG_READ(pl011, reg)		ddi_get32((pl011)->pl011_iohandle, (uint32_t *)((pl011)->pl011_ioaddr + (reg)))
#define REG_WRITE(pl011, reg, val)	ddi_put32((pl011)->pl011_iohandle, (uint32_t *)((pl011)->pl011_ioaddr + (reg)), (val))

union uart_dr {
	uint32_t dw;
	struct {
		uint32_t data		: 8;
		uint32_t fe		: 1;
		uint32_t pe		: 1;
		uint32_t be		: 1;
		uint32_t oe		: 1;
		uint32_t 		: 4;
		uint32_t 		: 16;
	};
};

union uart_rsr {
	uint32_t dw;
	struct {
		uint32_t fe		: 1;
		uint32_t pe		: 1;
		uint32_t be		: 1;
		uint32_t oe		: 1;
		uint32_t 		: 4;
		uint32_t 		: 24;
	};
};

union uart_fr {
	uint32_t dw;
	struct {
		uint32_t cts		: 1;
		uint32_t dsr		: 1;
		uint32_t dcd		: 1;
		uint32_t busy		: 1;
		uint32_t rxfe		: 1;
		uint32_t txff		: 1;
		uint32_t rxff		: 1;
		uint32_t txfe		: 1;
		uint32_t ri		: 1;
		uint32_t 		: 7;
		uint32_t 		: 16;
	};
};

union uart_ibrd {
	uint32_t dw;
	struct {
		uint32_t divint		: 16;
		uint32_t 		: 16;
	};
};

union uart_fbrd {
	uint32_t dw;
	struct {
		uint32_t divfrac	: 6;
		uint32_t 		: 26;
	};
};

union uart_lcr_h {
	uint32_t dw;
	struct {
		uint32_t brk		: 1;
		uint32_t pen		: 1;
		uint32_t eps		: 1;
		uint32_t stp2		: 1;
		uint32_t fen		: 1;
		uint32_t wlen		: 2;
		uint32_t sps		: 1;
		uint32_t 		: 8;
		uint32_t 		: 16;
	};
};

union uart_cr {
	uint32_t dw;
	struct {
		uint32_t uarten		: 1;
		uint32_t siren		: 1;
		uint32_t sirlp		: 1;
		uint32_t 		: 4;
		uint32_t lbe		: 1;
		uint32_t txe		: 1;
		uint32_t rxe		: 1;
		uint32_t dtr		: 1;
		uint32_t rts		: 1;
		uint32_t out1		: 1;
		uint32_t out2		: 1;
		uint32_t rtsen		: 1;
		uint32_t ctsen		: 1;
		uint32_t 		: 16;
	};
};

union uart_ifls {
	uint32_t dw;
	struct {
		uint32_t txiflsel	: 3;
		uint32_t rxiflsel	: 3;
		uint32_t 		: 10;
		uint32_t 		: 16;
	};
};

union uart_intr {
	uint32_t dw;
	struct {
		uint32_t ri		: 1;
		uint32_t cts		: 1;
		uint32_t dcd		: 1;
		uint32_t dsr		: 1;
		uint32_t rx		: 1;
		uint32_t tx		: 1;
		uint32_t rt		: 1;
		uint32_t fe		: 1;
		uint32_t pe		: 1;
		uint32_t be		: 1;
		uint32_t oe		: 1;
		uint32_t 		: 5;
		uint32_t 		: 16;
	};
};

#define	PL011_REGISTER_FILE_NO 0
#define	PL011_REGOFFSET 0
#define	PL011_REGISTER_LEN 0
#define	PL011_DEFAULT_BAUD	B115200

/*
 * set the RX FIFO trigger_level to half the RX FIFO size for now
 * we may want to make this configurable later.
 */
static	int pl011_trig_level = FIFO_TRIG_8;

static int pl011_drain_check = 15000000;		/* tunable: exit drain check time */
static int pl011_min_dtr_low = 500000;		/* tunable: minimum DTR down time */
static int pl011_min_utbrk = 100000;		/* tunable: minumum untimed brk time */

/*
 * Just in case someone has a chip with broken loopback mode, we provide a
 * means to disable the loopback test. By default, we only loopback test
 * UARTs which look like they have FIFOs bigger than 16 bytes.
 * Set to 0 to suppress test, or to 2 to enable test on any size FIFO.
 */
static int pl011_fifo_test = 1;		/* tunable: set to 0, 1, or 2 */

/*
 * Allow ability to switch off testing of the scratch register.
 * Some UART emulators might not have it. This will also disable the test
 * for Exar/Startech ST16C650, as that requires use of the SCR register.
 */
static int pl011_scr_test = 1;		/* tunable: set to 0 to disable SCR reg test */

/*
 * As we don't yet support on-chip flow control, it's a bad idea to put a
 * large number of characters in the TX FIFO, since if other end tells us
 * to stop transmitting, we can only stop filling the TX FIFO, but it will
 * still carry on draining by itself, so remote end still gets what's left
 * in the FIFO.
 */
static int pl011_max_tx_fifo = 16;	/* tunable: max fill of TX FIFO */

#define	plasync_stopc	plasync_ttycommon.t_stopc
#define	plasync_startc	plasync_ttycommon.t_startc

#define	PL011_INIT	1
#define	PL011_NOINIT	0

/* enum value for sw and hw flow control action */
typedef enum {
	FLOW_CHECK,
	FLOW_STOP,
	FLOW_START
} plasync_flowc_action;

#ifdef DEBUG
#define	PL011_DEBUG_INIT	0x0001	/* Output msgs during driver initialization. */
#define	PL011_DEBUG_INPUT	0x0002	/* Report characters received during int. */
#define	PL011_DEBUG_EOT	0x0004	/* Output msgs when wait for xmit to finish. */
#define	PL011_DEBUG_CLOSE	0x0008	/* Output msgs when driver open/close called */
#define	PL011_DEBUG_HFLOW	0x0010	/* Output msgs when H/W flowcontrol is active */
#define	PL011_DEBUG_PROCS	0x0020	/* Output each proc name as it is entered. */
#define	PL011_DEBUG_STATE	0x0040	/* Output value of Interrupt Service Reg. */
#define	PL011_DEBUG_INTR	0x0080	/* Output value of Interrupt Service Reg. */
#define	PL011_DEBUG_OUT	0x0100	/* Output msgs about output events. */
#define	PL011_DEBUG_BUSY	0x0200	/* Output msgs when xmit is enabled/disabled */
#define	PL011_DEBUG_MODEM	0x0400	/* Output msgs about modem status & control. */
#define	PL011_DEBUG_MODM2	0x0800	/* Output msgs about modem status & control. */
#define	PL011_DEBUG_IOCTL	0x1000	/* Output msgs about ioctl messages. */
#define	PL011_DEBUG_CHIP	0x2000	/* Output msgs about chip identification. */
#define	PL011_DEBUG_SFLOW	0x4000	/* Output msgs when S/W flowcontrol is active */
#define	PL011_DEBUG(x) (debug & (x))
static	int debug  = 0;
#else
#define	PL011_DEBUG(x) B_FALSE
#endif

/* pnpISA compressed device ids */
#define	pnpMTS0219 0xb6930219	/* Multitech MT5634ZTX modem */

/*
 * PPS (Pulse Per Second) support.
 */
void ddi_hardpps(struct timeval *, int);
/*
 * This is protected by the pl011_excl_hi of the port on which PPS event
 * handling is enabled.  Note that only one port should have this enabled at
 * any one time.  Enabling PPS handling on multiple ports will result in
 * unpredictable (but benign) results.
 */
static struct ppsclockev pl011_ppsev;

#ifdef PPSCLOCKLED
/* XXX Use these to observe PPS latencies and jitter on a scope */
#define	LED_ON
#define	LED_OFF
#else
#define	LED_ON
#define	LED_OFF
#endif

static	int max_pl011_instance = -1;

static	uint_t	pl011softintr(caddr_t intarg);
static	uint_t	pl011intr(caddr_t argpl011);

static boolean_t abort_charseq_recognize(uchar_t ch);

/* The async interrupt entry points */
static void	plasync_txint(struct pl011com *pl011);
static void	plasync_rxint(struct pl011com *pl011, uchar_t lsr);
static void	plasync_msint(struct pl011com *pl011);
static void	plasync_softint(struct pl011com *pl011);

static void	plasync_ioctl(struct plasyncline *plasync, queue_t *q, mblk_t *mp);
static void	plasync_reioctl(void *unit);
static void	plasync_iocdata(queue_t *q, mblk_t *mp);
static void	plasync_restart(void *arg);
static void	plasync_start(struct plasyncline *plasync);
static void	plasync_nstart(struct plasyncline *plasync, int mode);
static void	plasync_resume(struct plasyncline *plasync);
static void	pl011_program(struct pl011com *pl011, int mode);
static void	pl011init(struct pl011com *pl011);
static void	pl011_waiteot(struct pl011com *pl011);
static void	pl011putchar(cons_polledio_arg_t, uchar_t c);
static int	pl011getchar(cons_polledio_arg_t);
static boolean_t	pl011ischar(cons_polledio_arg_t);

static int	pl011mctl(struct pl011com *, int, int);
static int	pl011todm(int, int);
static int	dmtopl011(int);
/*PRINTFLIKE2*/
static void	pl011error(int level, const char *fmt, ...) __KPRINTFLIKE(2);
static void	pl011_parse_mode(dev_info_t *devi, struct pl011com *pl011);
static void	pl011_soft_state_free(struct pl011com *);
static char	*pl011_hw_name(struct pl011com *pl011);
static void	plasync_hold_utbrk(void *arg);
static void	plasync_resume_utbrk(struct plasyncline *plasync);
static void	plasync_dtr_free(struct plasyncline *plasync);
static int	pl011_getproperty(dev_info_t *devi, struct pl011com *pl011,
		    const char *property);
static boolean_t	plasync_flowcontrol_sw_input(struct pl011com *pl011,
			    plasync_flowc_action onoff, int type);
static void	plasync_flowcontrol_sw_output(struct pl011com *pl011,
		    plasync_flowc_action onoff);
static void	plasync_flowcontrol_hw_input(struct pl011com *pl011,
		    plasync_flowc_action onoff, int type);
static void	plasync_flowcontrol_hw_output(struct pl011com *pl011,
		    plasync_flowc_action onoff);

#define	GET_PROP(devi, pname, pflag, pval, plen) \
		(ddi_prop_op(DDI_DEV_T_ANY, (devi), PROP_LEN_AND_VAL_BUF, \
		(pflag), (pname), (caddr_t)(pval), (plen)))

static kmutex_t pl011_glob_lock; /* lock protecting global data manipulation */
static void *pl011_soft_state;

#ifdef	DEBUG
/*
 * Set this to true to make the driver pretend to do a suspend.  Useful
 * for debugging suspend/resume code with a serial debugger.
 */
static boolean_t	pl011_nosuspend = B_FALSE;
#endif


static int baudtable[] = {
	0,	/* 0 baud rate */
	50,	/* 50 baud rate */
	75,	/* 75 baud rate */
	110,	/* 110 baud rate */
	134,	/* 134 baud rate */
	150,	/* 150 baud rate */
	200,	/* 200 baud rate */
	300,	/* 300 baud rate */
	600,	/* 600 baud rate */
	1200,	/* 1200 baud rate */
	1800,	/* 1800 baud rate */
	2400,	/* 2400 baud rate */
	4800,	/* 4800 baud rate */
	9600,	/* 9600 baud rate */
	19200,	/* 19200 baud rate */
	38400,	/* 38400 baud rate */
	57600,	/* 57600 baud rate */
	76800,	/* 76800 baud rate */
	115200,	/* 115200 baud rate */
	153600,	/* 153600 baud rate */
	230400,	/* 230400 baud rate */
	307200,	/* 307200 baud rate */
	460800	/* 460800 baud rate */
};

#define	N_SU_SPEEDS	(sizeof (baudtable)/sizeof (baudtable[0]))

static void
pl011_reset_fifo(struct pl011com *pl011, uint8_t flush)
{
}

static void
pl011_put_char(struct pl011com *pl011, uint8_t val)
{
	union uart_dr reg = {0};
	reg.data = val;
	REG_WRITE(pl011, UARTDR, reg.dw);
}

static boolean_t
pl011_is_busy(struct pl011com *pl011)
{
	union uart_fr reg;
	reg.dw = REG_READ(pl011, UARTFR);
	return !reg.txfe || reg.busy;
}

static boolean_t
pl011_tx_is_ready(struct pl011com *pl011)
{
	union uart_fr reg;
	reg.dw = REG_READ(pl011, UARTFR);
	return reg.txff == 0;
}

static boolean_t
pl011_rx_is_ready(struct pl011com *pl011)
{
	union uart_fr reg;
	reg.dw = REG_READ(pl011, UARTFR);
	return !reg.rxfe;
}

static uint8_t
pl011_get_msr(struct pl011com *pl011)
{
	union uart_fr reg;
	reg.dw = REG_READ(pl011, UARTFR);
	uint8_t ret = 0;
	if (reg.cts)
		ret |= CTS;
	if (reg.dsr)
		ret |= DSR;
	if (reg.dcd)
		ret |= DCD;
	if (reg.ri)
		ret |= RI;
	return ret;
}

static void
pl011_set_mcr(struct pl011com *pl011, uint8_t mcr)
{
	union uart_cr reg;
	reg.dw = REG_READ(pl011, UARTCR);
	reg.dtr = ((mcr & DTR)? 1: 0);
	reg.rts = ((mcr & RTS)? 1: 0);
	reg.out1 = ((mcr & OUT1)? 1: 0);
	reg.out2 = ((mcr & OUT2)? 1: 0);
	reg.lbe = ((mcr & PL011_LOOP)? 1: 0);
	REG_WRITE(pl011, UARTCR, reg.dw);
}

static uint8_t
pl011_get_mcr(struct pl011com *pl011)
{
	union uart_cr reg;
	reg.dw = REG_READ(pl011, UARTCR);
	uint8_t ret = 0;
	if (reg.dtr)
		ret |= DTR;
	if (reg.rts)
		ret |= RTS;
	if (reg.out1)
		ret |= OUT1;
	if (reg.out2)
		ret |= OUT2;
	if (reg.lbe)
		ret |= PL011_LOOP;
	return ret;
}

static void
pl011_set_icr(struct pl011com *pl011, uint8_t icr, uint8_t mask)
{
	union uart_intr reg;
	reg.dw = REG_READ(pl011, UARTIMSC);
	if (mask & RIEN) {
		reg.rx = ((icr & RIEN)? 1: 0);
		//reg.rt = ((icr & RIEN)? 1: 0);
	}
	if (mask & TIEN) {
		reg.tx = ((icr & TIEN)? 1: 0);
	}
	if (mask & MIEN) {
		reg.ri =  ((icr & MIEN)? 1: 0);
		reg.cts = ((icr & MIEN)? 1: 0);
		reg.dcd = ((icr & MIEN)? 1: 0);
		reg.dsr = ((icr & MIEN)? 1: 0);
	}
	REG_WRITE(pl011, UARTIMSC, reg.dw);
}

static uint8_t
pl011_get_icr(struct pl011com *pl011)
{
	union uart_intr reg;
	reg.dw = REG_READ(pl011, UARTIMSC);
	uint8_t ret = 0;
	if (reg.rx)
		ret |= RIEN;
	if (reg.tx)
		ret |= TIEN;
	if (reg.ri || reg.cts || reg.dcd || reg.dsr)
		ret |= MIEN;
	return ret;
}

static uint8_t
pl011_get_lsr(struct pl011com *pl011)
{
	union uart_rsr rsr;
	rsr.dw = REG_READ(pl011, UARTRSR);
	uint8_t ret = 0;
	if (rsr.fe)
		ret |= FRMERR;
	if (rsr.pe)
		ret |= PARERR;
	if (rsr.be)
		ret |= BRKDET;
	if (rsr.oe)
		ret |= OVRRUN;
	REG_WRITE(pl011, UARTECR, 0);

	union uart_fr fr;
	fr.dw = REG_READ(pl011, UARTFR);
	if (fr.txfe) {
		ret |= XHRE;
		if (!fr.busy)
			ret |= XSRE;
	}
	if (!fr.rxfe)
		ret |= RCA;
	return ret;
}

static uint8_t
pl011_get_char(struct pl011com *pl011)
{
	union uart_dr reg;
	reg.dw = REG_READ(pl011, UARTDR);
	return reg.data;
}

static void
pl011_set_lcr(struct pl011com *pl011, uint8_t lcr)
{
	union uart_lcr_h reg;
	reg.dw = REG_READ(pl011, UARTLCR_H);

	reg.pen = ((lcr & PEN)? 1: 0);
	reg.eps = ((lcr & EPS)? 1: 0);

	switch (lcr & (WLS0 | WLS1)) {
	case BITS5: reg.wlen = 0; break;
	case BITS6: reg.wlen = 1; break;
	case BITS7: reg.wlen = 2; break;
	case BITS8: reg.wlen = 3; break;
	}
	reg.stp2 = ((lcr & STB)? 1: 0);
	reg.brk = ((lcr & SETBREAK)? 1: 0);
	REG_WRITE(pl011, UARTLCR_H, reg.dw);
}

static void
pl011_set_break(struct pl011com *pl011, boolean_t on)
{
	union uart_lcr_h reg;
	reg.dw = REG_READ(pl011, UARTLCR_H);
	reg.brk = (on? 1: 0);
	REG_WRITE(pl011, UARTLCR_H, reg.dw);
}

static uint8_t
pl011_get_lcr(struct pl011com *pl011)
{
	union uart_lcr_h reg;
	reg.dw = REG_READ(pl011, UARTLCR_H);

	uint8_t ret = 0;
	if (reg.pen)
		ret |= PEN;
	if (reg.eps)
		ret |= EPS;
	switch (reg.wlen) {
	case 0: ret |= BITS5; break;
	case 1: ret |= BITS6; break;
	case 2: ret |= BITS7; break;
	case 3: ret |= BITS8; break;
	}
	if (reg.stp2)
		ret |= STB;
	if (reg.brk)
		ret |= SETBREAK;
	return ret;
}

static uint8_t
pl011_get_isr(struct pl011com *pl011)
{
	union uart_intr reg;
	reg.dw = REG_READ(pl011, UARTRIS);
	if (reg.fe || reg.pe || reg.be || reg.oe) {
		reg.dw = 0;
		reg.fe = 1;
		reg.pe = 1;
		reg.be = 1;
		reg.oe = 1;
		REG_WRITE(pl011, UARTICR, reg.dw);
		return RSTATUS;
	}
	if (reg.rx) {
		reg.dw = 0;
		reg.rx = 1;
		REG_WRITE(pl011, UARTICR, reg.dw);
		return RxRDY;
	}
	if (reg.rt) {
		reg.dw = 0;
		reg.rt = 1;
		REG_WRITE(pl011, UARTICR, reg.dw);
		return FFTMOUT;
	}
	if (reg.tx) {
		reg.dw = 0;
		reg.tx = 1;
		REG_WRITE(pl011, UARTICR, reg.dw);
		return TxRDY;
	}
	if (reg.ri || reg.cts || reg.dcd || reg.dsr) {
		reg.dw = 0;
		reg.ri = 1;
		reg.cts = 1;
		reg.dcd = 1;
		reg.dsr = 1;
		REG_WRITE(pl011, UARTICR, reg.dw);
		return MSTATUS;
	}
	return NOINTERRUPT;
}

static void
pl011_reset(struct pl011com *pl011)
{
	REG_WRITE(pl011, UARTCR, 0);
	REG_WRITE(pl011, UARTECR, 0);
	REG_WRITE(pl011, UARTIMSC, 0);
	REG_WRITE(pl011, UARTICR, 0xffff);

	union uart_ifls ifls = {0};
	ifls.txiflsel = 2;	// 1/2
	ifls.rxiflsel = 4;	// 7/8
	REG_WRITE(pl011, UARTIFLS, ifls.dw);

	union uart_cr cr = {0};
	cr.uarten = 1;
	cr.txe = 1;
	cr.rxe = 1;
	REG_WRITE(pl011, UARTCR, cr.dw);

	union uart_lcr_h lcr_h = {0};
	lcr_h.fen = 1;
	lcr_h.wlen = 3;
	REG_WRITE(pl011, UARTLCR_H, lcr_h.dw);
}

static void
pl011_set_baud(struct pl011com *pl011, uint8_t bidx)
{
	ASSERT(bidx < N_SU_SPEEDS);
	int baudrate;
	if (bidx == 0)
		baudrate = 115200;
	else
		baudrate = baudtable[bidx];

	uint32_t bauddiv = (pl011->pl011_clock * 4 + baudrate / 2) / baudrate;

	uint32_t cr = REG_READ(pl011, UARTCR);
	REG_WRITE(pl011, UARTCR, 0);

	union uart_ibrd ibrd = {0};
	union uart_fbrd fbrd = {0};
	ibrd.divint = bauddiv >> 6;
	fbrd.divfrac = bauddiv & 0x3f;

	REG_WRITE(pl011, UARTIBRD, ibrd.dw);
	REG_WRITE(pl011, UARTFBRD, fbrd.dw);
	REG_WRITE(pl011, UARTCR, cr);
}

static int pl011rsrv(queue_t *q);
static int pl011open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr);
static int pl011close(queue_t *q, int flag, cred_t *credp);
static int pl011wputdo(queue_t *q, mblk_t *mp, boolean_t);
static int pl011wput(queue_t *q, mblk_t *mp);

struct module_info pl011_info = {
	0,
	"pl011",
	0,
	INFPSZ,
	4096,
	128
};

static struct qinit pl011_rint = {
	putq,
	pl011rsrv,
	pl011open,
	pl011close,
	NULL,
	&pl011_info,
	NULL
};

static struct qinit pl011_wint = {
	pl011wput,
	NULL,
	NULL,
	NULL,
	NULL,
	&pl011_info,
	NULL
};

struct streamtab pl011_str_info = {
	&pl011_rint,
	&pl011_wint,
	NULL,
	NULL
};

static int pl011info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int pl011probe(dev_info_t *);
static int pl011attach(dev_info_t *, ddi_attach_cmd_t);
static int pl011detach(dev_info_t *, ddi_detach_cmd_t);
static int pl011quiesce(dev_info_t *);

static 	struct cb_ops cb_pl011_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&pl011_str_info,		/* cb_stream */
	D_MP			/* cb_flag */
};

struct dev_ops pl011_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	pl011info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	pl011probe,		/* devo_probe */
	pl011attach,		/* devo_attach */
	pl011detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_pl011_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* power */
	pl011quiesce,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"PL011 driver",
	&pl011_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int i;

	i = ddi_soft_state_init(&pl011_soft_state, sizeof (struct pl011com), 2);
	if (i == 0) {
		mutex_init(&pl011_glob_lock, NULL, MUTEX_DRIVER, NULL);
		if ((i = mod_install(&modlinkage)) != 0) {
			mutex_destroy(&pl011_glob_lock);
			ddi_soft_state_fini(&pl011_soft_state);
		} else {
			DEBUGCONT2(PL011_DEBUG_INIT, "%s, debug = %x\n",
			    modldrv.drv_linkinfo, debug);
		}
	}
	return (i);
}

int
_fini(void)
{
	int i;

	if ((i = mod_remove(&modlinkage)) == 0) {
		DEBUGCONT1(PL011_DEBUG_INIT, "%s unloading\n",
		    modldrv.drv_linkinfo);
		ASSERT(max_pl011_instance == -1);
		mutex_destroy(&pl011_glob_lock);
		ddi_soft_state_fini(&pl011_soft_state);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

void
plasync_put_suspq(struct pl011com *pl011, mblk_t *mp)
{
	struct plasyncline *plasync = pl011->pl011_priv;

	ASSERT(mutex_owned(&pl011->pl011_excl));

	if (plasync->plasync_suspqf == NULL)
		plasync->plasync_suspqf = mp;
	else
		plasync->plasync_suspqb->b_next = mp;

	plasync->plasync_suspqb = mp;
}

static mblk_t *
plasync_get_suspq(struct pl011com *pl011)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	mblk_t *mp;

	ASSERT(mutex_owned(&pl011->pl011_excl));

	if ((mp = plasync->plasync_suspqf) != NULL) {
		plasync->plasync_suspqf = mp->b_next;
		mp->b_next = NULL;
	} else {
		plasync->plasync_suspqb = NULL;
	}
	return (mp);
}

static void
plasync_process_suspq(struct pl011com *pl011)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	mblk_t *mp;

	ASSERT(mutex_owned(&pl011->pl011_excl));

	while ((mp = plasync_get_suspq(pl011)) != NULL) {
		queue_t *q;

		q = plasync->plasync_ttycommon.t_writeq;
		ASSERT(q != NULL);
		mutex_exit(&pl011->pl011_excl);
		(void) pl011wputdo(q, mp, B_FALSE);
		mutex_enter(&pl011->pl011_excl);
	}
	plasync->plasync_flags &= ~PLASYNC_DDI_SUSPENDED;
	cv_broadcast(&plasync->plasync_flags_cv);
}

static int
pl011detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct pl011com *pl011;
	struct plasyncline *plasync;

	instance = ddi_get_instance(devi);	/* find out which unit */

	pl011 = ddi_get_soft_state(pl011_soft_state, instance);
	if (pl011 == NULL)
		return (DDI_FAILURE);
	plasync = pl011->pl011_priv;

	switch (cmd) {
	case DDI_DETACH:
		DEBUGNOTE2(PL011_DEBUG_INIT, "pl011%d: %s shutdown.",
		    instance, pl011_hw_name(pl011));

		/* cancel DTR hold timeout */
		if (plasync->plasync_dtrtid != 0) {
			(void) untimeout(plasync->plasync_dtrtid);
			plasync->plasync_dtrtid = 0;
		}

		/* remove all minor device node(s) for this device */
		ddi_remove_minor_node(devi, NULL);

		mutex_destroy(&pl011->pl011_excl);
		mutex_destroy(&pl011->pl011_excl_hi);
		cv_destroy(&plasync->plasync_flags_cv);
		ddi_remove_intr(devi, 0, pl011->pl011_iblock);
		ddi_regs_map_free(&pl011->pl011_iohandle);
		ddi_remove_softintr(pl011->pl011_softintr_id);
		mutex_destroy(&pl011->pl011_soft_lock);
		pl011_soft_state_free(pl011);
		DEBUGNOTE1(PL011_DEBUG_INIT, "pl011%d: shutdown complete",
		    instance);
		break;
	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * pl011probe
 * We don't bother probing for the hardware, as since Solaris 2.6, device
 * nodes are only created for auto-detected hardware or nodes explicitly
 * created by the user, e.g. via the DCA. However, we should check the
 * device node is at least vaguely usable, i.e. we have a block of 8 i/o
 * ports. This prevents attempting to attach to bogus serial ports which
 * some BIOSs still partially report when they are disabled in the BIOS.
 */
static int
pl011probe(dev_info_t *dip)
{
	char buf[80];
	pnode_t node = ddi_get_nodeid(dip);
	if (node < 0)
		return (DDI_PROBE_FAILURE);

	int len = prom_getproplen(node, "status");
	if (len <= 0)
		return (DDI_PROBE_SUCCESS);
	if (len >= sizeof(buf))
		return (DDI_PROBE_FAILURE);

	prom_getprop(node, "status", (caddr_t)buf);
	if (strcmp(buf, "ok") != 0)
		return (DDI_PROBE_FAILURE);

	return (DDI_PROBE_SUCCESS);
}

static int
pl011attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	int mcr;
	int ret;
	int i;
	struct pl011com *pl011;
	char name[PL011_MINOR_LEN];
	int status;
	static ddi_device_acc_attr_t ioattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
	};

	instance = ddi_get_instance(devi);	/* find out which unit */

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	uint_t uart_clock = 24000000;
	struct prom_hwclock hwclock;
	if (prom_get_clock_by_name(ddi_get_nodeid(devi), "uartclk", &hwclock) == 0) {
		if (prom_getproplen(hwclock.node, "clock-frequency") == sizeof(uint_t)) {
			prom_getprop(hwclock.node, "clock-frequency", (caddr_t)&uart_clock);
			uart_clock = ntohl(uart_clock);
		}
	}

	ret = ddi_soft_state_zalloc(pl011_soft_state, instance);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);
	pl011 = ddi_get_soft_state(pl011_soft_state, instance);
	ASSERT(pl011 != NULL);	/* can't fail - we only just allocated it */
	pl011->pl011_unit = instance;
	mutex_enter(&pl011_glob_lock);
	if (instance > max_pl011_instance)
		max_pl011_instance = instance;
	mutex_exit(&pl011_glob_lock);

	pl011->pl011_clock = uart_clock;

	if (ddi_regs_map_setup(devi, PL011_REGISTER_FILE_NO, (caddr_t *)&pl011->pl011_ioaddr,
	    PL011_REGOFFSET, PL011_REGISTER_LEN, &ioattr, &pl011->pl011_iohandle)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pl011%d: could not map UART registers @ %p",
		    instance, (void *)pl011->pl011_ioaddr);

		pl011_soft_state_free(pl011);
		return (DDI_FAILURE);
	}

	DEBUGCONT2(PL011_DEBUG_INIT, "pl011%dattach: UART @ %p\n",
	    instance, (void *)pl011->pl011_ioaddr);

	pl011->pl011_com_port = instance + 1;

	/*
	 * It appears that there was plasync hardware that on reset
	 * did not clear ICR.  Hence when we get to
	 * ddi_get_iblock_cookie below, this hardware would cause
	 * the system to hang if there was input available.
	 */

	pl011_set_icr(pl011, 0, 0xff);

	/* establish default usage */
	pl011->pl011_mcr |= RTS|DTR;		/* do use RTS/DTR after open */
	pl011->pl011_lcr = STOP1|BITS8;		/* default to 1 stop 8 bits */
	pl011->pl011_bidx = PL011_DEFAULT_BAUD;	/* default to 9600  */
#ifdef DEBUG
	pl011->pl011_msint_cnt = 0;			/* # of times in plasync_msint */
#endif
	mcr = 0;				/* don't enable until open */

	/*
	 * For motherboard ports, emulate tty eeprom properties.
	 * Actually, we can't tell if a port is motherboard or not,
	 * so for "motherboard ports", read standard DOS COM ports.
	 */
	switch (pl011_getproperty(devi, pl011, "ignore-cd")) {
	case 0:				/* *-ignore-cd=False */
		DEBUGCONT1(PL011_DEBUG_MODEM,
		    "pl011%dattach: clear PL011_IGNORE_CD\n", instance);
		pl011->pl011_flags &= ~PL011_IGNORE_CD; /* wait for cd */
		break;
	case 1:				/* *-ignore-cd=True */
		/*FALLTHRU*/
	default:			/* *-ignore-cd not defined */
		/*
		 * We set rather silly defaults of soft carrier on
		 * and DTR/RTS raised here because it might be that
		 * one of the motherboard ports is the system console.
		 */
		DEBUGCONT1(PL011_DEBUG_MODEM,
		    "pl011%dattach: set PL011_IGNORE_CD, set RTS & DTR\n",
		    instance);
		mcr = pl011->pl011_mcr;		/* rts/dtr on */
		pl011->pl011_flags |= PL011_IGNORE_CD;	/* ignore cd */
		break;
	}

	/* Property for not raising DTR/RTS */
	switch (pl011_getproperty(devi, pl011, "rts-dtr-off")) {
	case 0:				/* *-rts-dtr-off=False */
		pl011->pl011_flags |= PL011_RTS_DTR_OFF;	/* OFF */
		mcr = pl011->pl011_mcr;		/* rts/dtr on */
		DEBUGCONT1(PL011_DEBUG_MODEM, "pl011%dattach: "
		    "PL011_RTS_DTR_OFF set and DTR & RTS set\n",
		    instance);
		break;
	case 1:				/* *-rts-dtr-off=True */
		/*FALLTHRU*/
	default:			/* *-rts-dtr-off undefined */
		break;
	}

	/* Parse property for tty modes */
	pl011_parse_mode(devi, pl011);

	/*
	 * Get icookie for mutexes initialization
	 */
	if ((ddi_get_iblock_cookie(devi, 0, &pl011->pl011_iblock) !=
	    DDI_SUCCESS) ||
	    (ddi_get_soft_iblock_cookie(devi, DDI_SOFTINT_MED,
	    &pl011->pl011_soft_iblock) != DDI_SUCCESS)) {
		ddi_regs_map_free(&pl011->pl011_iohandle);
		cmn_err(CE_CONT,
		    "pl011%d: could not hook interrupt for UART @ %p\n",
		    instance, (void *)pl011->pl011_ioaddr);
		pl011_soft_state_free(pl011);
		return (DDI_FAILURE);
	}

	/*
	 * Initialize mutexes before accessing the hardware
	 */
	mutex_init(&pl011->pl011_soft_lock, NULL, MUTEX_DRIVER,
	    (void *)pl011->pl011_soft_iblock);
	mutex_init(&pl011->pl011_excl, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pl011->pl011_excl_hi, NULL, MUTEX_DRIVER,
	    (void *)pl011->pl011_iblock);
	mutex_init(&pl011->pl011_soft_sr, NULL, MUTEX_DRIVER,
	    (void *)pl011->pl011_soft_iblock);
	mutex_enter(&pl011->pl011_excl);
	mutex_enter(&pl011->pl011_excl_hi);

	/* Make UART type visible in device tree for prtconf, etc */
	dev_t dev = makedevice(DDI_MAJOR_T_UNKNOWN, pl011->pl011_unit);
	ddi_prop_update_string(dev, devi, "uart", pl011_hw_name(pl011));

	pl011_reset(pl011);

	/* Set the baud rate to 9600 */
	pl011_set_baud(pl011, pl011->pl011_bidx);
	pl011_set_lcr(pl011, pl011->pl011_lcr);
	pl011_set_mcr(pl011, mcr);

	mutex_exit(&pl011->pl011_excl_hi);
	mutex_exit(&pl011->pl011_excl);

	/*
	 * Set up the other components of the pl011com structure for this port.
	 */
	pl011->pl011_dip = devi;

	/*
	 * Install per instance software interrupt handler.
	 */
	if (ddi_add_softintr(devi, DDI_SOFTINT_MED,
	    &(pl011->pl011_softintr_id), NULL, 0, pl011softintr,
	    (caddr_t)pl011) != DDI_SUCCESS) {
		mutex_destroy(&pl011->pl011_soft_lock);
		mutex_destroy(&pl011->pl011_excl);
		mutex_destroy(&pl011->pl011_excl_hi);
		ddi_regs_map_free(&pl011->pl011_iohandle);
		cmn_err(CE_CONT,
		    "Can not set soft interrupt for PL011 driver\n");
		pl011_soft_state_free(pl011);
		return (DDI_FAILURE);
	}

	mutex_enter(&pl011->pl011_excl);
	mutex_enter(&pl011->pl011_excl_hi);

	/*
	 * Install interrupt handler for this device.
	 */
	if (ddi_add_intr(devi, 0, NULL, 0, pl011intr,
	    (caddr_t)pl011) != DDI_SUCCESS) {
		mutex_exit(&pl011->pl011_excl_hi);
		mutex_exit(&pl011->pl011_excl);
		ddi_remove_softintr(pl011->pl011_softintr_id);
		mutex_destroy(&pl011->pl011_soft_lock);
		mutex_destroy(&pl011->pl011_excl);
		mutex_destroy(&pl011->pl011_excl_hi);
		ddi_regs_map_free(&pl011->pl011_iohandle);
		cmn_err(CE_CONT,
		    "Can not set device interrupt for PL011 driver\n");
		pl011_soft_state_free(pl011);
		return (DDI_FAILURE);
	}

	mutex_exit(&pl011->pl011_excl_hi);
	mutex_exit(&pl011->pl011_excl);

	pl011init(pl011);	/* initialize the plasyncline structure */

	/* create minor device nodes for this device */
	/*
	 * For DOS COM ports, add letter suffix so
	 * devfsadm can create correct link names.
	 */
	name[0] = pl011->pl011_com_port + 'a' - 1;
	name[1] = '\0';
	status = ddi_create_minor_node(devi, name, S_IFCHR, instance,
	    pl011->pl011_com_port != 0 ? DDI_NT_SERIAL_MB : DDI_NT_SERIAL, 0);
	if (status == DDI_SUCCESS) {
		(void) strcat(name, ",cu");
		status = ddi_create_minor_node(devi, name, S_IFCHR,
		    OUTLINE | instance,
		    pl011->pl011_com_port != 0 ? DDI_NT_SERIAL_MB_DO :
		    DDI_NT_SERIAL_DO, 0);
	}

	if (status != DDI_SUCCESS) {
		struct plasyncline *plasync = pl011->pl011_priv;

		ddi_remove_minor_node(devi, NULL);
		ddi_remove_intr(devi, 0, pl011->pl011_iblock);
		ddi_remove_softintr(pl011->pl011_softintr_id);
		mutex_destroy(&pl011->pl011_soft_lock);
		mutex_destroy(&pl011->pl011_excl);
		mutex_destroy(&pl011->pl011_excl_hi);
		cv_destroy(&plasync->plasync_flags_cv);
		ddi_regs_map_free(&pl011->pl011_iohandle);
		pl011_soft_state_free(pl011);
		return (DDI_FAILURE);
	}

	/*
	 * Fill in the polled I/O structure.
	 */
	pl011->polledio.cons_polledio_version = CONSPOLLEDIO_V0;
	pl011->polledio.cons_polledio_argument = (cons_polledio_arg_t)pl011;
	pl011->polledio.cons_polledio_putchar = pl011putchar;
	pl011->polledio.cons_polledio_getchar = pl011getchar;
	pl011->polledio.cons_polledio_ischar = pl011ischar;
	pl011->polledio.cons_polledio_enter = NULL;
	pl011->polledio.cons_polledio_exit = NULL;

	ddi_report_dev(devi);
	DEBUGCONT1(PL011_DEBUG_INIT, "pl011%dattach: done\n", instance);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pl011info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
	void **result)
{
	dev_t dev = (dev_t)arg;
	int instance, error;
	struct pl011com *pl011;

	instance = UNIT(dev);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		pl011 = ddi_get_soft_state(pl011_soft_state, instance);
		if ((pl011 == NULL) || (pl011->pl011_dip == NULL))
			error = DDI_FAILURE;
		else {
			*result = (void *) pl011->pl011_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/* pl011_getproperty -- walk through all name variants until we find a match */

static int
pl011_getproperty(dev_info_t *devi, struct pl011com *pl011, const char *property)
{
	int len;
	int ret;
	char letter = pl011->pl011_com_port + 'a' - 1;	/* for ttya */
	char number = pl011->pl011_com_port + '0';		/* for COM1 */
	char val[40];
	char name[40];

	/* Property for ignoring DCD */
	(void) sprintf(name, "tty%c-%s", letter, property);
	len = sizeof (val);
	ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "com%c-%s", number, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "tty0%c-%s", number, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "port-%c-%s", letter, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS)
		return (-1);		/* property non-existant */
	if (val[0] == 'f' || val[0] == 'F' || val[0] == '0')
		return (0);		/* property false/0 */
	return (1);			/* property true/!0 */
}

/* pl011_soft_state_free - local wrapper for ddi_soft_state_free(9F) */

static void
pl011_soft_state_free(struct pl011com *pl011)
{
	mutex_enter(&pl011_glob_lock);
	/* If we were the max_pl011_instance, work out new value */
	if (pl011->pl011_unit == max_pl011_instance) {
		while (--max_pl011_instance >= 0) {
			if (ddi_get_soft_state(pl011_soft_state,
			    max_pl011_instance) != NULL)
				break;
		}
	}
	mutex_exit(&pl011_glob_lock);

	if (pl011->pl011_priv != NULL) {
		kmem_free(pl011->pl011_priv, sizeof (struct plasyncline));
		pl011->pl011_priv = NULL;
	}
	ddi_soft_state_free(pl011_soft_state, pl011->pl011_unit);
}

static char *
pl011_hw_name(struct pl011com *pl011)
{
	return "PL011";
}

/*
 * pl011init() initializes the TTY protocol-private data for this channel
 * before enabling the interrupts.
 */
static void
pl011init(struct pl011com *pl011)
{
	struct plasyncline *plasync;

	pl011->pl011_priv = kmem_zalloc(sizeof (struct plasyncline), KM_SLEEP);
	plasync = pl011->pl011_priv;
	mutex_enter(&pl011->pl011_excl);
	plasync->plasync_common = pl011;
	cv_init(&plasync->plasync_flags_cv, NULL, CV_DRIVER, NULL);
	mutex_exit(&pl011->pl011_excl);
}

/*ARGSUSED3*/
static int
pl011open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	struct pl011com	*pl011;
	struct plasyncline *plasync;
	int		mcr;
	int		unit;
	int 		len;
	struct termios 	*termiosp;

	unit = UNIT(*dev);
	DEBUGCONT1(PL011_DEBUG_CLOSE, "pl011%dopen\n", unit);
	pl011 = ddi_get_soft_state(pl011_soft_state, unit);
	if (pl011 == NULL)
		return (ENXIO);		/* unit not configured */
	plasync = pl011->pl011_priv;
	mutex_enter(&pl011->pl011_excl);

again:
	mutex_enter(&pl011->pl011_excl_hi);

	/*
	 * Block waiting for carrier to come up, unless this is a no-delay open.
	 */
	if (!(plasync->plasync_flags & PLASYNC_ISOPEN)) {
		/*
		 * Set the default termios settings (cflag).
		 * Others are set in ldterm.
		 */
		mutex_exit(&pl011->pl011_excl_hi);

		if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(),
		    0, "ttymodes",
		    (caddr_t)&termiosp, &len) == DDI_PROP_SUCCESS &&
		    len == sizeof (struct termios)) {
			plasync->plasync_ttycommon.t_cflag = termiosp->c_cflag;
			kmem_free(termiosp, len);
		} else
			cmn_err(CE_WARN,
			    "pl011: couldn't get ttymodes property!");
		mutex_enter(&pl011->pl011_excl_hi);

		/* eeprom mode support - respect properties */
		if (pl011->pl011_cflag)
			plasync->plasync_ttycommon.t_cflag = pl011->pl011_cflag;

		plasync->plasync_ttycommon.t_iflag = 0;
		plasync->plasync_ttycommon.t_iocpending = NULL;
		plasync->plasync_ttycommon.t_size.ws_row = 0;
		plasync->plasync_ttycommon.t_size.ws_col = 0;
		plasync->plasync_ttycommon.t_size.ws_xpixel = 0;
		plasync->plasync_ttycommon.t_size.ws_ypixel = 0;
		plasync->plasync_dev = *dev;
		plasync->plasync_wbufcid = 0;

		plasync->plasync_startc = CSTART;
		plasync->plasync_stopc = CSTOP;
		pl011_program(pl011, PL011_INIT);
	} else
		if ((plasync->plasync_ttycommon.t_flags & TS_XCLUDE) &&
		    secpolicy_excl_open(cr) != 0) {
		mutex_exit(&pl011->pl011_excl_hi);
		mutex_exit(&pl011->pl011_excl);
		return (EBUSY);
	} else if ((*dev & OUTLINE) && !(plasync->plasync_flags & PLASYNC_OUT)) {
		mutex_exit(&pl011->pl011_excl_hi);
		mutex_exit(&pl011->pl011_excl);
		return (EBUSY);
	}

	if (*dev & OUTLINE)
		plasync->plasync_flags |= PLASYNC_OUT;

	/* Raise DTR on every open, but delay if it was just lowered. */
	while (plasync->plasync_flags & PLASYNC_DTR_DELAY) {
		DEBUGCONT1(PL011_DEBUG_MODEM,
		    "pl011%dopen: waiting for the PLASYNC_DTR_DELAY to be clear\n",
		    unit);
		mutex_exit(&pl011->pl011_excl_hi);
		if (cv_wait_sig(&plasync->plasync_flags_cv,
		    &pl011->pl011_excl) == 0) {
			DEBUGCONT1(PL011_DEBUG_MODEM,
			    "pl011%dopen: interrupted by signal, exiting\n",
			    unit);
			mutex_exit(&pl011->pl011_excl);
			return (EINTR);
		}
		mutex_enter(&pl011->pl011_excl_hi);
	}

	mcr = pl011_get_mcr(pl011);
	pl011_set_mcr(pl011,
	    mcr|(pl011->pl011_mcr&DTR));

	DEBUGCONT3(PL011_DEBUG_INIT,
	    "pl011%dopen: \"Raise DTR on every open\": make mcr = %x, "
	    "make TS_SOFTCAR = %s\n",
	    unit, mcr|(pl011->pl011_mcr&DTR),
	    (pl011->pl011_flags & PL011_IGNORE_CD) ? "ON" : "OFF");

	if (pl011->pl011_flags & PL011_IGNORE_CD) {
		DEBUGCONT1(PL011_DEBUG_MODEM,
		    "pl011%dopen: PL011_IGNORE_CD set, set TS_SOFTCAR\n",
		    unit);
		plasync->plasync_ttycommon.t_flags |= TS_SOFTCAR;
	}
	else
		plasync->plasync_ttycommon.t_flags &= ~TS_SOFTCAR;

	/*
	 * Check carrier.
	 */
	pl011->pl011_msr = pl011_get_msr(pl011);
	DEBUGCONT3(PL011_DEBUG_INIT, "pl011%dopen: TS_SOFTCAR is %s, "
	    "MSR & DCD is %s\n",
	    unit,
	    (plasync->plasync_ttycommon.t_flags & TS_SOFTCAR) ? "set" : "clear",
	    (pl011->pl011_msr & DCD) ? "set" : "clear");

	if (pl011->pl011_msr & DCD)
		plasync->plasync_flags |= PLASYNC_CARR_ON;
	else
		plasync->plasync_flags &= ~PLASYNC_CARR_ON;
	mutex_exit(&pl011->pl011_excl_hi);

	/*
	 * If FNDELAY and FNONBLOCK are clear, block until carrier up.
	 * Quit on interrupt.
	 */
	if (!(flag & (FNDELAY|FNONBLOCK)) &&
	    !(plasync->plasync_ttycommon.t_cflag & CLOCAL)) {
		if ((!(plasync->plasync_flags & (PLASYNC_CARR_ON|PLASYNC_OUT)) &&
		    !(plasync->plasync_ttycommon.t_flags & TS_SOFTCAR)) ||
		    ((plasync->plasync_flags & PLASYNC_OUT) &&
		    !(*dev & OUTLINE))) {
			plasync->plasync_flags |= PLASYNC_WOPEN;
			if (cv_wait_sig(&plasync->plasync_flags_cv,
			    &pl011->pl011_excl) == B_FALSE) {
				plasync->plasync_flags &= ~PLASYNC_WOPEN;
				mutex_exit(&pl011->pl011_excl);
				return (EINTR);
			}
			plasync->plasync_flags &= ~PLASYNC_WOPEN;
			goto again;
		}
	} else if ((plasync->plasync_flags & PLASYNC_OUT) && !(*dev & OUTLINE)) {
		mutex_exit(&pl011->pl011_excl);
		return (EBUSY);
	}

	plasync->plasync_ttycommon.t_readq = rq;
	plasync->plasync_ttycommon.t_writeq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (caddr_t)plasync;
	mutex_exit(&pl011->pl011_excl);
	/*
	 * Caution here -- qprocson sets the pointers that are used by canput
	 * called by plasync_softint.  PLASYNC_ISOPEN must *not* be set until those
	 * pointers are valid.
	 */
	qprocson(rq);
	plasync->plasync_flags |= PLASYNC_ISOPEN;
	plasync->plasync_polltid = 0;
	DEBUGCONT1(PL011_DEBUG_INIT, "pl011%dopen: done\n", unit);
	return (0);
}

static void
plasync_progress_check(void *arg)
{
	struct plasyncline *plasync = arg;
	struct pl011com	 *pl011 = plasync->plasync_common;
	mblk_t *bp;

	/*
	 * We define "progress" as either waiting on a timed break or delay, or
	 * having had at least one transmitter interrupt.  If none of these are
	 * true, then just terminate the output and wake up that close thread.
	 */
	mutex_enter(&pl011->pl011_excl);
	mutex_enter(&pl011->pl011_excl_hi);
	if (!(plasync->plasync_flags & (PLASYNC_BREAK|PLASYNC_DELAY|PLASYNC_PROGRESS))) {
		plasync->plasync_ocnt = 0;
		plasync->plasync_flags &= ~PLASYNC_BUSY;
		plasync->plasync_timer = 0;
		bp = plasync->plasync_xmitblk;
		plasync->plasync_xmitblk = NULL;
		mutex_exit(&pl011->pl011_excl_hi);
		if (bp != NULL)
			freeb(bp);
		/*
		 * Since this timer is running, we know that we're in exit(2).
		 * That means that the user can't possibly be waiting on any
		 * valid ioctl(2) completion anymore, and we should just flush
		 * everything.
		 */
		flushq(plasync->plasync_ttycommon.t_writeq, FLUSHALL);
		cv_broadcast(&plasync->plasync_flags_cv);
	} else {
		plasync->plasync_flags &= ~PLASYNC_PROGRESS;
		plasync->plasync_timer = timeout(plasync_progress_check, plasync,
		    drv_usectohz(pl011_drain_check));
		mutex_exit(&pl011->pl011_excl_hi);
	}
	mutex_exit(&pl011->pl011_excl);
}

/*
 * Release DTR so that pl011open() can raise it.
 */
static void
plasync_dtr_free(struct plasyncline *plasync)
{
	struct pl011com *pl011 = plasync->plasync_common;

	DEBUGCONT0(PL011_DEBUG_MODEM,
	    "plasync_dtr_free, clearing PLASYNC_DTR_DELAY\n");
	mutex_enter(&pl011->pl011_excl);
	plasync->plasync_flags &= ~PLASYNC_DTR_DELAY;
	plasync->plasync_dtrtid = 0;
	cv_broadcast(&plasync->plasync_flags_cv);
	mutex_exit(&pl011->pl011_excl);
}

/*
 * Close routine.
 */
/*ARGSUSED2*/
static int
pl011close(queue_t *q, int flag, cred_t *credp)
{
	struct plasyncline *plasync;
	struct pl011com	 *pl011;
	int icr, lcr;
#ifdef DEBUG
	int instance;
#endif

	plasync = (struct plasyncline *)q->q_ptr;
	ASSERT(plasync != NULL);
#ifdef DEBUG
	instance = UNIT(plasync->plasync_dev);
	DEBUGCONT1(PL011_DEBUG_CLOSE, "pl011%dclose\n", instance);
#endif
	pl011 = plasync->plasync_common;

	mutex_enter(&pl011->pl011_excl);
	plasync->plasync_flags |= PLASYNC_CLOSING;

	/*
	 * Turn off PPS handling early to avoid events occuring during
	 * close.  Also reset the DCD edge monitoring bit.
	 */
	mutex_enter(&pl011->pl011_excl_hi);
	pl011->pl011_flags &= ~(PL011_PPS | PL011_PPS_EDGE);
	mutex_exit(&pl011->pl011_excl_hi);

	/*
	 * There are two flavors of break -- timed (M_BREAK or TCSBRK) and
	 * untimed (TIOCSBRK).  For the timed case, these are enqueued on our
	 * write queue and there's a timer running, so we don't have to worry
	 * about them.  For the untimed case, though, the user obviously made a
	 * mistake, because these are handled immediately.  We'll terminate the
	 * break now and honor his implicit request by discarding the rest of
	 * the data.
	 */
	if (plasync->plasync_flags & PLASYNC_OUT_SUSPEND) {
		if (plasync->plasync_utbrktid != 0) {
			(void) untimeout(plasync->plasync_utbrktid);
			plasync->plasync_utbrktid = 0;
		}
		mutex_enter(&pl011->pl011_excl_hi);
		pl011_set_break(pl011, B_FALSE);
		mutex_exit(&pl011->pl011_excl_hi);
		plasync->plasync_flags &= ~PLASYNC_OUT_SUSPEND;
		goto nodrain;
	}

	/*
	 * If the user told us not to delay the close ("non-blocking"), then
	 * don't bother trying to drain.
	 *
	 * If the user did M_STOP (PLASYNC_STOPPED), there's no hope of ever
	 * getting an M_START (since these messages aren't enqueued), and the
	 * only other way to clear the stop condition is by loss of DCD, which
	 * would discard the queue data.  Thus, we drop the output data if
	 * PLASYNC_STOPPED is set.
	 */
	if ((flag & (FNDELAY|FNONBLOCK)) ||
	    (plasync->plasync_flags & PLASYNC_STOPPED)) {
		goto nodrain;
	}

	/*
	 * If there's any pending output, then we have to try to drain it.
	 * There are two main cases to be handled:
	 *	- called by close(2): need to drain until done or until
	 *	  a signal is received.  No timeout.
	 *	- called by exit(2): need to drain while making progress
	 *	  or until a timeout occurs.  No signals.
	 *
	 * If we can't rely on receiving a signal to get us out of a hung
	 * session, then we have to use a timer.  In this case, we set a timer
	 * to check for progress in sending the output data -- all that we ask
	 * (at each interval) is that there's been some progress made.  Since
	 * the interrupt routine grabs buffers from the write queue, we can't
	 * trust changes in plasync_ocnt.  Instead, we use a progress flag.
	 *
	 * Note that loss of carrier will cause the output queue to be flushed,
	 * and we'll wake up again and finish normally.
	 */
	if (!ddi_can_receive_sig() && pl011_drain_check != 0) {
		plasync->plasync_flags &= ~PLASYNC_PROGRESS;
		plasync->plasync_timer = timeout(plasync_progress_check, plasync,
		    drv_usectohz(pl011_drain_check));
	}
	while (plasync->plasync_ocnt > 0 ||
	    plasync->plasync_ttycommon.t_writeq->q_first != NULL ||
	    (plasync->plasync_flags & (PLASYNC_BUSY|PLASYNC_BREAK|PLASYNC_DELAY))) {
		if (cv_wait_sig(&plasync->plasync_flags_cv, &pl011->pl011_excl) == 0)
			break;
	}
	if (plasync->plasync_timer != 0) {
		(void) untimeout(plasync->plasync_timer);
		plasync->plasync_timer = 0;
	}

nodrain:
	plasync->plasync_ocnt = 0;
	if (plasync->plasync_xmitblk != NULL)
		freeb(plasync->plasync_xmitblk);
	plasync->plasync_xmitblk = NULL;

	/*
	 * If line has HUPCL set or is incompletely opened fix up the modem
	 * lines.
	 */
	DEBUGCONT1(PL011_DEBUG_MODEM, "pl011%dclose: next check HUPCL flag\n",
	    instance);
	mutex_enter(&pl011->pl011_excl_hi);
	if ((plasync->plasync_ttycommon.t_cflag & HUPCL) ||
	    (plasync->plasync_flags & PLASYNC_WOPEN)) {
		DEBUGCONT3(PL011_DEBUG_MODEM,
		    "pl011%dclose: HUPCL flag = %x, PLASYNC_WOPEN flag = %x\n",
		    instance,
		    plasync->plasync_ttycommon.t_cflag & HUPCL,
		    plasync->plasync_ttycommon.t_cflag & PLASYNC_WOPEN);
		plasync->plasync_flags |= PLASYNC_DTR_DELAY;

		/* turn off DTR, RTS but NOT interrupt to 386 */
		if (pl011->pl011_flags & (PL011_IGNORE_CD|PL011_RTS_DTR_OFF)) {
			DEBUGCONT3(PL011_DEBUG_MODEM,
			    "pl011%dclose: PL011_IGNORE_CD flag = %x, "
			    "PL011_RTS_DTR_OFF flag = %x\n",
			    instance,
			    pl011->pl011_flags & PL011_IGNORE_CD,
			    pl011->pl011_flags & PL011_RTS_DTR_OFF);

			pl011_set_mcr(pl011, pl011->pl011_mcr|OUT2);
		} else {
			DEBUGCONT1(PL011_DEBUG_MODEM,
			    "pl011%dclose: Dropping DTR and RTS\n", instance);
			pl011_set_mcr(pl011, pl011->pl011_mcr|OUT2);
		}
		plasync->plasync_dtrtid =
		    timeout((void (*)())plasync_dtr_free,
		    (caddr_t)plasync, drv_usectohz(pl011_min_dtr_low));
	}
	/*
	 * If nobody's using it now, turn off receiver interrupts.
	 */
	if ((plasync->plasync_flags & (PLASYNC_WOPEN|PLASYNC_ISOPEN)) == 0) {
		pl011_set_icr(pl011, 0, RIEN);
	}
	mutex_exit(&pl011->pl011_excl_hi);
out:
	ttycommon_close(&plasync->plasync_ttycommon);

	/*
	 * Cancel outstanding "bufcall" request.
	 */
	if (plasync->plasync_wbufcid != 0) {
		unbufcall(plasync->plasync_wbufcid);
		plasync->plasync_wbufcid = 0;
	}

	/* Note that qprocsoff can't be done until after interrupts are off */
	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	plasync->plasync_ttycommon.t_readq = NULL;
	plasync->plasync_ttycommon.t_writeq = NULL;

	/*
	 * Clear out device state, except persistant device property flags.
	 */
	plasync->plasync_flags &= (PLASYNC_DTR_DELAY|PL011_RTS_DTR_OFF);
	cv_broadcast(&plasync->plasync_flags_cv);
	mutex_exit(&pl011->pl011_excl);

	DEBUGCONT1(PL011_DEBUG_CLOSE, "pl011%dclose: done\n", instance);
	return (0);
}

static boolean_t
pl011_isbusy(struct pl011com *pl011)
{
	struct plasyncline *plasync;

	DEBUGCONT0(PL011_DEBUG_EOT, "pl011_isbusy\n");
	plasync = pl011->pl011_priv;
	ASSERT(mutex_owned(&pl011->pl011_excl));
	ASSERT(mutex_owned(&pl011->pl011_excl_hi));
/*
 * XXXX this should be recoded
 */
	return ((plasync->plasync_ocnt > 0) || pl011_is_busy(pl011));
}

static void
pl011_waiteot(struct pl011com *pl011)
{
	/*
	 * Wait for the current transmission block and the
	 * current fifo data to transmit. Once this is done
	 * we may go on.
	 */
	DEBUGCONT0(PL011_DEBUG_EOT, "pl011_waiteot\n");
	ASSERT(mutex_owned(&pl011->pl011_excl));
	ASSERT(mutex_owned(&pl011->pl011_excl_hi));
	while (pl011_isbusy(pl011)) {
		mutex_exit(&pl011->pl011_excl_hi);
		mutex_exit(&pl011->pl011_excl);
		drv_usecwait(10000);		/* wait .01 */
		mutex_enter(&pl011->pl011_excl);
		mutex_enter(&pl011->pl011_excl_hi);
	}
}

/*
 * Program the PL011 port. Most of the plasync operation is based on the values
 * of 'c_iflag' and 'c_cflag'.
 */

#define	BAUDINDEX(cflg)	(((cflg) & CBAUDEXT) ? \
			(((cflg) & CBAUD) + CBAUD + 1) : ((cflg) & CBAUD))

static void
pl011_program(struct pl011com *pl011, int mode)
{
	struct plasyncline *plasync;
	int baudrate, c_flag;
	int icr, lcr;
	int flush_reg;
	int ocflags;
#ifdef DEBUG
	int instance;
#endif

	ASSERT(mutex_owned(&pl011->pl011_excl));
	ASSERT(mutex_owned(&pl011->pl011_excl_hi));

	plasync = pl011->pl011_priv;
#ifdef DEBUG
	instance = UNIT(plasync->plasync_dev);
	DEBUGCONT2(PL011_DEBUG_PROCS,
	    "pl011%d_program: mode = 0x%08X, enter\n", instance, mode);
#endif

	baudrate = BAUDINDEX(plasync->plasync_ttycommon.t_cflag);

	plasync->plasync_ttycommon.t_cflag &= ~(CIBAUD);

	if (baudrate > CBAUD) {
		plasync->plasync_ttycommon.t_cflag |= CIBAUDEXT;
		plasync->plasync_ttycommon.t_cflag |=
		    (((baudrate - CBAUD - 1) << IBSHIFT) & CIBAUD);
	} else {
		plasync->plasync_ttycommon.t_cflag &= ~CIBAUDEXT;
		plasync->plasync_ttycommon.t_cflag |=
		    ((baudrate << IBSHIFT) & CIBAUD);
	}

	c_flag = plasync->plasync_ttycommon.t_cflag &
	    (CLOCAL|CREAD|CSTOPB|CSIZE|PARENB|PARODD|CBAUD|CBAUDEXT);

	ocflags = pl011->pl011_ocflag;

	pl011_reset(pl011);
	pl011->pl011_msr = pl011_get_msr(pl011);
	/*
	 * The device is programmed in the open sequence, if we
	 * have to hardware handshake, then this is a good time
	 * to check if the device can receive any data.
	 */

	if ((CRTSCTS & plasync->plasync_ttycommon.t_cflag) && !(pl011->pl011_msr & CTS)) {
		plasync_flowcontrol_hw_output(pl011, FLOW_STOP);
	} else {
		/*
		 * We can not use plasync_flowcontrol_hw_output(pl011, FLOW_START)
		 * here, because if CRTSCTS is clear, we need clear
		 * PLASYNC_HW_OUT_FLW bit.
		 */
		plasync->plasync_flags &= ~PLASYNC_HW_OUT_FLW;
	}

	/*
	 * If IXON is not set, clear PLASYNC_SW_OUT_FLW;
	 * If IXON is set, no matter what IXON flag is before this
	 * function call to pl011_program,
	 * we will use the old PLASYNC_SW_OUT_FLW status.
	 * Because of handling IXON in the driver, we also should re-calculate
	 * the value of PLASYNC_OUT_FLW_RESUME bit, but in fact,
	 * the TCSET* commands which call pl011_program
	 * are put into the write queue, so there is no output needed to
	 * be resumed at this point.
	 */
	if (!(IXON & plasync->plasync_ttycommon.t_iflag))
		plasync->plasync_flags &= ~PLASYNC_SW_OUT_FLW;

	if (mode == PL011_INIT)
		while (pl011_rx_is_ready(pl011))
			pl011_get_char(pl011);

	if (ocflags != (c_flag & ~CLOCAL) || mode == PL011_INIT) {
		/* Set line control */
		lcr = pl011_get_lcr(pl011);
		lcr &= ~(WLS0|WLS1|STB|PEN|EPS);

		if (c_flag & CSTOPB)
			lcr |= STB;	/* 2 stop bits */

		if (c_flag & PARENB)
			lcr |= PEN;

		if ((c_flag & PARODD) == 0)
			lcr |= EPS;

		switch (c_flag & CSIZE) {
		case CS5:
			lcr |= BITS5;
			break;
		case CS6:
			lcr |= BITS6;
			break;
		case CS7:
			lcr |= BITS7;
			break;
		case CS8:
			lcr |= BITS8;
			break;
		}

		/* set the baud rate, unless it is "0" */
		if (baudrate != 0)
			pl011_set_baud(pl011, baudrate);

		/* set the line control modes */
		pl011_set_lcr(pl011, lcr);

		/*
		 * If we have a FIFO buffer, enable/flush
		 * at intialize time, flush if transitioning from
		 * CREAD off to CREAD on.
		 */
		if ((ocflags & CREAD) == 0 && (c_flag & CREAD) ||
		    mode == PL011_INIT)
			pl011_reset_fifo(pl011, FIFORXFLSH);

		/* remember the new cflags */
		pl011->pl011_ocflag = c_flag & ~CLOCAL;
	}

	if (baudrate == 0)
		pl011_set_mcr(pl011,
		    (pl011->pl011_mcr & RTS) | OUT2);
	else
		pl011_set_mcr(pl011,
		    pl011->pl011_mcr | OUT2);

	/*
	 * Call the modem status interrupt handler to check for the carrier
	 * in case CLOCAL was turned off after the carrier came on.
	 * (Note: Modem status interrupt is not enabled if CLOCAL is ON.)
	 */
	plasync_msint(pl011);

	/* Set interrupt control */
	DEBUGCONT3(PL011_DEBUG_MODM2,
	    "pl011%d_program: c_flag & CLOCAL = %x t_cflag & CRTSCTS = %x\n",
	    instance, c_flag & CLOCAL,
	    plasync->plasync_ttycommon.t_cflag & CRTSCTS);

	if ((c_flag & CLOCAL) && !(plasync->plasync_ttycommon.t_cflag & CRTSCTS))
		/*
		 * direct-wired line ignores DCD, so we don't enable modem
		 * status interrupts.
		 */
		icr = (TIEN | SIEN);
	else
		icr = (TIEN | SIEN | MIEN);

	if (c_flag & CREAD)
		icr |= RIEN;

	pl011_set_icr(pl011, icr, 0xff);
	DEBUGCONT1(PL011_DEBUG_PROCS, "pl011%d_program: done\n", instance);
}

static boolean_t
pl011_baudok(struct pl011com *pl011)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	int baudrate;

	baudrate = BAUDINDEX(plasync->plasync_ttycommon.t_cflag);

	return (baudrate >= N_SU_SPEEDS)? B_FALSE: B_TRUE;
}

/*
 * pl011intr() is the High Level Interrupt Handler.
 *
 * There are four different interrupt types indexed by ISR register values:
 *		0: modem
 *		1: Tx holding register is empty, ready for next char
 *		2: Rx register now holds a char to be picked up
 *		3: error or break on line
 * This routine checks the Bit 0 (interrupt-not-pending) to determine if
 * the interrupt is from this port.
 */
uint_t
pl011intr(caddr_t argpl011)
{
	struct pl011com		*pl011 = (struct pl011com *)argpl011;
	struct plasyncline	*plasync;
	int			ret_status = DDI_INTR_UNCLAIMED;
	uchar_t			interrupt_id, lsr;

	interrupt_id = pl011_get_isr(pl011);
	plasync = pl011->pl011_priv;

	if ((plasync == NULL) ||
	    !(plasync->plasync_flags & (PLASYNC_ISOPEN|PLASYNC_WOPEN))) {
		if (interrupt_id & NOINTERRUPT)
			return (DDI_INTR_UNCLAIMED);
		else {
			/*
			 * reset the device by:
			 *	reading line status
			 *	reading any data from data status register
			 *	reading modem status
			 */
			(void) pl011_get_lsr(pl011);
			(void) pl011_get_char(pl011);
			pl011->pl011_msr = pl011_get_msr(pl011);
			return (DDI_INTR_CLAIMED);
		}
	}

	mutex_enter(&pl011->pl011_excl_hi);

	if (pl011->pl011_flags & PL011_DDI_SUSPENDED) {
		mutex_exit(&pl011->pl011_excl_hi);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * We will loop until the interrupt line is pulled low. pl011
	 * interrupt is edge triggered.
	 */
	/* CSTYLED */
	for (;; interrupt_id =
	    pl011_get_isr(pl011)) {

		if (interrupt_id & NOINTERRUPT)
			break;
		ret_status = DDI_INTR_CLAIMED;

		DEBUGCONT1(PL011_DEBUG_INTR, "pl011intr: interrupt_id = 0x%d\n",
		    interrupt_id);
		lsr = pl011_get_lsr(pl011);
		switch (interrupt_id) {
		case RxRDY:
		case RSTATUS:
		case FFTMOUT:
			/* receiver interrupt or receiver errors */
			plasync_rxint(pl011, lsr);
			break;
		case TxRDY:
			/* transmit interrupt */
			plasync_txint(pl011);
			continue;
		case MSTATUS:
			/* modem status interrupt */
			plasync_msint(pl011);
			break;
		}
		if ((lsr & XHRE) && (plasync->plasync_flags & PLASYNC_BUSY) &&
		    (plasync->plasync_ocnt > 0))
			plasync_txint(pl011);
	}
	mutex_exit(&pl011->pl011_excl_hi);
	return (ret_status);
}

/*
 * Transmitter interrupt service routine.
 * If there is more data to transmit in the current pseudo-DMA block,
 * send the next character if output is not stopped or draining.
 * Otherwise, queue up a soft interrupt.
 *
 * XXX -  Needs review for HW FIFOs.
 */
static void
plasync_txint(struct pl011com *pl011)
{
	struct plasyncline *plasync = pl011->pl011_priv;

	/*
	 * If PLASYNC_BREAK or PLASYNC_OUT_SUSPEND has been set, return to
	 * pl011intr()'s context to claim the interrupt without performing
	 * any action. No character will be loaded into FIFO/THR until
	 * timed or untimed break is removed
	 */
	if (plasync->plasync_flags & (PLASYNC_BREAK|PLASYNC_OUT_SUSPEND))
		return;

	plasync_flowcontrol_sw_input(pl011, FLOW_CHECK, IN_FLOW_NULL);

	if (!(plasync->plasync_flags &
	    (PLASYNC_HW_OUT_FLW|PLASYNC_SW_OUT_FLW|PLASYNC_STOPPED))) {
		while (plasync->plasync_ocnt > 0) {
			if (!pl011_tx_is_ready(pl011)) {
				break;
			}
			pl011_put_char(pl011, *plasync->plasync_optr++);
			plasync->plasync_ocnt--;
		}
		plasync->plasync_flags |= PLASYNC_PROGRESS;
	}

	PL011SETSOFT(pl011);
}

/*
 * Interrupt on port: handle PPS event.  This function is only called
 * for a port on which PPS event handling has been enabled.
 */
static void
pl011_ppsevent(struct pl011com *pl011, int msr)
{
	if (pl011->pl011_flags & PL011_PPS_EDGE) {
		/* Have seen leading edge, now look for and record drop */
		if ((msr & DCD) == 0)
			pl011->pl011_flags &= ~PL011_PPS_EDGE;
		/*
		 * Waiting for leading edge, look for rise; stamp event and
		 * calibrate kernel clock.
		 */
	} else if (msr & DCD) {
			/*
			 * This code captures a timestamp at the designated
			 * transition of the PPS signal (DCD asserted).  The
			 * code provides a pointer to the timestamp, as well
			 * as the hardware counter value at the capture.
			 *
			 * Note: the kernel has nano based time values while
			 * NTP requires micro based, an in-line fast algorithm
			 * to convert nsec to usec is used here -- see hrt2ts()
			 * in common/os/timers.c for a full description.
			 */
			struct timeval *tvp = &pl011_ppsev.tv;
			timestruc_t ts;
			long nsec, usec;

			pl011->pl011_flags |= PL011_PPS_EDGE;
			LED_OFF;
			gethrestime(&ts);
			LED_ON;
			nsec = ts.tv_nsec;
			usec = nsec + (nsec >> 2);
			usec = nsec + (usec >> 1);
			usec = nsec + (usec >> 2);
			usec = nsec + (usec >> 4);
			usec = nsec - (usec >> 3);
			usec = nsec + (usec >> 2);
			usec = nsec + (usec >> 3);
			usec = nsec + (usec >> 4);
			usec = nsec + (usec >> 1);
			usec = nsec + (usec >> 6);
			tvp->tv_usec = usec >> 10;
			tvp->tv_sec = ts.tv_sec;

			++pl011_ppsev.serial;

			/*
			 * Because the kernel keeps a high-resolution time,
			 * pass the current highres timestamp in tvp and zero
			 * in usec.
			 */
			ddi_hardpps(tvp, 0);
	}
}

/*
 * Receiver interrupt: RxRDY interrupt, FIFO timeout interrupt or receive
 * error interrupt.
 * Try to put the character into the circular buffer for this line; if it
 * overflows, indicate a circular buffer overrun. If this port is always
 * to be serviced immediately, or the character is a STOP character, or
 * more than 15 characters have arrived, queue up a soft interrupt to
 * drain the circular buffer.
 * XXX - needs review for hw FIFOs support.
 */

static void
plasync_rxint(struct pl011com *pl011, uchar_t lsr)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	uchar_t c;
	uint_t s, needsoft = 0;
	tty_common_t *tp;

	tp = &plasync->plasync_ttycommon;
	if (!(tp->t_cflag & CREAD)) {
		while (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
			(void) pl011_get_char(pl011);
			lsr = pl011_get_lsr(pl011);
		}
		return; /* line is not open for read? */
	}

	while (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
		c = 0;
		s = 0;				/* reset error status */
		if (lsr & RCA) {
			c = pl011_get_char(pl011);

			/*
			 * We handle XON/XOFF char if IXON is set,
			 * but if received char is _POSIX_VDISABLE,
			 * we left it to the up level module.
			 */
			if (tp->t_iflag & IXON) {
				if ((c == plasync->plasync_stopc) &&
				    (c != _POSIX_VDISABLE)) {
					plasync_flowcontrol_sw_output(pl011,
					    FLOW_STOP);
					goto check_looplim;
				} else if ((c == plasync->plasync_startc) &&
				    (c != _POSIX_VDISABLE)) {
					plasync_flowcontrol_sw_output(pl011,
					    FLOW_START);
					needsoft = 1;
					goto check_looplim;
				}
				if ((tp->t_iflag & IXANY) &&
				    (plasync->plasync_flags & PLASYNC_SW_OUT_FLW)) {
					plasync_flowcontrol_sw_output(pl011,
					    FLOW_START);
					needsoft = 1;
				}
			}
		}

		/*
		 * Check for character break sequence
		 */
		if ((abort_enable == KIOCABORTALTERNATE) &&
		    (pl011->pl011_flags & PL011_CONSOLE)) {
			if (abort_charseq_recognize(c))
				abort_sequence_enter((char *)NULL);
		}

		/* Handle framing errors */
		if (lsr & (PARERR|FRMERR|BRKDET|OVRRUN)) {
			if (lsr & PARERR) {
				if (tp->t_iflag & INPCK) /* parity enabled */
					s |= PERROR;
			}

			if (lsr & (FRMERR|BRKDET))
				s |= FRERROR;
			if (lsr & OVRRUN) {
				plasync->plasync_hw_overrun = 1;
				s |= OVERRUN;
			}
		}

		if (s == 0)
			if ((tp->t_iflag & PARMRK) &&
			    !(tp->t_iflag & (IGNPAR|ISTRIP)) &&
			    (c == 0377))
				if (RING_POK(plasync, 2)) {
					RING_PUT(plasync, 0377);
					RING_PUT(plasync, c);
				} else
					plasync->plasync_sw_overrun = 1;
			else
				if (RING_POK(plasync, 1))
					RING_PUT(plasync, c);
				else
					plasync->plasync_sw_overrun = 1;
		else
			if (s & FRERROR) /* Handle framing errors */
				if (c == 0)
					if ((pl011->pl011_flags & PL011_CONSOLE) &&
					    (abort_enable !=
					    KIOCABORTALTERNATE))
						abort_sequence_enter((char *)0);
					else
						plasync->plasync_break++;
				else
					if (RING_POK(plasync, 1))
						RING_MARK(plasync, c, s);
					else
						plasync->plasync_sw_overrun = 1;
			else /* Parity errors are handled by ldterm */
				if (RING_POK(plasync, 1))
					RING_MARK(plasync, c, s);
				else
					plasync->plasync_sw_overrun = 1;
check_looplim:
		lsr = pl011_get_lsr(pl011);
	}
	if ((RING_CNT(plasync) > (RINGSIZE * 3)/4) &&
	    !(plasync->plasync_inflow_source & IN_FLOW_RINGBUFF)) {
		plasync_flowcontrol_hw_input(pl011, FLOW_STOP, IN_FLOW_RINGBUFF);
		(void) plasync_flowcontrol_sw_input(pl011, FLOW_STOP,
		    IN_FLOW_RINGBUFF);
	}

	if ((plasync->plasync_flags & PLASYNC_SERVICEIMM) || needsoft ||
	    (RING_FRAC(plasync)) || (plasync->plasync_polltid == 0))
		PL011SETSOFT(pl011);	/* need a soft interrupt */
}

/*
 * Modem status interrupt.
 *
 * (Note: It is assumed that the MSR hasn't been read by pl011intr().)
 */

static void
plasync_msint(struct pl011com *pl011)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	int msr, t_cflag = plasync->plasync_ttycommon.t_cflag;
#ifdef DEBUG
	int instance = UNIT(plasync->plasync_dev);
#endif

plasync_msint_retry:
	/* this resets the interrupt */
	msr = pl011_get_msr(pl011);
	DEBUGCONT10(PL011_DEBUG_STATE,
	    "plasync%d_msint call #%d:\n"
	    "   transition: %3s %3s %3s %3s\n"
	    "current state: %3s %3s %3s %3s\n",
	    instance,
	    ++(pl011->pl011_msint_cnt),
	    (msr & DCTS) ? "DCTS" : "    ",
	    (msr & DDSR) ? "DDSR" : "    ",
	    (msr & DRI)  ? "DRI " : "    ",
	    (msr & DDCD) ? "DDCD" : "    ",
	    (msr & CTS)  ? "CTS " : "    ",
	    (msr & DSR)  ? "DSR " : "    ",
	    (msr & RI)   ? "RI  " : "    ",
	    (msr & DCD)  ? "DCD " : "    ");

	/* If CTS status is changed, do H/W output flow control */
	if ((t_cflag & CRTSCTS) && (((pl011->pl011_msr ^ msr) & CTS) != 0))
		plasync_flowcontrol_hw_output(pl011,
		    msr & CTS ? FLOW_START : FLOW_STOP);
	/*
	 * Reading MSR resets the interrupt, we save the
	 * value of msr so that other functions could examine MSR by
	 * looking at pl011_msr.
	 */
	pl011->pl011_msr = (uchar_t)msr;

	/* Handle PPS event */
	if (pl011->pl011_flags & PL011_PPS)
		pl011_ppsevent(pl011, msr);

	plasync->plasync_ext++;
	PL011SETSOFT(pl011);
	/*
	 * We will make sure that the modem status presented to us
	 * during the previous read has not changed. If the chip samples
	 * the modem status on the falling edge of the interrupt line,
	 * and uses this state as the base for detecting change of modem
	 * status, we would miss a change of modem status event that occured
	 * after we initiated a read MSR operation.
	 */
	msr = pl011_get_msr(pl011);
	if (STATES(msr) != STATES(pl011->pl011_msr))
		goto	plasync_msint_retry;
}

/*
 * Handle a second-stage interrupt.
 */
/*ARGSUSED*/
uint_t
pl011softintr(caddr_t intarg)
{
	struct pl011com *pl011 = (struct pl011com *)intarg;
	struct plasyncline *plasync;
	int rv;
	uint_t cc;

	/*
	 * Test and clear soft interrupt.
	 */
	mutex_enter(&pl011->pl011_soft_lock);
	DEBUGCONT0(PL011_DEBUG_PROCS, "pl011softintr: enter\n");
	rv = pl011->pl011softpend;
	if (rv != 0)
		pl011->pl011softpend = 0;
	mutex_exit(&pl011->pl011_soft_lock);

	if (rv) {
		if (pl011->pl011_priv == NULL)
			return (rv ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
		plasync = (struct plasyncline *)pl011->pl011_priv;
		mutex_enter(&pl011->pl011_excl_hi);
		if (pl011->pl011_flags & PL011_NEEDSOFT) {
			pl011->pl011_flags &= ~PL011_NEEDSOFT;
			mutex_exit(&pl011->pl011_excl_hi);
			plasync_softint(pl011);
			mutex_enter(&pl011->pl011_excl_hi);
		}

		/*
		 * There are some instances where the softintr is not
		 * scheduled and hence not called. It so happens that
		 * causes the last few characters to be stuck in the
		 * ringbuffer. Hence, call the handler once again so
		 * the last few characters are cleared.
		 */
		cc = RING_CNT(plasync);
		mutex_exit(&pl011->pl011_excl_hi);
		if (cc > 0)
			(void) plasync_softint(pl011);
	}
	return (rv ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

/*
 * Handle a software interrupt.
 */
static void
plasync_softint(struct pl011com *pl011)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	uint_t	cc;
	mblk_t	*bp;
	queue_t	*q;
	uchar_t	val;
	uchar_t	c;
	tty_common_t	*tp;
	int nb;
	int instance = UNIT(plasync->plasync_dev);

	DEBUGCONT1(PL011_DEBUG_PROCS, "plasync%d_softint\n", instance);
	mutex_enter(&pl011->pl011_excl_hi);
	if (pl011->pl011_flags & PL011_DOINGSOFT) {
		pl011->pl011_flags |= PL011_DOINGSOFT_RETRY;
		mutex_exit(&pl011->pl011_excl_hi);
		return;
	}
	pl011->pl011_flags |= PL011_DOINGSOFT;
begin:
	pl011->pl011_flags &= ~PL011_DOINGSOFT_RETRY;
	mutex_exit(&pl011->pl011_excl_hi);
	mutex_enter(&pl011->pl011_excl);
	tp = &plasync->plasync_ttycommon;
	q = tp->t_readq;
	if (plasync->plasync_flags & PLASYNC_OUT_FLW_RESUME) {
		if (plasync->plasync_ocnt > 0) {
			mutex_enter(&pl011->pl011_excl_hi);
			plasync_resume(plasync);
			mutex_exit(&pl011->pl011_excl_hi);
		} else {
			if (plasync->plasync_xmitblk)
				freeb(plasync->plasync_xmitblk);
			plasync->plasync_xmitblk = NULL;
			plasync_start(plasync);
		}
		plasync->plasync_flags &= ~PLASYNC_OUT_FLW_RESUME;
	}
	mutex_enter(&pl011->pl011_excl_hi);
	if (plasync->plasync_ext) {
		plasync->plasync_ext = 0;
		/* check for carrier up */
		DEBUGCONT3(PL011_DEBUG_MODM2,
		    "plasync%d_softint: pl011_msr & DCD = %x, "
		    "tp->t_flags & TS_SOFTCAR = %x\n",
		    instance, pl011->pl011_msr & DCD, tp->t_flags & TS_SOFTCAR);

		if (pl011->pl011_msr & DCD) {
			/* carrier present */
			if ((plasync->plasync_flags & PLASYNC_CARR_ON) == 0) {
				DEBUGCONT1(PL011_DEBUG_MODM2,
				    "plasync%d_softint: set PLASYNC_CARR_ON\n",
				    instance);
				plasync->plasync_flags |= PLASYNC_CARR_ON;
				if (plasync->plasync_flags & PLASYNC_ISOPEN) {
					mutex_exit(&pl011->pl011_excl_hi);
					mutex_exit(&pl011->pl011_excl);
					(void) putctl(q, M_UNHANGUP);
					mutex_enter(&pl011->pl011_excl);
					mutex_enter(&pl011->pl011_excl_hi);
				}
				cv_broadcast(&plasync->plasync_flags_cv);
			}
		} else {
			if ((plasync->plasync_flags & PLASYNC_CARR_ON) &&
			    !(tp->t_cflag & CLOCAL) &&
			    !(tp->t_flags & TS_SOFTCAR)) {
				int flushflag;

				DEBUGCONT1(PL011_DEBUG_MODEM,
				    "plasync%d_softint: carrier dropped, "
				    "so drop DTR\n",
				    instance);
				/*
				 * Carrier went away.
				 * Drop DTR, abort any output in
				 * progress, indicate that output is
				 * not stopped, and send a hangup
				 * notification upstream.
				 */
				val = pl011_get_mcr(pl011);
				pl011_set_mcr(pl011, (val & ~DTR));

				if (plasync->plasync_flags & PLASYNC_BUSY) {
					DEBUGCONT0(PL011_DEBUG_BUSY,
					    "plasync_softint: "
					    "Carrier dropped.  "
					    "Clearing plasync_ocnt\n");
					plasync->plasync_ocnt = 0;
				}	/* if */

				plasync->plasync_flags &= ~PLASYNC_STOPPED;
				if (plasync->plasync_flags & PLASYNC_ISOPEN) {
					mutex_exit(&pl011->pl011_excl_hi);
					mutex_exit(&pl011->pl011_excl);
					(void) putctl(q, M_HANGUP);
					mutex_enter(&pl011->pl011_excl);
					DEBUGCONT1(PL011_DEBUG_MODEM,
					    "plasync%d_softint: "
					    "putctl(q, M_HANGUP)\n",
					    instance);
					/*
					 * Flush FIFO buffers
					 * Any data left in there is invalid now
					 */
					pl011_reset_fifo(pl011, FIFOTXFLSH);
					/*
					 * Flush our write queue if we have one.
					 * If we're in the midst of close, then
					 * flush everything. Don't leave stale
					 * ioctls lying about.
					 */
					flushflag = (plasync->plasync_flags &
					    PLASYNC_CLOSING) ? FLUSHALL :
					    FLUSHDATA;
					flushq(tp->t_writeq, flushflag);

					/* active msg */
					bp = plasync->plasync_xmitblk;
					if (bp != NULL) {
						freeb(bp);
						plasync->plasync_xmitblk = NULL;
					}

					mutex_enter(&pl011->pl011_excl_hi);
					plasync->plasync_flags &= ~PLASYNC_BUSY;
					/*
					 * This message warns of Carrier loss
					 * with data left to transmit can hang
					 * the system.
					 */
					DEBUGCONT0(PL011_DEBUG_MODEM,
					    "plasync_softint: Flushing to "
					    "prevent HUPCL hanging\n");
				}	/* if (PLASYNC_ISOPEN) */
			}	/* if (PLASYNC_CARR_ON && CLOCAL) */
			plasync->plasync_flags &= ~PLASYNC_CARR_ON;
			cv_broadcast(&plasync->plasync_flags_cv);
		}	/* else */
	}	/* if (plasync->plasync_ext) */

	mutex_exit(&pl011->pl011_excl_hi);

	/*
	 * If data has been added to the circular buffer, remove
	 * it from the buffer, and send it up the stream if there's
	 * somebody listening. Try to do it 16 bytes at a time. If we
	 * have more than 16 bytes to move, move 16 byte chunks and
	 * leave the rest for next time around (maybe it will grow).
	 */
	mutex_enter(&pl011->pl011_excl_hi);
	if (!(plasync->plasync_flags & PLASYNC_ISOPEN)) {
		RING_INIT(plasync);
		goto rv;
	}
	if ((cc = RING_CNT(plasync)) == 0)
		goto rv;
	mutex_exit(&pl011->pl011_excl_hi);

	if (!canput(q)) {
		mutex_enter(&pl011->pl011_excl_hi);
		if (!(plasync->plasync_inflow_source & IN_FLOW_STREAMS)) {
			plasync_flowcontrol_hw_input(pl011, FLOW_STOP,
			    IN_FLOW_STREAMS);
			(void) plasync_flowcontrol_sw_input(pl011, FLOW_STOP,
			    IN_FLOW_STREAMS);
		}
		goto rv;
	}
	if (plasync->plasync_inflow_source & IN_FLOW_STREAMS) {
		mutex_enter(&pl011->pl011_excl_hi);
		plasync_flowcontrol_hw_input(pl011, FLOW_START,
		    IN_FLOW_STREAMS);
		(void) plasync_flowcontrol_sw_input(pl011, FLOW_START,
		    IN_FLOW_STREAMS);
		mutex_exit(&pl011->pl011_excl_hi);
	}

	DEBUGCONT2(PL011_DEBUG_INPUT, "plasync%d_softint: %d char(s) in queue.\n",
	    instance, cc);

	if (!(bp = allocb(cc, BPRI_MED))) {
		mutex_exit(&pl011->pl011_excl);
		ttycommon_qfull(&plasync->plasync_ttycommon, q);
		mutex_enter(&pl011->pl011_excl);
		mutex_enter(&pl011->pl011_excl_hi);
		goto rv;
	}
	mutex_enter(&pl011->pl011_excl_hi);
	do {
		if (RING_ERR(plasync, S_ERRORS)) {
			RING_UNMARK(plasync);
			c = RING_GET(plasync);
			break;
		} else
			*bp->b_wptr++ = RING_GET(plasync);
	} while (--cc);
	mutex_exit(&pl011->pl011_excl_hi);
	mutex_exit(&pl011->pl011_excl);
	if (bp->b_wptr > bp->b_rptr) {
			if (!canput(q)) {
				pl011error(CE_NOTE, "pl011%d: local queue full",
				    instance);
				freemsg(bp);
			} else
				(void) putq(q, bp);
	} else
		freemsg(bp);
	/*
	 * If we have a parity error, then send
	 * up an M_BREAK with the "bad"
	 * character as an argument. Let ldterm
	 * figure out what to do with the error.
	 */
	if (cc) {
		(void) putctl1(q, M_BREAK, c);
		PL011SETSOFT(plasync->plasync_common);	/* finish cc chars */
	}
	mutex_enter(&pl011->pl011_excl);
	mutex_enter(&pl011->pl011_excl_hi);
rv:
	if ((RING_CNT(plasync) < (RINGSIZE/4)) &&
	    (plasync->plasync_inflow_source & IN_FLOW_RINGBUFF)) {
		plasync_flowcontrol_hw_input(pl011, FLOW_START, IN_FLOW_RINGBUFF);
		(void) plasync_flowcontrol_sw_input(pl011, FLOW_START,
		    IN_FLOW_RINGBUFF);
	}

	/*
	 * If a transmission has finished, indicate that it's finished,
	 * and start that line up again.
	 */
	if (plasync->plasync_break > 0) {
		nb = plasync->plasync_break;
		plasync->plasync_break = 0;
		if (plasync->plasync_flags & PLASYNC_ISOPEN) {
			mutex_exit(&pl011->pl011_excl_hi);
			mutex_exit(&pl011->pl011_excl);
			for (; nb > 0; nb--)
				(void) putctl(q, M_BREAK);
			mutex_enter(&pl011->pl011_excl);
			mutex_enter(&pl011->pl011_excl_hi);
		}
	}
	if (plasync->plasync_ocnt <= 0 && (plasync->plasync_flags & PLASYNC_BUSY)) {
		DEBUGCONT2(PL011_DEBUG_BUSY,
		    "plasync%d_softint: Clearing PLASYNC_BUSY.  plasync_ocnt=%d\n",
		    instance,
		    plasync->plasync_ocnt);
		plasync->plasync_flags &= ~PLASYNC_BUSY;
		mutex_exit(&pl011->pl011_excl_hi);
		if (plasync->plasync_xmitblk)
			freeb(plasync->plasync_xmitblk);
		plasync->plasync_xmitblk = NULL;
		plasync_start(plasync);
		/*
		 * If the flag isn't set after doing the plasync_start above, we
		 * may have finished all the queued output.  Signal any thread
		 * stuck in close.
		 */
		if (!(plasync->plasync_flags & PLASYNC_BUSY))
			cv_broadcast(&plasync->plasync_flags_cv);
		mutex_enter(&pl011->pl011_excl_hi);
	}
	/*
	 * A note about these overrun bits: all they do is *tell* someone
	 * about an error- They do not track multiple errors. In fact,
	 * you could consider them latched register bits if you like.
	 * We are only interested in printing the error message once for
	 * any cluster of overrun errrors.
	 */
	if (plasync->plasync_hw_overrun) {
		if (plasync->plasync_flags & PLASYNC_ISOPEN) {
			mutex_exit(&pl011->pl011_excl_hi);
			mutex_exit(&pl011->pl011_excl);
			pl011error(CE_NOTE, "pl011%d: silo overflow", instance);
			mutex_enter(&pl011->pl011_excl);
			mutex_enter(&pl011->pl011_excl_hi);
		}
		plasync->plasync_hw_overrun = 0;
	}
	if (plasync->plasync_sw_overrun) {
		if (plasync->plasync_flags & PLASYNC_ISOPEN) {
			mutex_exit(&pl011->pl011_excl_hi);
			mutex_exit(&pl011->pl011_excl);
			pl011error(CE_NOTE, "pl011%d: ring buffer overflow",
			    instance);
			mutex_enter(&pl011->pl011_excl);
			mutex_enter(&pl011->pl011_excl_hi);
		}
		plasync->plasync_sw_overrun = 0;
	}
	if (pl011->pl011_flags & PL011_DOINGSOFT_RETRY) {
		mutex_exit(&pl011->pl011_excl);
		goto begin;
	}
	pl011->pl011_flags &= ~PL011_DOINGSOFT;
	mutex_exit(&pl011->pl011_excl_hi);
	mutex_exit(&pl011->pl011_excl);
	DEBUGCONT1(PL011_DEBUG_PROCS, "plasync%d_softint: done\n", instance);
}

/*
 * Restart output on a line after a delay or break timer expired.
 */
static void
plasync_restart(void *arg)
{
	struct plasyncline *plasync = (struct plasyncline *)arg;
	struct pl011com *pl011 = plasync->plasync_common;
	uchar_t lcr;

	/*
	 * If break timer expired, turn off the break bit.
	 */
#ifdef DEBUG
	int instance = UNIT(plasync->plasync_dev);

	DEBUGCONT1(PL011_DEBUG_PROCS, "plasync%d_restart\n", instance);
#endif
	mutex_enter(&pl011->pl011_excl);
	/*
	 * If PLASYNC_OUT_SUSPEND is also set, we don't really
	 * clean the HW break, TIOCCBRK is responsible for this.
	 */
	if ((plasync->plasync_flags & PLASYNC_BREAK) &&
	    !(plasync->plasync_flags & PLASYNC_OUT_SUSPEND)) {
		mutex_enter(&pl011->pl011_excl_hi);
		pl011_set_break(pl011, B_FALSE);
		mutex_exit(&pl011->pl011_excl_hi);
	}
	plasync->plasync_flags &= ~(PLASYNC_DELAY|PLASYNC_BREAK);
	cv_broadcast(&plasync->plasync_flags_cv);
	plasync_start(plasync);

	mutex_exit(&pl011->pl011_excl);
}

static void
plasync_start(struct plasyncline *plasync)
{
	plasync_nstart(plasync, 0);
}

/*
 * Start output on a line, unless it's busy, frozen, or otherwise.
 */
/*ARGSUSED*/
static void
plasync_nstart(struct plasyncline *plasync, int mode)
{
	struct pl011com *pl011 = plasync->plasync_common;
	int cc;
	queue_t *q;
	mblk_t *bp;
	uchar_t *xmit_addr;
	uchar_t	val;
	boolean_t didsome;
	mblk_t *nbp;

#ifdef DEBUG
	int instance = UNIT(plasync->plasync_dev);

	DEBUGCONT1(PL011_DEBUG_PROCS, "plasync%d_nstart\n", instance);
#endif

	ASSERT(mutex_owned(&pl011->pl011_excl));

	/*
	 * If the chip is busy (i.e., we're waiting for a break timeout
	 * to expire, or for the current transmission to finish, or for
	 * output to finish draining from chip), don't grab anything new.
	 */
	if (plasync->plasync_flags & (PLASYNC_BREAK|PLASYNC_BUSY)) {
		DEBUGCONT2((mode? PL011_DEBUG_OUT : 0),
		    "plasync%d_nstart: start %s.\n",
		    instance,
		    plasync->plasync_flags & PLASYNC_BREAK ? "break" : "busy");
		return;
	}

	/*
	 * Check only pended sw input flow control.
	 */
	mutex_enter(&pl011->pl011_excl_hi);
	plasync_flowcontrol_sw_input(pl011, FLOW_CHECK, IN_FLOW_NULL);
	mutex_exit(&pl011->pl011_excl_hi);

	/*
	 * If we're waiting for a delay timeout to expire, don't grab
	 * anything new.
	 */
	if (plasync->plasync_flags & PLASYNC_DELAY) {
		DEBUGCONT1((mode? PL011_DEBUG_OUT : 0),
		    "plasync%d_nstart: start PLASYNC_DELAY.\n", instance);
		return;
	}

	if ((q = plasync->plasync_ttycommon.t_writeq) == NULL) {
		DEBUGCONT1((mode? PL011_DEBUG_OUT : 0),
		    "plasync%d_nstart: start writeq is null.\n", instance);
		return;	/* not attached to a stream */
	}

	for (;;) {
		if ((bp = getq(q)) == NULL)
			return;	/* no data to transmit */

		/*
		 * We have a message block to work on.
		 * Check whether it's a break, a delay, or an ioctl (the latter
		 * occurs if the ioctl in question was waiting for the output
		 * to drain).  If it's one of those, process it immediately.
		 */
		switch (bp->b_datap->db_type) {

		case M_BREAK:
			/*
			 * Set the break bit, and arrange for "plasync_restart"
			 * to be called in 1/4 second; it will turn the
			 * break bit off, and call "plasync_start" to grab
			 * the next message.
			 */
			mutex_enter(&pl011->pl011_excl_hi);
			pl011_set_break(pl011, B_TRUE);
			mutex_exit(&pl011->pl011_excl_hi);
			plasync->plasync_flags |= PLASYNC_BREAK;
			(void) timeout(plasync_restart, (caddr_t)plasync,
			    drv_usectohz(1000000)/4);
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_DELAY:
			/*
			 * Arrange for "plasync_restart" to be called when the
			 * delay expires; it will turn PLASYNC_DELAY off,
			 * and call "plasync_start" to grab the next message.
			 */
			(void) timeout(plasync_restart, (caddr_t)plasync,
			    (int)(*(unsigned char *)bp->b_rptr + 6));
			plasync->plasync_flags |= PLASYNC_DELAY;
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_IOCTL:
			/*
			 * This ioctl was waiting for the output ahead of
			 * it to drain; obviously, it has.  Do it, and
			 * then grab the next message after it.
			 */
			mutex_exit(&pl011->pl011_excl);
			plasync_ioctl(plasync, q, bp);
			mutex_enter(&pl011->pl011_excl);
			continue;
		}

		while (bp != NULL && ((cc = MBLKL(bp)) == 0)) {
			nbp = bp->b_cont;
			freeb(bp);
			bp = nbp;
		}
		if (bp != NULL)
			break;
	}

	/*
	 * We have data to transmit.  If output is stopped, put
	 * it back and try again later.
	 */
	if (plasync->plasync_flags & (PLASYNC_HW_OUT_FLW | PLASYNC_SW_OUT_FLW |
	    PLASYNC_STOPPED | PLASYNC_OUT_SUSPEND)) {
		(void) putbq(q, bp);
		return;
	}

	plasync->plasync_xmitblk = bp;
	xmit_addr = bp->b_rptr;
	bp = bp->b_cont;
	if (bp != NULL)
		(void) putbq(q, bp);	/* not done with this message yet */

	/*
	 * In 5-bit mode, the high order bits are used
	 * to indicate character sizes less than five,
	 * so we need to explicitly mask before transmitting
	 */
	if ((plasync->plasync_ttycommon.t_cflag & CSIZE) == CS5) {
		unsigned char *p = xmit_addr;
		int cnt = cc;

		while (cnt--)
			*p++ &= (unsigned char) 0x1f;
	}

	/*
	 * Set up this block for pseudo-DMA.
	 */
	mutex_enter(&pl011->pl011_excl_hi);
	/*
	 * If the transmitter is ready, shove the first
	 * character out.
	 */
	didsome = B_FALSE;
	while (cc > 0) {
		if (!pl011_tx_is_ready(pl011))
			break;
		pl011_put_char(pl011, *xmit_addr++);
		cc--;
		didsome = B_TRUE;
	}
	plasync->plasync_optr = xmit_addr;
	plasync->plasync_ocnt = cc;
	if (didsome)
		plasync->plasync_flags |= PLASYNC_PROGRESS;
	DEBUGCONT2(PL011_DEBUG_BUSY,
	    "plasync%d_nstart: Set PLASYNC_BUSY.  plasync_ocnt=%d\n",
	    instance, plasync->plasync_ocnt);
	plasync->plasync_flags |= PLASYNC_BUSY;
	if (cc == 0)
		PL011SETSOFT(pl011);

	mutex_exit(&pl011->pl011_excl_hi);
}

/*
 * Resume output by poking the transmitter.
 */
static void
plasync_resume(struct plasyncline *plasync)
{
	struct pl011com *pl011 = plasync->plasync_common;
#ifdef DEBUG
	int instance;
#endif

	ASSERT(mutex_owned(&pl011->pl011_excl_hi));
#ifdef DEBUG
	instance = UNIT(plasync->plasync_dev);
	DEBUGCONT1(PL011_DEBUG_PROCS, "plasync%d_resume\n", instance);
#endif

	if (pl011_tx_is_ready(pl011)) {
		if (plasync_flowcontrol_sw_input(pl011, FLOW_CHECK, IN_FLOW_NULL))
			return;
		if (plasync->plasync_ocnt > 0 &&
		    !(plasync->plasync_flags &
		    (PLASYNC_HW_OUT_FLW|PLASYNC_SW_OUT_FLW|PLASYNC_OUT_SUSPEND))) {
			pl011_put_char(pl011, *plasync->plasync_optr++);
			plasync->plasync_ocnt--;
			plasync->plasync_flags |= PLASYNC_PROGRESS;
		}
	}
}

/*
 * Hold the untimed break to last the minimum time.
 */
static void
plasync_hold_utbrk(void *arg)
{
	struct plasyncline *plasync = arg;
	struct pl011com *pl011 = plasync->plasync_common;

	mutex_enter(&pl011->pl011_excl);
	plasync->plasync_flags &= ~PLASYNC_HOLD_UTBRK;
	cv_broadcast(&plasync->plasync_flags_cv);
	plasync->plasync_utbrktid = 0;
	mutex_exit(&pl011->pl011_excl);
}

/*
 * Resume the untimed break.
 */
static void
plasync_resume_utbrk(struct plasyncline *plasync)
{
	uchar_t	val;
	struct pl011com *pl011 = plasync->plasync_common;
	ASSERT(mutex_owned(&pl011->pl011_excl));

	/*
	 * Because the wait time is very short,
	 * so we use uninterruptably wait.
	 */
	while (plasync->plasync_flags & PLASYNC_HOLD_UTBRK) {
		cv_wait(&plasync->plasync_flags_cv, &pl011->pl011_excl);
	}
	mutex_enter(&pl011->pl011_excl_hi);
	/*
	 * Timed break and untimed break can exist simultaneously,
	 * if PLASYNC_BREAK is also set at here, we don't
	 * really clean the HW break.
	 */
	if (!(plasync->plasync_flags & PLASYNC_BREAK)) {
		pl011_set_break(pl011, B_FALSE);
	}
	plasync->plasync_flags &= ~PLASYNC_OUT_SUSPEND;
	cv_broadcast(&plasync->plasync_flags_cv);
	if (plasync->plasync_ocnt > 0) {
		plasync_resume(plasync);
		mutex_exit(&pl011->pl011_excl_hi);
	} else {
		plasync->plasync_flags &= ~PLASYNC_BUSY;
		mutex_exit(&pl011->pl011_excl_hi);
		if (plasync->plasync_xmitblk != NULL) {
			freeb(plasync->plasync_xmitblk);
			plasync->plasync_xmitblk = NULL;
		}
		plasync_start(plasync);
	}
}

/*
 * Process an "ioctl" message sent down to us.
 * Note that we don't need to get any locks until we are ready to access
 * the hardware.  Nothing we access until then is going to be altered
 * outside of the STREAMS framework, so we should be safe.
 */
int pl011delay = 10000;
static void
plasync_ioctl(struct plasyncline *plasync, queue_t *wq, mblk_t *mp)
{
	struct pl011com *pl011 = plasync->plasync_common;
	tty_common_t  *tp = &plasync->plasync_ttycommon;
	struct iocblk *iocp;
	unsigned datasize;
	int error = 0;
	uchar_t val;
	mblk_t *datamp;
	unsigned int index;

#ifdef DEBUG
	int instance = UNIT(plasync->plasync_dev);

	DEBUGCONT1(PL011_DEBUG_PROCS, "plasync%d_ioctl\n", instance);
#endif

	if (tp->t_iocpending != NULL) {
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(plasync->plasync_ttycommon.t_iocpending);
		plasync->plasync_ttycommon.t_iocpending = NULL;
	}

	iocp = (struct iocblk *)mp->b_rptr;

	/*
	 * For TIOCMGET and the PPS ioctls, do NOT call ttycommon_ioctl()
	 * because this function frees up the message block (mp->b_cont) that
	 * contains the user location where we pass back the results.
	 *
	 * Similarly, CONSOPENPOLLEDIO needs ioc_count, which ttycommon_ioctl
	 * zaps.  We know that ttycommon_ioctl doesn't know any CONS*
	 * ioctls, so keep the others safe too.
	 */
	DEBUGCONT2(PL011_DEBUG_IOCTL, "plasync%d_ioctl: %s\n",
	    instance,
	    iocp->ioc_cmd == TIOCMGET ? "TIOCMGET" :
	    iocp->ioc_cmd == TIOCMSET ? "TIOCMSET" :
	    iocp->ioc_cmd == TIOCMBIS ? "TIOCMBIS" :
	    iocp->ioc_cmd == TIOCMBIC ? "TIOCMBIC" :
	    "other");

	switch (iocp->ioc_cmd) {
	case TIOCMGET:
	case TIOCGPPS:
	case TIOCSPPS:
	case TIOCGPPSEV:
	case CONSOPENPOLLEDIO:
	case CONSCLOSEPOLLEDIO:
	case CONSSETABORTENABLE:
	case CONSGETABORTENABLE:
		error = -1; /* Do Nothing */
		break;
	default:

		/*
		 * The only way in which "ttycommon_ioctl" can fail is if the
		 * "ioctl" requires a response containing data to be returned
		 * to the user, and no mblk could be allocated for the data.
		 * No such "ioctl" alters our state.  Thus, we always go ahead
		 * and do any state-changes the "ioctl" calls for.  If we
		 * couldn't allocate the data, "ttycommon_ioctl" has stashed
		 * the "ioctl" away safely, so we just call "bufcall" to
		 * request that we be called back when we stand a better
		 * chance of allocating the data.
		 */
		if ((datasize = ttycommon_ioctl(tp, wq, mp, &error)) != 0) {
			if (plasync->plasync_wbufcid)
				unbufcall(plasync->plasync_wbufcid);
			plasync->plasync_wbufcid = bufcall(datasize, BPRI_HI,
			    (void (*)(void *)) plasync_reioctl,
			    (void *)(intptr_t)plasync->plasync_common->pl011_unit);
			return;
		}
	}

	mutex_enter(&pl011->pl011_excl);

	if (error == 0) {
		/*
		 * "ttycommon_ioctl" did most of the work; we just use the
		 * data it set up.
		 */
		switch (iocp->ioc_cmd) {

		case TCSETS:
			mutex_enter(&pl011->pl011_excl_hi);
			if (pl011_baudok(pl011))
				pl011_program(pl011, PL011_NOINIT);
			else
				error = EINVAL;
			mutex_exit(&pl011->pl011_excl_hi);
			break;
		case TCSETSF:
		case TCSETSW:
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			mutex_enter(&pl011->pl011_excl_hi);
			if (!pl011_baudok(pl011))
				error = EINVAL;
			else {
				if (pl011_isbusy(pl011))
					pl011_waiteot(pl011);
				pl011_program(pl011, PL011_NOINIT);
			}
			mutex_exit(&pl011->pl011_excl_hi);
			break;
		}
	} else if (error < 0) {
		/*
		 * "ttycommon_ioctl" didn't do anything; we process it here.
		 */
		error = 0;
		switch (iocp->ioc_cmd) {

		case TIOCGPPS:
			/*
			 * Get PPS on/off.
			 */
			if (mp->b_cont != NULL)
				freemsg(mp->b_cont);

			mp->b_cont = allocb(sizeof (int), BPRI_HI);
			if (mp->b_cont == NULL) {
				error = ENOMEM;
				break;
			}
			if (pl011->pl011_flags & PL011_PPS)
				*(int *)mp->b_cont->b_wptr = 1;
			else
				*(int *)mp->b_cont->b_wptr = 0;
			mp->b_cont->b_wptr += sizeof (int);
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_count = sizeof (int);
			break;

		case TIOCSPPS:
			/*
			 * Set PPS on/off.
			 */
			error = miocpullup(mp, sizeof (int));
			if (error != 0)
				break;

			mutex_enter(&pl011->pl011_excl_hi);
			if (*(int *)mp->b_cont->b_rptr)
				pl011->pl011_flags |= PL011_PPS;
			else
				pl011->pl011_flags &= ~PL011_PPS;
			/* Reset edge sense */
			pl011->pl011_flags &= ~PL011_PPS_EDGE;
			mutex_exit(&pl011->pl011_excl_hi);
			mp->b_datap->db_type = M_IOCACK;
			break;

		case TIOCGPPSEV:
		{
			/*
			 * Get PPS event data.
			 */
			mblk_t *bp;
			void *buf;
#ifdef _SYSCALL32_IMPL
			struct ppsclockev32 p32;
#endif
			struct ppsclockev ppsclockev;

			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}

			if ((pl011->pl011_flags & PL011_PPS) == 0) {
				error = ENXIO;
				break;
			}

			/* Protect from incomplete pl011_ppsev */
			mutex_enter(&pl011->pl011_excl_hi);
			ppsclockev = pl011_ppsev;
			mutex_exit(&pl011->pl011_excl_hi);

#ifdef _SYSCALL32_IMPL
			if ((iocp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
				TIMEVAL_TO_TIMEVAL32(&p32.tv, &ppsclockev.tv);
				p32.serial = ppsclockev.serial;
				buf = &p32;
				iocp->ioc_count = sizeof (struct ppsclockev32);
			} else
#endif
			{
				buf = &ppsclockev;
				iocp->ioc_count = sizeof (struct ppsclockev);
			}

			if ((bp = allocb(iocp->ioc_count, BPRI_HI)) == NULL) {
				error = ENOMEM;
				break;
			}
			mp->b_cont = bp;

			bcopy(buf, bp->b_wptr, iocp->ioc_count);
			bp->b_wptr += iocp->ioc_count;
			mp->b_datap->db_type = M_IOCACK;
			break;
		}

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0)
				break;

			if (*(int *)mp->b_cont->b_rptr == 0) {

				/*
				 * XXX Arrangements to ensure that a break
				 * isn't in progress should be sufficient.
				 * This ugly delay() is the only thing
				 * that seems to work on the NCR Worldmark.
				 * It should be replaced. Note that an
				 * pl011_waiteot() also does not work.
				 */
				if (pl011delay)
					delay(drv_usectohz(pl011delay));

				while (plasync->plasync_flags & PLASYNC_BREAK) {
					cv_wait(&plasync->plasync_flags_cv,
					    &pl011->pl011_excl);
				}
				mutex_enter(&pl011->pl011_excl_hi);
				/*
				 * We loop until the TSR is empty and then
				 * set the break.  PLASYNC_BREAK has been set
				 * to ensure that no characters are
				 * transmitted while the TSR is being
				 * flushed and SOUT is being used for the
				 * break signal.
				 *
				 * The wait period is equal to
				 * clock / (baud * 16) * 16 * 2.
				 */
				index = BAUDINDEX(
				    plasync->plasync_ttycommon.t_cflag);
				plasync->plasync_flags |= PLASYNC_BREAK;

				while (pl011_is_busy(pl011)) {
					mutex_exit(&pl011->pl011_excl_hi);
					mutex_exit(&pl011->pl011_excl);
					drv_usecwait(pl011->pl011_clock / baudtable[index] * 2);
					mutex_enter(&pl011->pl011_excl);
					mutex_enter(&pl011->pl011_excl_hi);
				}
				/*
				 * Arrange for "plasync_restart"
				 * to be called in 1/4 second;
				 * it will turn the break bit off, and call
				 * "plasync_start" to grab the next message.
				 */
				pl011_set_break(pl011, B_TRUE);
				mutex_exit(&pl011->pl011_excl_hi);
				(void) timeout(plasync_restart, (caddr_t)plasync,
				    drv_usectohz(1000000)/4);
			} else {
				DEBUGCONT1(PL011_DEBUG_OUT,
				    "plasync%d_ioctl: wait for flush.\n",
				    instance);
				mutex_enter(&pl011->pl011_excl_hi);
				pl011_waiteot(pl011);
				mutex_exit(&pl011->pl011_excl_hi);
				DEBUGCONT1(PL011_DEBUG_OUT,
				    "plasync%d_ioctl: ldterm satisfied.\n",
				    instance);
			}
			break;

		case TIOCSBRK:
			if (!(plasync->plasync_flags & PLASYNC_OUT_SUSPEND)) {
				mutex_enter(&pl011->pl011_excl_hi);
				plasync->plasync_flags |= PLASYNC_OUT_SUSPEND;
				plasync->plasync_flags |= PLASYNC_HOLD_UTBRK;
				index = BAUDINDEX(
				    plasync->plasync_ttycommon.t_cflag);
				while (pl011_is_busy(pl011)) {
					mutex_exit(&pl011->pl011_excl_hi);
					mutex_exit(&pl011->pl011_excl);
					drv_usecwait(pl011->pl011_clock / baudtable[index] * 2);
					mutex_enter(&pl011->pl011_excl);
					mutex_enter(&pl011->pl011_excl_hi);
				}
				pl011_set_break(pl011, B_TRUE);
				mutex_exit(&pl011->pl011_excl_hi);
				/* wait for 100ms to hold BREAK */
				plasync->plasync_utbrktid =
				    timeout((void (*)())plasync_hold_utbrk,
				    (caddr_t)plasync,
				    drv_usectohz(pl011_min_utbrk));
			}
			mioc2ack(mp, NULL, 0, 0);
			break;

		case TIOCCBRK:
			if (plasync->plasync_flags & PLASYNC_OUT_SUSPEND)
				plasync_resume_utbrk(plasync);
			mioc2ack(mp, NULL, 0, 0);
			break;

		case TIOCMSET:
		case TIOCMBIS:
		case TIOCMBIC:
			if (iocp->ioc_count != TRANSPARENT) {
				DEBUGCONT1(PL011_DEBUG_IOCTL, "plasync%d_ioctl: "
				    "non-transparent\n", instance);

				error = miocpullup(mp, sizeof (int));
				if (error != 0)
					break;

				mutex_enter(&pl011->pl011_excl_hi);
				(void) pl011mctl(pl011,
				    dmtopl011(*(int *)mp->b_cont->b_rptr),
				    iocp->ioc_cmd);
				mutex_exit(&pl011->pl011_excl_hi);
				iocp->ioc_error = 0;
				mp->b_datap->db_type = M_IOCACK;
			} else {
				DEBUGCONT1(PL011_DEBUG_IOCTL, "plasync%d_ioctl: "
				    "transparent\n", instance);
				mcopyin(mp, NULL, sizeof (int), NULL);
			}
			break;

		case TIOCMGET:
			datamp = allocb(sizeof (int), BPRI_MED);
			if (datamp == NULL) {
				error = EAGAIN;
				break;
			}

			mutex_enter(&pl011->pl011_excl_hi);
			*(int *)datamp->b_rptr = pl011mctl(pl011, 0, TIOCMGET);
			mutex_exit(&pl011->pl011_excl_hi);

			if (iocp->ioc_count == TRANSPARENT) {
				DEBUGCONT1(PL011_DEBUG_IOCTL, "plasync%d_ioctl: "
				    "transparent\n", instance);
				mcopyout(mp, NULL, sizeof (int), NULL, datamp);
			} else {
				DEBUGCONT1(PL011_DEBUG_IOCTL, "plasync%d_ioctl: "
				    "non-transparent\n", instance);
				mioc2ack(mp, datamp, sizeof (int), 0);
			}
			break;

		case CONSOPENPOLLEDIO:
			error = miocpullup(mp, sizeof (struct cons_polledio *));
			if (error != 0)
				break;

			*(struct cons_polledio **)mp->b_cont->b_rptr =
			    &pl011->polledio;

			mp->b_datap->db_type = M_IOCACK;
			break;

		case CONSCLOSEPOLLEDIO:
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSSETABORTENABLE:
			error = secpolicy_console(iocp->ioc_cr);
			if (error != 0)
				break;

			if (iocp->ioc_count != TRANSPARENT) {
				error = EINVAL;
				break;
			}

			if (*(intptr_t *)mp->b_cont->b_rptr)
				pl011->pl011_flags |= PL011_CONSOLE;
			else
				pl011->pl011_flags &= ~PL011_CONSOLE;

			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSGETABORTENABLE:
			/*CONSTANTCONDITION*/
			ASSERT(sizeof (boolean_t) <= sizeof (boolean_t *));
			/*
			 * Store the return value right in the payload
			 * we were passed.  Crude.
			 */
			mcopyout(mp, NULL, sizeof (boolean_t), NULL, NULL);
			*(boolean_t *)mp->b_cont->b_rptr =
			    (pl011->pl011_flags & PL011_CONSOLE) != 0;
			break;

		default:
			/*
			 * If we don't understand it, it's an error.  NAK it.
			 */
			error = EINVAL;
			break;
		}
	}
	if (error != 0) {
		iocp->ioc_error = error;
		mp->b_datap->db_type = M_IOCNAK;
	}
	mutex_exit(&pl011->pl011_excl);
	qreply(wq, mp);
	DEBUGCONT1(PL011_DEBUG_PROCS, "plasync%d_ioctl: done\n", instance);
}

static int
pl011rsrv(queue_t *q)
{
	mblk_t *bp;
	struct plasyncline *plasync;

	plasync = (struct plasyncline *)q->q_ptr;

	while (canputnext(q) && (bp = getq(q)))
		putnext(q, bp);
	PL011SETSOFT(plasync->plasync_common);
	plasync->plasync_polltid = 0;
	return (0);
}

/*
 * The PL011WPUTDO_NOT_SUSP macro indicates to pl011wputdo() whether it should
 * handle messages as though the driver is operating normally or is
 * suspended.  In the suspended case, some or all of the processing may have
 * to be delayed until the driver is resumed.
 */
#define	PL011WPUTDO_NOT_SUSP(plasync, wput) \
	!((wput) && ((plasync)->plasync_flags & PLASYNC_DDI_SUSPENDED))

/*
 * Processing for write queue put procedure.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * set the flow control character for M_STOPI and M_STARTI messages;
 * queue up M_BREAK, M_DELAY, and M_DATA messages for processing
 * by the start routine, and then call the start routine; discard
 * everything else.  Note that this driver does not incorporate any
 * mechanism to negotiate to handle the canonicalization process.
 * It expects that these functions are handled in upper module(s),
 * as we do in ldterm.
 */
static int
pl011wputdo(queue_t *q, mblk_t *mp, boolean_t wput)
{
	struct plasyncline *plasync;
	struct pl011com *pl011;
#ifdef DEBUG
	int instance;
#endif
	int error;

	plasync = (struct plasyncline *)q->q_ptr;

#ifdef DEBUG
	instance = UNIT(plasync->plasync_dev);
#endif
	pl011 = plasync->plasync_common;

	switch (mp->b_datap->db_type) {

	case M_STOP:
		/*
		 * Since we don't do real DMA, we can just let the
		 * chip coast to a stop after applying the brakes.
		 */
		mutex_enter(&pl011->pl011_excl);
		plasync->plasync_flags |= PLASYNC_STOPPED;
		mutex_exit(&pl011->pl011_excl);
		freemsg(mp);
		break;

	case M_START:
		mutex_enter(&pl011->pl011_excl);
		if (plasync->plasync_flags & PLASYNC_STOPPED) {
			plasync->plasync_flags &= ~PLASYNC_STOPPED;
			if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
				/*
				 * If an output operation is in progress,
				 * resume it.  Otherwise, prod the start
				 * routine.
				 */
				if (plasync->plasync_ocnt > 0) {
					mutex_enter(&pl011->pl011_excl_hi);
					plasync_resume(plasync);
					mutex_exit(&pl011->pl011_excl_hi);
				} else {
					plasync_start(plasync);
				}
			}
		}
		mutex_exit(&pl011->pl011_excl);
		freemsg(mp);
		break;

	case M_IOCTL:
		switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return (0);
			}

			if (*(int *)mp->b_cont->b_rptr != 0) {
				DEBUGCONT1(PL011_DEBUG_OUT,
				    "plasync%d_ioctl: flush request.\n",
				    instance);
				(void) putq(q, mp);

				mutex_enter(&pl011->pl011_excl);
				if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
					/*
					 * If an TIOCSBRK is in progress,
					 * clean it as TIOCCBRK does,
					 * then kick off output.
					 * If TIOCSBRK is not in progress,
					 * just kick off output.
					 */
					plasync_resume_utbrk(plasync);
				}
				mutex_exit(&pl011->pl011_excl);
				break;
			}
			/*FALLTHROUGH*/
		case TCSETSW:
		case TCSETSF:
		case TCSETAW:
		case TCSETAF:
			/*
			 * The changes do not take effect until all
			 * output queued before them is drained.
			 * Put this message on the queue, so that
			 * "plasync_start" will see it when it's done
			 * with the output before it.  Poke the
			 * start routine, just in case.
			 */
			(void) putq(q, mp);

			mutex_enter(&pl011->pl011_excl);
			if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
				/*
				 * If an TIOCSBRK is in progress,
				 * clean it as TIOCCBRK does.
				 * then kick off output.
				 * If TIOCSBRK is not in progress,
				 * just kick off output.
				 */
				plasync_resume_utbrk(plasync);
			}
			mutex_exit(&pl011->pl011_excl);
			break;

		default:
			/*
			 * Do it now.
			 */
			mutex_enter(&pl011->pl011_excl);
			if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
				mutex_exit(&pl011->pl011_excl);
				plasync_ioctl(plasync, q, mp);
				break;
			}
			plasync_put_suspq(pl011, mp);
			mutex_exit(&pl011->pl011_excl);
			break;
		}
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			mutex_enter(&pl011->pl011_excl);

			/*
			 * Abort any output in progress.
			 */
			mutex_enter(&pl011->pl011_excl_hi);
			if (plasync->plasync_flags & PLASYNC_BUSY) {
				DEBUGCONT1(PL011_DEBUG_BUSY, "pl011%dwput: "
				    "Clearing plasync_ocnt, "
				    "leaving PLASYNC_BUSY set\n",
				    instance);
				plasync->plasync_ocnt = 0;
				plasync->plasync_flags &= ~PLASYNC_BUSY;
			} /* if */

			if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
				/* Flush FIFO buffers */
				pl011_reset_fifo(pl011, FIFOTXFLSH);
			}
			mutex_exit(&pl011->pl011_excl_hi);

			/* Flush FIFO buffers */
			pl011_reset_fifo(pl011, FIFOTXFLSH);

			/*
			 * Flush our write queue.
			 */
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			if (plasync->plasync_xmitblk != NULL) {
				freeb(plasync->plasync_xmitblk);
				plasync->plasync_xmitblk = NULL;
			}
			mutex_exit(&pl011->pl011_excl);
			*mp->b_rptr &= ~FLUSHW;	/* it has been flushed */
		}
		if (*mp->b_rptr & FLUSHR) {
			if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
				/* Flush FIFO buffers */
				pl011_reset_fifo(pl011, FIFORXFLSH);
			}
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);	/* give the read queues a crack at it */
		} else {
			freemsg(mp);
		}

		/*
		 * We must make sure we process messages that survive the
		 * write-side flush.
		 */
		if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
			mutex_enter(&pl011->pl011_excl);
			plasync_start(plasync);
			mutex_exit(&pl011->pl011_excl);
		}
		break;

	case M_BREAK:
	case M_DELAY:
	case M_DATA:
		/*
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
		(void) putq(q, mp);
		if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
			mutex_enter(&pl011->pl011_excl);
			plasync_start(plasync);
			mutex_exit(&pl011->pl011_excl);
		}
		break;

	case M_STOPI:
		mutex_enter(&pl011->pl011_excl);
		if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
			mutex_enter(&pl011->pl011_excl_hi);
			if (!(plasync->plasync_inflow_source & IN_FLOW_USER)) {
				plasync_flowcontrol_hw_input(pl011, FLOW_STOP,
				    IN_FLOW_USER);
				(void) plasync_flowcontrol_sw_input(pl011,
				    FLOW_STOP, IN_FLOW_USER);
			}
			mutex_exit(&pl011->pl011_excl_hi);
			mutex_exit(&pl011->pl011_excl);
			freemsg(mp);
			break;
		}
		plasync_put_suspq(pl011, mp);
		mutex_exit(&pl011->pl011_excl);
		break;

	case M_STARTI:
		mutex_enter(&pl011->pl011_excl);
		if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
			mutex_enter(&pl011->pl011_excl_hi);
			if (plasync->plasync_inflow_source & IN_FLOW_USER) {
				plasync_flowcontrol_hw_input(pl011, FLOW_START,
				    IN_FLOW_USER);
				(void) plasync_flowcontrol_sw_input(pl011,
				    FLOW_START, IN_FLOW_USER);
			}
			mutex_exit(&pl011->pl011_excl_hi);
			mutex_exit(&pl011->pl011_excl);
			freemsg(mp);
			break;
		}
		plasync_put_suspq(pl011, mp);
		mutex_exit(&pl011->pl011_excl);
		break;

	case M_CTL:
		if (MBLKL(mp) >= sizeof (struct iocblk) &&
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd == MC_POSIXQUERY) {
			mutex_enter(&pl011->pl011_excl);
			if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
				((struct iocblk *)mp->b_rptr)->ioc_cmd =
				    MC_HAS_POSIX;
				mutex_exit(&pl011->pl011_excl);
				qreply(q, mp);
				break;
			} else {
				plasync_put_suspq(pl011, mp);
			}
		} else {
			/*
			 * These MC_SERVICE type messages are used by upper
			 * modules to tell this driver to send input up
			 * immediately, or that it can wait for normal
			 * processing that may or may not be done.  Sun
			 * requires these for the mouse module.
			 * (XXX - for x86?)
			 */
			mutex_enter(&pl011->pl011_excl);
			switch (*mp->b_rptr) {

			case MC_SERVICEIMM:
				plasync->plasync_flags |= PLASYNC_SERVICEIMM;
				break;

			case MC_SERVICEDEF:
				plasync->plasync_flags &= ~PLASYNC_SERVICEIMM;
				break;
			}
			mutex_exit(&pl011->pl011_excl);
			freemsg(mp);
		}
		break;

	case M_IOCDATA:
		mutex_enter(&pl011->pl011_excl);
		if (PL011WPUTDO_NOT_SUSP(plasync, wput)) {
			mutex_exit(&pl011->pl011_excl);
			plasync_iocdata(q, mp);
			break;
		}
		plasync_put_suspq(pl011, mp);
		mutex_exit(&pl011->pl011_excl);
		break;

	default:
		freemsg(mp);
		break;
	}
	return (0);
}

static int
pl011wput(queue_t *q, mblk_t *mp)
{
	return (pl011wputdo(q, mp, B_TRUE));
}

/*
 * Retry an "ioctl", now that "bufcall" claims we may be able to allocate
 * the buffer we need.
 */
static void
plasync_reioctl(void *unit)
{
	int instance = (uintptr_t)unit;
	struct plasyncline *plasync;
	struct pl011com *pl011;
	queue_t	*q;
	mblk_t	*mp;

	pl011 = ddi_get_soft_state(pl011_soft_state, instance);
	ASSERT(pl011 != NULL);
	plasync = pl011->pl011_priv;

	/*
	 * The bufcall is no longer pending.
	 */
	mutex_enter(&pl011->pl011_excl);
	plasync->plasync_wbufcid = 0;
	if ((q = plasync->plasync_ttycommon.t_writeq) == NULL) {
		mutex_exit(&pl011->pl011_excl);
		return;
	}
	if ((mp = plasync->plasync_ttycommon.t_iocpending) != NULL) {
		/* not pending any more */
		plasync->plasync_ttycommon.t_iocpending = NULL;
		mutex_exit(&pl011->pl011_excl);
		plasync_ioctl(plasync, q, mp);
	} else
		mutex_exit(&pl011->pl011_excl);
}

static void
plasync_iocdata(queue_t *q, mblk_t *mp)
{
	struct plasyncline	*plasync = (struct plasyncline *)q->q_ptr;
	struct pl011com		*pl011;
	struct iocblk *ip;
	struct copyresp *csp;
#ifdef DEBUG
	int instance = UNIT(plasync->plasync_dev);
#endif

	pl011 = plasync->plasync_common;
	ip = (struct iocblk *)mp->b_rptr;
	csp = (struct copyresp *)mp->b_rptr;

	if (csp->cp_rval != 0) {
		if (csp->cp_private)
			freemsg(csp->cp_private);
		freemsg(mp);
		return;
	}

	mutex_enter(&pl011->pl011_excl);
	DEBUGCONT2(PL011_DEBUG_MODEM, "plasync%d_iocdata: case %s\n",
	    instance,
	    csp->cp_cmd == TIOCMGET ? "TIOCMGET" :
	    csp->cp_cmd == TIOCMSET ? "TIOCMSET" :
	    csp->cp_cmd == TIOCMBIS ? "TIOCMBIS" :
	    "TIOCMBIC");
	switch (csp->cp_cmd) {

	case TIOCMGET:
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_datap->db_type = M_IOCACK;
		ip->ioc_error = 0;
		ip->ioc_count = 0;
		ip->ioc_rval = 0;
		mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
		break;

	case TIOCMSET:
	case TIOCMBIS:
	case TIOCMBIC:
		mutex_enter(&pl011->pl011_excl_hi);
		(void) pl011mctl(pl011, dmtopl011(*(int *)mp->b_cont->b_rptr),
		    csp->cp_cmd);
		mutex_exit(&pl011->pl011_excl_hi);
		mioc2ack(mp, NULL, 0, 0);
		break;

	default:
		mp->b_datap->db_type = M_IOCNAK;
		ip->ioc_error = EINVAL;
		break;
	}
	qreply(q, mp);
	mutex_exit(&pl011->pl011_excl);
}

/*
 * debugger/console support routines.
 */

/*
 * put a character out
 * Do not use interrupts.  If char is LF, put out CR, LF.
 */
static void
pl011putchar(cons_polledio_arg_t arg, uchar_t c)
{
	struct pl011com *pl011 = (struct pl011com *)arg;

	if (c == '\n')
		pl011putchar(arg, '\r');

	while (!pl011_tx_is_ready(pl011)) {
		/* wait for xmit to finish */
		drv_usecwait(10);
	}

	/* put the character out */
	pl011_put_char(pl011, c);
}

/*
 * See if there's a character available. If no character is
 * available, return 0. Run in polled mode, no interrupts.
 */
static boolean_t
pl011ischar(cons_polledio_arg_t arg)
{
	struct pl011com *pl011 = (struct pl011com *)arg;

	return pl011_rx_is_ready(pl011);
}

/*
 * Get a character. Run in polled mode, no interrupts.
 */
static int
pl011getchar(cons_polledio_arg_t arg)
{
	struct pl011com *pl011 = (struct pl011com *)arg;

	while (!pl011ischar(arg))
		drv_usecwait(10);
	return (pl011_get_char(pl011));
}

/*
 * Set or get the modem control status.
 */
static int
pl011mctl(struct pl011com *pl011, int bits, int how)
{
	int mcr_r, msr_r;
	int instance = pl011->pl011_unit;

	ASSERT(mutex_owned(&pl011->pl011_excl_hi));
	ASSERT(mutex_owned(&pl011->pl011_excl));

	/* Read Modem Control Registers */
	mcr_r = pl011_get_mcr(pl011);

	switch (how) {

	case TIOCMSET:
		DEBUGCONT2(PL011_DEBUG_MODEM,
		    "pl011%dmctl: TIOCMSET, bits = %x\n", instance, bits);
		mcr_r = bits;		/* Set bits	*/
		break;

	case TIOCMBIS:
		DEBUGCONT2(PL011_DEBUG_MODEM, "pl011%dmctl: TIOCMBIS, bits = %x\n",
		    instance, bits);
		mcr_r |= bits;		/* Mask in bits	*/
		break;

	case TIOCMBIC:
		DEBUGCONT2(PL011_DEBUG_MODEM, "pl011%dmctl: TIOCMBIC, bits = %x\n",
		    instance, bits);
		mcr_r &= ~bits;		/* Mask out bits */
		break;

	case TIOCMGET:
		/* Read Modem Status Registers */
		/*
		 * If modem interrupts are enabled, we return the
		 * saved value of msr. We read MSR only in plasync_msint()
		 */
		if (pl011_get_icr(pl011) & MIEN) {
			msr_r = pl011->pl011_msr;
			DEBUGCONT2(PL011_DEBUG_MODEM,
			    "pl011%dmctl: TIOCMGET, read msr_r = %x\n",
			    instance, msr_r);
		} else {
			msr_r = pl011_get_msr(pl011);
			DEBUGCONT2(PL011_DEBUG_MODEM,
			    "pl011%dmctl: TIOCMGET, read MSR = %x\n",
			    instance, msr_r);
		}
		DEBUGCONT2(PL011_DEBUG_MODEM, "pl011%dtodm: modem_lines = %x\n",
		    instance, pl011todm(mcr_r, msr_r));
		return (pl011todm(mcr_r, msr_r));
	}

	pl011_set_mcr(pl011, mcr_r);

	return (mcr_r);
}

static int
pl011todm(int mcr_r, int msr_r)
{
	int b = 0;

	/* MCR registers */
	if (mcr_r & RTS)
		b |= TIOCM_RTS;

	if (mcr_r & DTR)
		b |= TIOCM_DTR;

	/* MSR registers */
	if (msr_r & DCD)
		b |= TIOCM_CAR;

	if (msr_r & CTS)
		b |= TIOCM_CTS;

	if (msr_r & DSR)
		b |= TIOCM_DSR;

	if (msr_r & RI)
		b |= TIOCM_RNG;
	return (b);
}

static int
dmtopl011(int bits)
{
	int b = 0;

	DEBUGCONT1(PL011_DEBUG_MODEM, "dmtopl011: bits = %x\n", bits);
#ifdef	CAN_NOT_SET	/* only DTR and RTS can be set */
	if (bits & TIOCM_CAR)
		b |= DCD;
	if (bits & TIOCM_CTS)
		b |= CTS;
	if (bits & TIOCM_DSR)
		b |= DSR;
	if (bits & TIOCM_RNG)
		b |= RI;
#endif

	if (bits & TIOCM_RTS) {
		DEBUGCONT0(PL011_DEBUG_MODEM, "dmtopl011: set b & RTS\n");
		b |= RTS;
	}
	if (bits & TIOCM_DTR) {
		DEBUGCONT0(PL011_DEBUG_MODEM, "dmtopl011: set b & DTR\n");
		b |= DTR;
	}

	return (b);
}

static void
pl011error(int level, const char *fmt, ...)
{
	va_list adx;
	static	time_t	last;
	static	const char *lastfmt;
	time_t	now;

	/*
	 * Don't print the same error message too often.
	 * Print the message only if we have not printed the
	 * message within the last second.
	 * Note: that fmt cannot be a pointer to a string
	 * stored on the stack. The fmt pointer
	 * must be in the data segment otherwise lastfmt would point
	 * to non-sense.
	 */
	now = gethrestime_sec();
	if (last == now && lastfmt == fmt)
		return;

	last = now;
	lastfmt = fmt;

	va_start(adx, fmt);
	vcmn_err(level, fmt, adx);
	va_end(adx);
}

/*
 * pl011_parse_mode(dev_info_t *devi, struct pl011com *pl011)
 * The value of this property is in the form of "9600,8,n,1,-"
 * 1) speed: 9600, 4800, ...
 * 2) data bits
 * 3) parity: n(none), e(even), o(odd)
 * 4) stop bits
 * 5) handshake: -(none), h(hardware: rts/cts), s(software: xon/off)
 *
 * This parsing came from a SPARCstation eeprom.
 */
static void
pl011_parse_mode(dev_info_t *devi, struct pl011com *pl011)
{
	char		name[40];
	char		val[40];
	int		len;
	int		ret;
	char		*p;
	char		*p1;

	ASSERT(pl011->pl011_com_port != 0);

	/*
	 * Parse the ttyx-mode property
	 */
	(void) sprintf(name, "tty%c-mode", pl011->pl011_com_port + 'a' - 1);
	len = sizeof (val);
	ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "com%c-mode", pl011->pl011_com_port + '0');
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}

	/* no property to parse */
	pl011->pl011_cflag = 0;
	if (ret != DDI_PROP_SUCCESS)
		return;

	p = val;
	/* ---- baud rate ---- */
	pl011->pl011_cflag = CREAD |
	    (PL011_DEFAULT_BAUD & CBAUD) |
	    (PL011_DEFAULT_BAUD > CBAUD? CBAUDEXT: 0);		/* initial default */
	if (p && (p1 = strchr(p, ',')) != 0) {
		*p1++ = '\0';
	} else {
		pl011->pl011_cflag |= BITS8;	/* add default bits */
		return;
	}

	if (strcmp(p, "110") == 0)
		pl011->pl011_bidx = B110;
	else if (strcmp(p, "150") == 0)
		pl011->pl011_bidx = B150;
	else if (strcmp(p, "300") == 0)
		pl011->pl011_bidx = B300;
	else if (strcmp(p, "600") == 0)
		pl011->pl011_bidx = B600;
	else if (strcmp(p, "1200") == 0)
		pl011->pl011_bidx = B1200;
	else if (strcmp(p, "2400") == 0)
		pl011->pl011_bidx = B2400;
	else if (strcmp(p, "4800") == 0)
		pl011->pl011_bidx = B4800;
	else if (strcmp(p, "9600") == 0)
		pl011->pl011_bidx = B9600;
	else if (strcmp(p, "19200") == 0)
		pl011->pl011_bidx = B19200;
	else if (strcmp(p, "38400") == 0)
		pl011->pl011_bidx = B38400;
	else if (strcmp(p, "57600") == 0)
		pl011->pl011_bidx = B57600;
	else if (strcmp(p, "115200") == 0)
		pl011->pl011_bidx = B115200;
	else
		pl011->pl011_bidx = PL011_DEFAULT_BAUD;

	pl011->pl011_cflag &= ~(CBAUD | CBAUDEXT);
	if (pl011->pl011_bidx > CBAUD) {	/* > 38400 uses the CBAUDEXT bit */
		pl011->pl011_cflag |= CBAUDEXT;
		pl011->pl011_cflag |= pl011->pl011_bidx - CBAUD - 1;
	} else {
		pl011->pl011_cflag |= pl011->pl011_bidx;
	}

	ASSERT(pl011->pl011_bidx == BAUDINDEX(pl011->pl011_cflag));

	/* ---- Next item is data bits ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		pl011->pl011_cflag |= BITS8;	/* add default bits */
		return;
	}
	switch (*p) {
		default:
		case '8':
			pl011->pl011_cflag |= CS8;
			pl011->pl011_lcr = BITS8;
			break;
		case '7':
			pl011->pl011_cflag |= CS7;
			pl011->pl011_lcr = BITS7;
			break;
		case '6':
			pl011->pl011_cflag |= CS6;
			pl011->pl011_lcr = BITS6;
			break;
		case '5':
			/* LINTED: CS5 is currently zero (but might change) */
			pl011->pl011_cflag |= CS5;
			pl011->pl011_lcr = BITS5;
			break;
	}

	/* ---- Parity info ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		return;
	}
	switch (*p)  {
		default:
		case 'n':
			break;
		case 'e':
			pl011->pl011_cflag |= PARENB;
			pl011->pl011_lcr |= PEN; break;
		case 'o':
			pl011->pl011_cflag |= PARENB|PARODD;
			pl011->pl011_lcr |= PEN|EPS;
			break;
	}

	/* ---- Find stop bits ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		return;
	}
	if (*p == '2') {
		pl011->pl011_cflag |= CSTOPB;
		pl011->pl011_lcr |= STB;
	}

	/* ---- handshake is next ---- */
	p = p1;
	if (p) {
		if ((p1 = strchr(p, ',')) != 0)
			*p1++ = '\0';

		if (*p == 'h')
			pl011->pl011_cflag |= CRTSCTS;
		else if (*p == 's')
			pl011->pl011_cflag |= CRTSXOFF;
	}
}

/*
 * Check for abort character sequence
 */
static boolean_t
abort_charseq_recognize(uchar_t ch)
{
	static int state = 0;
#define	CNTRL(c) ((c)&037)
	static char sequence[] = { '\r', '~', CNTRL('b') };

	if (ch == sequence[state]) {
		if (++state >= sizeof (sequence)) {
			state = 0;
			return (B_TRUE);
		}
	} else {
		state = (ch == sequence[0]) ? 1 : 0;
	}
	return (B_FALSE);
}

/*
 * Flow control functions
 */
/*
 * Software input flow control
 * This function can execute software input flow control sucessfully
 * at most of situations except that the line is in BREAK status
 * (timed and untimed break).
 * INPUT VALUE of onoff:
 *               FLOW_START means to send out a XON char
 *                          and clear SW input flow control flag.
 *               FLOW_STOP means to send out a XOFF char
 *                          and set SW input flow control flag.
 *               FLOW_CHECK means to check whether there is pending XON/XOFF
 *                          if it is true, send it out.
 * INPUT VALUE of type:
 *		 IN_FLOW_RINGBUFF means flow control is due to RING BUFFER
 *		 IN_FLOW_STREAMS means flow control is due to STREAMS
 *		 IN_FLOW_USER means flow control is due to user's commands
 * RETURN VALUE: B_FALSE means no flow control char is sent
 *               B_TRUE means one flow control char is sent
 */
static boolean_t
plasync_flowcontrol_sw_input(struct pl011com *pl011, plasync_flowc_action onoff,
    int type)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	int instance = UNIT(plasync->plasync_dev);
	int rval = B_FALSE;

	ASSERT(mutex_owned(&pl011->pl011_excl_hi));

	if (!(plasync->plasync_ttycommon.t_iflag & IXOFF))
		return (rval);

	/*
	 * If we get this far, then we know IXOFF is set.
	 */
	switch (onoff) {
	case FLOW_STOP:
		plasync->plasync_inflow_source |= type;

		/*
		 * We'll send an XOFF character for each of up to
		 * three different input flow control attempts to stop input.
		 * If we already send out one XOFF, but FLOW_STOP comes again,
		 * it seems that input flow control becomes more serious,
		 * then send XOFF again.
		 */
		if (plasync->plasync_inflow_source & (IN_FLOW_RINGBUFF |
		    IN_FLOW_STREAMS | IN_FLOW_USER))
			plasync->plasync_flags |= PLASYNC_SW_IN_FLOW |
			    PLASYNC_SW_IN_NEEDED;
		DEBUGCONT2(PL011_DEBUG_SFLOW, "plasync%d: input sflow stop, "
		    "type = %x\n", instance, plasync->plasync_inflow_source);
		break;
	case FLOW_START:
		plasync->plasync_inflow_source &= ~type;
		if (plasync->plasync_inflow_source == 0) {
			plasync->plasync_flags = (plasync->plasync_flags &
			    ~PLASYNC_SW_IN_FLOW) | PLASYNC_SW_IN_NEEDED;
			DEBUGCONT1(PL011_DEBUG_SFLOW, "plasync%d: "
			    "input sflow start\n", instance);
		}
		break;
	default:
		break;
	}

	if ((plasync->plasync_flags & (PLASYNC_SW_IN_NEEDED | PLASYNC_BREAK | PLASYNC_OUT_SUSPEND)) == PLASYNC_SW_IN_NEEDED) {
		/*
		 * If we get this far, then we know we need to send out
		 * XON or XOFF char.
		 */
		plasync->plasync_flags = (plasync->plasync_flags & ~PLASYNC_SW_IN_NEEDED) | PLASYNC_BUSY;
		while (!pl011_tx_is_ready(pl011)) {}
		pl011_put_char(pl011, plasync->plasync_flags & PLASYNC_SW_IN_FLOW ?  plasync->plasync_stopc : plasync->plasync_startc);
		rval = B_TRUE;
	}
	return (rval);
}

/*
 * Software output flow control
 * This function can be executed sucessfully at any situation.
 * It does not handle HW, and just change the SW output flow control flag.
 * INPUT VALUE of onoff:
 *                 FLOW_START means to clear SW output flow control flag,
 *			also combine with HW output flow control status to
 *			determine if we need to set PLASYNC_OUT_FLW_RESUME.
 *                 FLOW_STOP means to set SW output flow control flag,
 *			also clear PLASYNC_OUT_FLW_RESUME.
 */
static void
plasync_flowcontrol_sw_output(struct pl011com *pl011, plasync_flowc_action onoff)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	int instance = UNIT(plasync->plasync_dev);

	ASSERT(mutex_owned(&pl011->pl011_excl_hi));

	if (!(plasync->plasync_ttycommon.t_iflag & IXON))
		return;

	switch (onoff) {
	case FLOW_STOP:
		plasync->plasync_flags |= PLASYNC_SW_OUT_FLW;
		plasync->plasync_flags &= ~PLASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(PL011_DEBUG_SFLOW, "plasync%d: output sflow stop\n",
		    instance);
		break;
	case FLOW_START:
		plasync->plasync_flags &= ~PLASYNC_SW_OUT_FLW;
		if (!(plasync->plasync_flags & PLASYNC_HW_OUT_FLW))
			plasync->plasync_flags |= PLASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(PL011_DEBUG_SFLOW, "plasync%d: output sflow start\n",
		    instance);
		break;
	default:
		break;
	}
}

/*
 * Hardware input flow control
 * This function can be executed sucessfully at any situation.
 * It directly changes RTS depending on input parameter onoff.
 * INPUT VALUE of onoff:
 *       FLOW_START means to clear HW input flow control flag,
 *                  and pull up RTS if it is low.
 *       FLOW_STOP means to set HW input flow control flag,
 *                  and low RTS if it is high.
 * INPUT VALUE of type:
 *		 IN_FLOW_RINGBUFF means flow control is due to RING BUFFER
 *		 IN_FLOW_STREAMS means flow control is due to STREAMS
 *		 IN_FLOW_USER means flow control is due to user's commands
 */
static void
plasync_flowcontrol_hw_input(struct pl011com *pl011, plasync_flowc_action onoff,
    int type)
{
	uchar_t	mcr;
	uchar_t	flag;
	struct plasyncline *plasync = pl011->pl011_priv;
	int instance = UNIT(plasync->plasync_dev);

	ASSERT(mutex_owned(&pl011->pl011_excl_hi));

	if (!(plasync->plasync_ttycommon.t_cflag & CRTSXOFF))
		return;

	switch (onoff) {
	case FLOW_STOP:
		plasync->plasync_inflow_source |= type;
		if (plasync->plasync_inflow_source & (IN_FLOW_RINGBUFF |
		    IN_FLOW_STREAMS | IN_FLOW_USER))
			plasync->plasync_flags |= PLASYNC_HW_IN_FLOW;
		DEBUGCONT2(PL011_DEBUG_HFLOW, "plasync%d: input hflow stop, "
		    "type = %x\n", instance, plasync->plasync_inflow_source);
		break;
	case FLOW_START:
		plasync->plasync_inflow_source &= ~type;
		if (plasync->plasync_inflow_source == 0) {
			plasync->plasync_flags &= ~PLASYNC_HW_IN_FLOW;
			DEBUGCONT1(PL011_DEBUG_HFLOW, "plasync%d: "
			    "input hflow start\n", instance);
		}
		break;
	default:
		break;
	}
	mcr = pl011_get_mcr(pl011);
	flag = (plasync->plasync_flags & PLASYNC_HW_IN_FLOW) ? 0 : RTS;

	if (((mcr ^ flag) & RTS) != 0) {
		pl011_set_mcr(pl011, (mcr ^ RTS));
	}
}

/*
 * Hardware output flow control
 * This function can execute HW output flow control sucessfully
 * at any situation.
 * It doesn't really change RTS, and just change
 * HW output flow control flag depending on CTS status.
 * INPUT VALUE of onoff:
 *                FLOW_START means to clear HW output flow control flag.
 *			also combine with SW output flow control status to
 *			determine if we need to set PLASYNC_OUT_FLW_RESUME.
 *                FLOW_STOP means to set HW output flow control flag.
 *			also clear PLASYNC_OUT_FLW_RESUME.
 */
static void
plasync_flowcontrol_hw_output(struct pl011com *pl011, plasync_flowc_action onoff)
{
	struct plasyncline *plasync = pl011->pl011_priv;
	int instance = UNIT(plasync->plasync_dev);

	ASSERT(mutex_owned(&pl011->pl011_excl_hi));

	if (!(plasync->plasync_ttycommon.t_cflag & CRTSCTS))
		return;

	switch (onoff) {
	case FLOW_STOP:
		plasync->plasync_flags |= PLASYNC_HW_OUT_FLW;
		plasync->plasync_flags &= ~PLASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(PL011_DEBUG_HFLOW, "plasync%d: output hflow stop\n",
		    instance);
		break;
	case FLOW_START:
		plasync->plasync_flags &= ~PLASYNC_HW_OUT_FLW;
		if (!(plasync->plasync_flags & PLASYNC_SW_OUT_FLW))
			plasync->plasync_flags |= PLASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(PL011_DEBUG_HFLOW, "plasync%d: output hflow start\n",
		    instance);
		break;
	default:
		break;
	}
}


/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
pl011quiesce(dev_info_t *devi)
{
	int instance;
	struct pl011com *pl011;

	instance = ddi_get_instance(devi);	/* find out which unit */

	pl011 = ddi_get_soft_state(pl011_soft_state, instance);
	if (pl011 == NULL)
		return (DDI_FAILURE);

	/* disable all interrupts */
	pl011_set_icr(pl011, 0, RIEN | TIEN);

	/* reset the FIFO */
	pl011_reset_fifo(pl011, FIFOTXFLSH | FIFORXFLSH);

	return (DDI_SUCCESS);
}
