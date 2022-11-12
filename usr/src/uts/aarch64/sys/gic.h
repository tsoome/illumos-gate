/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2017 Hayashi Naoyuki
 */

#ifndef _SYS_GIC_H
#define _SYS_GIC_H

#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gic_dist {
	volatile uint32_t ctlr;
	volatile uint32_t typer;
	volatile uint32_t iidr;
	volatile uint32_t resv0[29];
	//: 0x80
	volatile uint32_t igroupr[32];
	//: 0x100
	volatile uint32_t isenabler[32];
	volatile uint32_t icenabler[32];
	//: 0x200
	volatile uint32_t ispendr[32];
	volatile uint32_t icpendr[32];
	//: 0x300
	volatile uint32_t isactiver[32];
	volatile uint32_t icactiver[32];
	//: 0x400
	volatile uint32_t ipriorityr[256];
	//: 0x800
	volatile uint32_t itargetsr[256];
	//: 0xc00
	volatile uint32_t icfgr[64];
	//: 0xd00
	volatile uint32_t resv1[64];
	//: 0xe00
	volatile uint32_t nsacr[64];
	//: 0xf00
	volatile uint32_t sgir;
	volatile uint32_t resv2[3];
	//: 0xf10
	volatile uint32_t cpendsgir[4];
	//: 0xf20
	volatile uint32_t spendsgir[4];
	//: 0xf30
	volatile uint32_t resv3[52];
};

struct gic_cpuif {
	volatile uint32_t ctlr;
	volatile uint32_t pmr;
	volatile uint32_t bpr;
	volatile uint32_t iar;
	//: 0x10
	volatile uint32_t eoir;
	volatile uint32_t rpr;
	volatile uint32_t hppir;
	volatile uint32_t abpr;
	//: 0x20
	volatile uint32_t aiar;
	volatile uint32_t aeoir;
	volatile uint32_t ahppir;
	//: 0x2c
	volatile uint32_t resv0[41];
	//: 0xd0
	volatile uint32_t apr[4];
	//: 0xe0
	volatile uint32_t nsapr[4];
	//: 0xf0
	volatile uint32_t resv1[3];
	volatile uint32_t iidr;
};

void gic_mask_level_irq(int irq);
void gic_unmask_level_irq(int irq);

void gic_send_ipi(cpuset_t cpuset, uint32_t irq);
void gic_init(void);
void gic_slave_init(int);
void gic_config_irq(uint32_t irq, bool is_edge);
int gic_num_cpus(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_GIC_H */
