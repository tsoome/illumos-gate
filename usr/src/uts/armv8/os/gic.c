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
 * Copyright 2017 Hayashi Naoyuki
 */

#include <sys/types.h>
#include <sys/gic.h>
#include <sys/avintr.h>
#include <sys/smp_impldefs.h>
#include <sys/promif.h>

#define IPL_TO_GICPRI(ipl)	((0xF & ~(ipl)) << 4)
static volatile int exclusion;
static volatile uint32_t ipriorityr_private[8];
static volatile uint32_t ienable_private;
static uint32_t intr_cfg[1024 / 32];
uintptr_t gic_cpuif_base;
uintptr_t gic_dist_base;
static uint8_t gic_target[8];
static cpuset_t gic_cpuset;

static void
gic_enable_irq(int irq)
{
	if (irq >= 16) {
		struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
		dist->isenabler[irq / 32] = (1u << (irq % 32));
	}
}

static void
gic_disable_irq(int irq)
{
	if (irq >= 16) {
		struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
		dist->icenabler[irq / 32] = (1u << (irq % 32));
	}
}

void gic_unmask_level_irq(int irq)
{
	if (irq >= 16 && (intr_cfg[irq / 32] & (1u << (irq % 32))) == 0) {
		ASSERT(irq != 225);
		struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
		dist->isenabler[irq / 32] = (1u << (irq % 32));
	}
}

void gic_mask_level_irq(int irq)
{
	if (irq >= 16 && (intr_cfg[irq / 32] & (1u << (irq % 32))) == 0) {
		ASSERT(irq != 225);
		struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
		dist->icenabler[irq / 32] = (1u << (irq % 32));
	}
}

void gic_config_irq(uint32_t irq, bool is_edge)
{
	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
	uint32_t v = (is_edge? 0x2: 0);
	dist->icfgr[irq / 16] = (dist->icfgr[irq / 16] & ~(0x3u << ((irq % 16) * 2))) | (v << ((irq % 16) * 2));
	if (is_edge)
		intr_cfg[irq / 32] |= (1u << (irq % 32));
	else
		intr_cfg[irq / 32] &= ~(1u << (irq % 32));
}

int
setlvl(int irq)
{
	int new_ipl;
	new_ipl = autovect[irq].avh_hi_pri;

	if (new_ipl != 0) {
		struct gic_cpuif *cpuif = (struct gic_cpuif *)gic_cpuif_base;
		cpuif->pmr = IPL_TO_GICPRI(new_ipl);
	}

	return new_ipl;
}

void
setlvlx(int ipl, int irq)
{
	gic_unmask_level_irq(irq);
	struct gic_cpuif *cpuif = (struct gic_cpuif *)gic_cpuif_base;
	cpuif->pmr = IPL_TO_GICPRI(ipl);
}

static void
gic_set_ipl(uint32_t irq, uint32_t ipl)
{
	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;

	uint64_t old = read_daif();
	set_daif(0x2);
	while (__sync_lock_test_and_set(&exclusion, 1)) {}

	uint32_t ipriorityr = dist->ipriorityr[irq / 4];
	ipriorityr &= ~(0xFF << (8 * (irq % 4)));
	ipriorityr |= (IPL_TO_GICPRI(ipl) << (8 * (irq % 4)));
	dist->ipriorityr[irq / 4] = ipriorityr;

	if (irq < 32) {
		ipriorityr_private[irq / 4] = ipriorityr;
	}
	__sync_lock_release(&exclusion);
	write_daif(old);
}

static void
gic_add_target(uint32_t irq)
{
	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;

	uint64_t old = read_daif();
	set_daif(0x2);
	while (__sync_lock_test_and_set(&exclusion, 1)) {}
	uint32_t coreMask = 0xFF;

	if (irq >= 32)
		dist->itargetsr[irq / 4] = (dist->itargetsr[irq / 4] & ~(coreMask << (8 * (irq % 4)))) | (coreMask << (8 * (irq % 4)));

	__sync_lock_release(&exclusion);
	write_daif(old);
}

static int
gic_addspl(int irq, int ipl, int min_ipl, int max_ipl)
{
	gic_set_ipl((uint32_t)irq, (uint32_t)ipl);
	gic_add_target((uint32_t)irq);
	gic_enable_irq((uint32_t)irq);
	if (irq < 32)
		ienable_private |= (1u << irq);

	return 0;
}

static int
gic_delspl(int irq, int ipl, int min_ipl, int max_ipl)
{
	if (autovect[irq].avh_hi_pri == 0) {
		gic_disable_irq((uint32_t)irq);
		gic_set_ipl((uint32_t)irq, 0);
		if (irq < 32)
			ienable_private &= ~(1u << irq);
	}

	return 0;
}

int (*addspl)(int, int, int, int) = gic_addspl;
int (*delspl)(int, int, int, int) = gic_delspl;

void
gic_send_ipi(cpuset_t cpuset, uint32_t irq)
{
	uint32_t target = 0;
	CPUSET_AND(cpuset, gic_cpuset);
	while (!CPUSET_ISNULL(cpuset)) {
		uint_t cpu;
		CPUSET_FIND(cpuset, cpu);
		target |= gic_target[cpu];
		CPUSET_DEL(cpuset, cpu);
	}
	uint64_t old = read_daif();
	set_daif(0x2);
	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
	dsb(ish);
	dist->sgir = (((target & 0xff) << 16) | irq);

	write_daif(old);
}

static pnode_t
find_gic(pnode_t nodeid, int depth)
{
	if (prom_is_compatible(nodeid, "arm,cortex-a15-gic") ||
	    prom_is_compatible(nodeid, "arm,gic-400")) {
		return nodeid;
	}

	pnode_t child = prom_childnode(nodeid);
	while (child > 0) {
		pnode_t node = find_gic(child, depth + 1);
		if (node > 0)
			return node;
		child = prom_nextnode(child);
	}
	return OBP_NONODE;
}

static uint_t
gic_get_target(void)
{
	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
	return __builtin_ctz(dist->itargetsr[0] & 0xFF);
}

void
gic_init(void)
{
	uint64_t old = read_daif();
	set_daif(0x2);
	while (__sync_lock_test_and_set(&exclusion, 1)) {}

	pnode_t node = find_gic(prom_rootnode(), 0);
	if (node > 0) {
		uint64_t base;
		if (prom_get_reg_address(node, 0, &base) == 0) {
			gic_dist_base = base + SEGKPM_BASE;
		}
		if (prom_get_reg_address(node, 1, &base) == 0) {
			gic_cpuif_base = base + SEGKPM_BASE;
		}
	}

	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
	struct gic_cpuif *cpuif = (struct gic_cpuif *)gic_cpuif_base;

	for (int i = 0; i < 32; i++) {
		dist->icenabler[i] = 0xffffffff;
		dist->icpendr[i]   = 0xffffffff;
		dist->icactiver[i] = 0xffffffff;
		dist->igroupr[i] = 0;
	}
	for (int i = 1; i < 64; i++) {
		dist->icfgr[i] = 0;
	}

	for (int i = 0; i < 8; i++) {
		dist->ipriorityr[i] = 0xffffffff;
		ipriorityr_private[i] = dist->ipriorityr[i];
	}
	for (int i = 8; i < 256; i++) {
		dist->itargetsr[i] = 0xffffffff;
		dist->ipriorityr[i] = 0xffffffff;
	}

	cpuif->ctlr = 1;

	cpuif->bpr = 3;
	cpuif->pmr = 0xFF;

	dist->ctlr = 1;

	__sync_lock_release(&exclusion);
	write_daif(old);

	CPUSET_ONLY(gic_cpuset, 0);

	gic_target[0] = 1u << gic_get_target();
}

void gic_slave_init(processorid_t id)
{
	uint64_t old = read_daif();
	set_daif(0x2);
	while (__sync_lock_test_and_set(&exclusion, 1)) {}

	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
	struct gic_cpuif *cpuif = (struct gic_cpuif *)gic_cpuif_base;

	for (int i = 0; i < 1; i++) {
		dist->icenabler[i] = 0xffffffff;
		dist->icpendr[i]   = 0xffffffff;
		dist->icactiver[i] = 0xffffffff;
		dist->igroupr[i] = 0;
	}
	for (int i = 1; i < 2; i++) {	// SGIは設定しない
		dist->icfgr[i] = 0;
	}

	for (int i = 0; i < 8; i++) {
		dist->ipriorityr[i] = ipriorityr_private[i];
	}
	dist->isenabler[0] = ienable_private;

	cpuif->ctlr = 1;

	cpuif->bpr = 3;
	cpuif->pmr = 0xFF;

	CPUSET_ADD(gic_cpuset, id);
	gic_target[id] = 1u << gic_get_target();

	__sync_lock_release(&exclusion);
	write_daif(old);
}

int gic_num_cpus(void)
{
	struct gic_dist *dist = (struct gic_dist *)gic_dist_base;
	return ((dist->typer >> 5) & 0x7) + 1;
}
