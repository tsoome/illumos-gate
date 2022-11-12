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

#pragma once

#include <sys/types.h>
#include <sys/platform.h>

struct emac_desc {
	uint32_t status;
	uint32_t cntl;
	uint32_t addr;
	uint32_t next;
};

#define EMAC_DESC_STATUS_OWN	(1u << 31)

#define EMAC_RXDESC_STATUS_FL(status)	(((status) >> 16) & 0x1fff)
#define EMAC_RXDESC_STATUS_ES		(1u << 15)
#define EMAC_RXDESC_STATUS_FS		(1u << 9)
#define EMAC_RXDESC_STATUS_LD		(1u << 8)

#define EMAC_DESC_CNTL_CHAIN	(1u << 24)

#define EMAC_TXDESC_CNTL_IC	(1u << 31)
#define EMAC_TXDESC_CNTL_LS	(1u << 30)
#define EMAC_TXDESC_CNTL_FS	(1u << 29)

union emac_mac_conf {
	uint32_t dw;
	struct {
		uint32_t prelen		:	2;
		uint32_t re		:	1;
		uint32_t te		:	1;
		uint32_t dc		:	1;
		uint32_t bl		:	2;
		uint32_t acs		:	1;
		uint32_t lud		:	1;
		uint32_t dr		:	1;
		uint32_t ipc		:	1;
		uint32_t dm		:	1;
		uint32_t lm		:	1;
		uint32_t diso		:	1;
		uint32_t fes		:	1;
		uint32_t ps		:	1;
		uint32_t dcrs		:	1;
		uint32_t ifg		:	3;
		uint32_t je		:	1;
		uint32_t be		:	1;
		uint32_t jd		:	1;
		uint32_t wd		:	1;
		uint32_t tc		:	1;
		uint32_t cst		:	1;
		uint32_t		:	1;
		uint32_t twokpe		:	1;
		uint32_t		:	4;
	};
};

union emac_mac_frame_filter {
	uint32_t dw;
	struct {
		uint32_t pr		:	1;
		uint32_t huc		:	1;
		uint32_t hmc		:	1;
		uint32_t daif		:	1;
		uint32_t pm		:	1;
		uint32_t dbf		:	1;
		uint32_t pcf		:	2;
		uint32_t saif		:	1;
		uint32_t saf		:	1;
		uint32_t hpf		:	1;
		uint32_t		:	5;
		uint32_t vtfe		:	1;
		uint32_t		:	3;
		uint32_t ipfe		:	1;
		uint32_t dntu		:	1;
		uint32_t		:	9;
		uint32_t ra		:	1;
	};
};

union emac_gmii_address {
	uint32_t dw;
	struct {
		uint32_t gb		:	1;
		uint32_t gw		:	1;
		uint32_t cr		:	4;
		uint32_t gr		:	5;
		uint32_t pa		:	5;
		uint32_t		:	16;
	};
};

union emac_gmii_data {
	uint32_t dw;
	struct {
		uint32_t gd		:	16;
		uint32_t		:	16;
	};
};

union emac_flow_control {
	uint32_t dw;
	struct {
		uint32_t fca_bpa	:	1;
		uint32_t tfe		:	1;
		uint32_t rfe		:	1;
		uint32_t up		:	1;
		uint32_t plt		:	2;
		uint32_t		:	1;
		uint32_t dzpq		:	1;
		uint32_t		:	8;
		uint32_t pt		:	16;
	};
};

union emac_vlan_tag {
	uint32_t dw;
	struct {
		uint32_t vl		:	16;
		uint32_t evt		:	1;
		uint32_t vtim		:	1;
		uint32_t esvl		:	1;
		uint32_t vthm		:	1;
		uint32_t		:	12;
	};
};

union emac_version {
	uint32_t dw;
	struct {
		uint32_t snpsver	:	8;
		uint32_t userver	:	8;
		uint32_t		:	16;
	};
};

union emac_mac_address_high {
	uint32_t dw;
	struct {
		uint32_t addrhi		:	16;
		uint32_t		:	8;
		uint32_t mbc_0		:	1;
		uint32_t mbc_1		:	1;
		uint32_t mbc_2		:	1;
		uint32_t mbc_3		:	1;
		uint32_t mbc_4		:	1;
		uint32_t mbc_5		:	1;
		uint32_t sa		:	1;
		uint32_t ae		:	1;
	};
};

union emac_mac_address_low {
	uint32_t dw;
	struct {
		uint32_t addrlo		:	32;
	};
};

union emac_mii_control_status {
	uint32_t dw;
	struct {
		uint32_t lnkmod		:	1;
		uint32_t lnkspeed	:	2;
		uint32_t lnksts		:	1;
		uint32_t		:	28;
	};
};

union emac_mmc_control {
	uint32_t dw;
	struct {
		uint32_t cntrst		:	1;
		uint32_t cntstopro	:	1;
		uint32_t rstonrd	:	1;
		uint32_t cntfreez	:	1;
		uint32_t cntprst	:	1;
		uint32_t cntprstlvl	:	1;
		uint32_t		:	2;
		uint32_t ucdbc		:	1;
		uint32_t		:	23;
	};
};

union emac_dma_bus_mode {
	uint32_t dw;
	struct {
		uint32_t swr		:	1;
		uint32_t		:	1;
		uint32_t dsl		:	5;
		uint32_t atds		:	1;
		uint32_t pbl		:	6;
		uint32_t		:	2;
		uint32_t fb		:	1;
		uint32_t rpbl		:	6;
		uint32_t usp		:	1;
		uint32_t eightxpbl	:	1;
		uint32_t aal		:	1;
		uint32_t		:	6;
	};
};

union emac_dma_status {
	uint32_t dw;
	struct {
		uint32_t ti		:	1;
		uint32_t tps		:	1;
		uint32_t tu		:	1;
		uint32_t tjt		:	1;
		uint32_t ovf		:	1;
		uint32_t unf		:	1;
		uint32_t ri		:	1;
		uint32_t ru		:	1;
		uint32_t rps		:	1;
		uint32_t rwt		:	1;
		uint32_t eti		:	1;
		uint32_t		:	2;
		uint32_t fbi		:	1;
		uint32_t eri		:	1;
		uint32_t ais		:	1;
		uint32_t nis		:	1;
		uint32_t rs		:	3;
		uint32_t ts		:	3;
		uint32_t eb		:	3;
		uint32_t gli		:	1;
		uint32_t gmi		:	1;
		uint32_t		:	1;
		uint32_t tti		:	1;
		uint32_t glpii		:	1;
		uint32_t		:	1;
	};
};

union emac_dma_operation_mode {
	uint32_t dw;
	struct {
		uint32_t		:	1;
		uint32_t sr		:	1;
		uint32_t osf		:	1;
		uint32_t rtc		:	2;
		uint32_t		:	1;
		uint32_t fuf		:	1;
		uint32_t fef		:	1;
		uint32_t efc		:	1;
		uint32_t rfa		:	2;
		uint32_t rfd		:	2;
		uint32_t st		:	1;
		uint32_t ttc		:	3;
		uint32_t		:	3;
		uint32_t ftf		:	1;
		uint32_t tsf		:	1;
		uint32_t		:	2;
		uint32_t dff		:	1;
		uint32_t rsf		:	1;
		uint32_t dt		:	1;
		uint32_t		:	5;
	};
};

union emac_dma_int_enable {
	uint32_t dw;
	struct {
		uint32_t tie		:	1;
		uint32_t tse		:	1;
		uint32_t tue		:	1;
		uint32_t tje		:	1;
		uint32_t ove		:	1;
		uint32_t une		:	1;
		uint32_t rie		:	1;
		uint32_t rue		:	1;
		uint32_t rse		:	1;
		uint32_t rwe		:	1;
		uint32_t ete		:	1;
		uint32_t		:	2;
		uint32_t fbe		:	1;
		uint32_t ere		:	1;
		uint32_t aie		:	1;
		uint32_t nie		:	1;
		uint32_t		:	15;
	};
};

#define EMAC_MAC_CONF			0x0000
#define EMAC_MAC_FRAME_FILTER		0x0004
#define EMAC_MAC_HASHTABLE_HIGH		0x0008
#define EMAC_MAC_HASHTABLE_LOW		0x000c
#define EMAC_GMII_ADDRESS		0x0010
#define EMAC_GMII_DATA			0x0014
#define EMAC_FLOW_CONTROL		0x0018
#define EMAC_VLAN_TAG			0x001c
#define EMAC_VERSION			0x0020
#define EMAC_LPI_CONTROL_STATUS		0x0030
#define EMAC_LPI_TIMERS_CONTROL		0x0034
#define EMAC_INT_STATUS			0x0038
#define EMAC_INT_MASK			0x003c
#define EMAC_MAC_ADDRESS_HIGH(i)	(0x0040 + (i) * 8)
#define EMAC_MAC_ADDRESS_LOW(i)		(0x0044 + (i) * 8)
#define EMAC_MII_CONTROL_STATUS		0x00d8
#define EMAC_MMC_CONTROL		0x0100
#define EMAC_MMC_RX_INT			0x0104
#define EMAC_MMC_TX_INT			0x0108
#define EMAC_MMC_RX_INT_MASK		0x010c
#define EMAC_MMC_TX_INT_MASK		0x0110
#define EMAC_MMC_IPC_RX_INT_MASK	0x0200
#define EMAC_MMC_IPC_RX_INT		0x0208

#define EMAC_DMA_BUS_MODE		0x1000
#define EMAC_DMA_TX_POLL_DEMAND		0x1004
#define EMAC_DMA_RX_POLL_DEMAND		0x1008
#define EMAC_DMA_RX_DESC_ADDRESS	0x100c
#define EMAC_DMA_TX_DESC_ADDRESS	0x1010
#define EMAC_DMA_STATUS			0x1014
#define EMAC_DMA_OPERATION_MODE		0x1018
#define EMAC_DMA_INT_ENABLE		0x101c

