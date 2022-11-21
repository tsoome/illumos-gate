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

#ifndef _IO_DWMAC_H
#define _IO_DWMAC_H

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/types.h>
#include <sys/platform.h>
#include <sys/mac.h>
#include <sys/mii.h>
#include <sys/ethernet.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>


struct emac_reg {
	ddi_acc_handle_t handle;
	caddr_t addr;
};

struct emac_dma {
	caddr_t addr;
	size_t size;
	uint64_t dmac_addr;
	ddi_dma_handle_t dma_handle;
	ddi_acc_handle_t mem_handle;
};

struct emac_sc;
struct emac_packet {
	struct emac_packet *next;
	struct emac_dma dma;
	mblk_t *mp;
	frtn_t free_rtn;
	struct emac_sc *sc;
};

struct emac_desc_ring {
	int slots;
	int index;
};

struct emac_mcast {
	list_node_t		node;
	uint8_t			addr[ETHERADDRL];
};

#define TX_DESC_NUM	512
#define RX_DESC_NUM	256
#define RX_PKT_NUM_MAX	256

struct emac_desc_tx_ring {
	struct emac_dma desc;
	struct emac_packet *pkt[TX_DESC_NUM];

	mblk_t *mp[TX_DESC_NUM];

	int head;
	int tail;
};

struct emac_desc_rx_ring {
	struct emac_dma desc;
	struct emac_packet *pkt[RX_DESC_NUM];
	int index;
};

struct emac_sc {
	dev_info_t *dip;
	kmutex_t intrlock;
	kmutex_t rx_pkt_lock;
	int rx_pkt_num;

	mac_handle_t mac_handle;
	mii_handle_t mii_handle;
	ddi_intr_handle_t intr_handle;
	link_duplex_t phy_duplex;

	mac_register_t *macp;
	struct emac_reg reg;
	struct emac_desc_tx_ring tx_ring;
	struct emac_desc_rx_ring rx_ring;
	int running;
	int phy_speed;
	int phy_id;
	uint8_t dev_addr[ETHERADDRL];
	struct emac_packet *rx_pkt_free;
	list_t mcast;
	uint32_t default_mtu;
	uint32_t pkt_size;
};

#ifdef __cplusplus
}
#endif

#endif	/* _IO_DWMAC_H */
