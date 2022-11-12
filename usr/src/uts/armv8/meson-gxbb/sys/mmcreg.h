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
 * Copyright 2022 Hayashi Naoyuki
 */

#ifndef _IO_MMCREG_H
#define _IO_MMCREG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define SD_EMMC_CLOCK		0x00
#define SD_EMMC_DELAY		0x04
#define SD_EMMC_ADJUST		0x08
#define SD_EMMC_CALOUT		0x10
#define SD_EMMC_START		0x40
#define SD_EMMC_CFG		0x44
#define SD_EMMC_STATUS		0x48
#define SD_EMMC_IRQ_EN		0x4c
#define SD_EMMC_CMD_CFG		0x50
#define SD_EMMC_CMD_ARG		0x54
#define SD_EMMC_CMD_DAT		0x58
#define SD_EMMC_CMD_RSP0	0x5c
#define SD_EMMC_CMD_RSP1	0x60
#define SD_EMMC_CMD_RSP2	0x64
#define SD_EMMC_CMD_RSP3	0x68

union sd_emmc_clock {
	uint32_t dw;
	struct {
		uint32_t Cfg_div		:	6;
		uint32_t Cfg_src		:	2;
		uint32_t Cfg_co_phase		:	2;
		uint32_t Cfg_tx_phase		:	2;
		uint32_t Cfg_rx_phase		:	2;
		uint32_t Cfg_sram_pd		:	2;
		uint32_t Cfg_tx_delay		:	4;
		uint32_t Cfg_rx_delay		:	4;
		uint32_t Cfg_always_on		:	1;
		uint32_t Cfg_irq_sdio_sleep	:	1;
		uint32_t 			:	6;
	};
};

union sd_emmc_delay {
	uint32_t dw;
	struct {
		uint32_t Dly0	: 4;
		uint32_t Dly1	: 4;
		uint32_t Dly2	: 4;
		uint32_t Dly3	: 4;
		uint32_t Dly4	: 4;
		uint32_t Dly5	: 4;
		uint32_t Dly6	: 4;
		uint32_t Dly7	: 4;
	};
};

union sd_emmc_adjust {
	uint32_t dw;
	struct {
		uint32_t Dly8		: 4;
		uint32_t Dly9		: 4;
		uint32_t Cali_sel	: 4;
		uint32_t Cali_enable	: 1;
		uint32_t Adj_enable	: 1;
		uint32_t Cali_rise	: 1;
		uint32_t		: 1;
		uint32_t Adj_delay	: 6;
		uint32_t 		: 10;
	};
};

union sd_emmc_calout {
	uint32_t dw;
	struct {
		uint32_t Cali_idx	: 6;
		uint32_t		: 1;
		uint32_t Cali_vld	: 1;
		uint32_t Cali_setup	: 8;
		uint32_t 		: 16;
	};
};

union sd_emmc_start {
	uint32_t dw;
	struct {
		uint32_t Desc_int	: 1;
		uint32_t Desc_busy	: 1;
		uint32_t Desc_addr	: 30;
	};
};

union sd_emmc_cfg {
	uint32_t dw;
	struct {
		uint32_t Cfg_bus_width		: 2;
		uint32_t Cfg_ddr		: 1;
		uint32_t Cfg_dc_ugt		: 1;
		uint32_t Cfg_bl_len		: 4;
		uint32_t Cfg_resp_timeout	: 4;
		uint32_t Cfg_rc_cc		: 4;
		uint32_t Cfg_out_fall		: 1;
		uint32_t Cfg_blk_gap_ip		: 1;
		uint32_t Cfg_sdclk_always_on	: 1;
		uint32_t Cfg_ignore_owner	: 1;
		uint32_t Cfg_chk_ds		: 1;
		uint32_t Cfg_cmd_low		: 1;
		uint32_t Cfg_stop_clk		: 1;
		uint32_t Cfg_auto_clk		: 1;
		uint32_t Cfg_txd_add_err	: 1;
		uint32_t Cfg_txd_retry		: 1;
		uint32_t Cfg_irq_ds		: 1;
		uint32_t Cfg_err_abor		: 1;
		uint32_t Cfg_ip_txd_adj		: 4;
	};
};

union sd_emmc_status {
	uint32_t dw;
	struct {
		uint32_t error			:13;
		uint32_t			:19;
	};
	struct {
		uint32_t Rxd_err		: 8;
		uint32_t Txd_err		: 1;
		uint32_t Desc_err		: 1;
		uint32_t Resp_err		: 1;
		uint32_t Resp_timeout		: 1;
		uint32_t Desc_timeout		: 1;
		uint32_t End_of_Chain		: 1;
		uint32_t Resp_status		: 1;
		uint32_t IRQ_sdio		: 1;
		uint32_t DAT_i			: 8;
		uint32_t CMD_i			: 1;
		uint32_t DS			: 1;
		uint32_t Bus_fsm		: 4;
		uint32_t Desc_Busy		: 1;
		uint32_t Core_Busy		: 1;
	};
};

union sd_emmc_irq_en {
	uint32_t dw;
	struct {
		uint32_t error			:13;
		uint32_t			:19;
	};
	struct {
		uint32_t En_Rxd_err		: 8;
		uint32_t En_Txd_err		: 1;
		uint32_t En_Desc_err		: 1;
		uint32_t En_Resp_err		: 1;
		uint32_t En_Resp_timeout	: 1;
		uint32_t En_Desc_timeout	: 1;
		uint32_t En_End_of_Chain	: 1;
		uint32_t En_Resp_status		: 1;
		uint32_t En_IRQ_sdio		: 1;
		uint32_t Cfg_secure		: 1;
		uint32_t			: 15;
	};
};

union sd_emmc_cmd_cfg {
	uint32_t dw;
	struct {
		uint32_t Length		: 9;
		uint32_t Block_mode	: 1;
		uint32_t R1b		: 1;
		uint32_t End_of_chain	: 1;
		uint32_t Timeout	: 4;
		uint32_t No_resp	: 1;
		uint32_t No_cmd		: 1;
		uint32_t Data_io	: 1;
		uint32_t Data_wr	: 1;
		uint32_t Resp_nocrc	: 1;
		uint32_t Resp_128	: 1;
		uint32_t Resp_num	: 1;
		uint32_t Data_num	: 1;
		uint32_t Cmd_index	: 6;
		uint32_t Error		: 1;
		uint32_t Owner		: 1;
	};
};

#ifdef __cplusplus
}
#endif

#endif	/* _IO_MMCREG_H */
