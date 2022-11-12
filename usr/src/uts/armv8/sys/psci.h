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

#ifndef _SYS_PSCI_H
#define _SYS_PSCI_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

enum {
	PSCI_SUCCESS		= 0,
	PSCI_NOT_SUPPORTED	= -1,
	PSCI_INVALID_PARAMETERS	= -2,
	PSCI_DENIED		= -3,
	PSCI_ALREADY_ON		= -4,
	PSCI_ON_PENDING		= -5,
	PSCI_INTERNAL_FAILURE	= -6,
	PSCI_NOT_PRESENT	= -7,
	PSCI_DISABLED		= -8,
	PSCI_INVALID_ADDRESS	= -9,
};

void psci_init(void);
uint32_t psci_version(void);
int32_t psci_cpu_suspend(uint32_t power_state, uint64_t entry_point_address, uint64_t context_id);
int32_t psci_cpu_off(void);
int32_t psci_cpu_on(uint64_t target_cpu, uint64_t entry_point_address, uint64_t context_id);
int32_t psci_affinity_info(uint64_t target_affinity, uint32_t lowest_affinity_level);
int32_t psci_migrate(uint64_t target_cpu);
int32_t psci_migrate_info_type(void);
uint64_t psci_migrate_info_up_cpu(void);
void psci_system_off(void);
void psci_system_reset(void);
int32_t psci_features(uint32_t psci_func_id);
int32_t psci_cpu_freeze(void);
int32_t psci_cpu_default_suspend(uint64_t entry_point_address, uint64_t context_id);
int32_t psci_node_hw_state(uint64_t target_cpu, uint32_t power_level);
int32_t psci_system_suspend(uint64_t entry_point_address, uint64_t context_id);
int32_t psci_set_suspend_mode(uint32_t mode);
uint64_t psci_stat_residency(uint64_t target_cpu, uint32_t power_state);
uint64_t psci_stat_count(uint64_t target_cpu, uint32_t power_state);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PSCI_H */
