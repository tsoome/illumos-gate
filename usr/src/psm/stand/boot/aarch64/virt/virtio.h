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
#include <stdbool.h>

#define VIRTIO_MMIO_MAGIC_VALUE(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x000)
#define VIRTIO_MMIO_VERSION(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x004)
#define VIRTIO_MMIO_DEVICE_ID(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x008)
#define VIRTIO_MMIO_VENDOR_ID(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x00c)
#define VIRTIO_MMIO_HOST_FEATURES(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x010)
#define VIRTIO_MMIO_HOST_FEATURES_SEL(base)	*(volatile uint32_t *)((uintptr_t)(base) + 0x014)
#define VIRTIO_MMIO_GUEST_FEATURES(base)	*(volatile uint32_t *)((uintptr_t)(base) + 0x020)
#define VIRTIO_MMIO_GUEST_FEATURES_SEL(base)	*(volatile uint32_t *)((uintptr_t)(base) + 0x024)
#define VIRTIO_MMIO_GUEST_PAGE_SIZE(base)	*(volatile uint32_t *)((uintptr_t)(base) + 0x028)
#define VIRTIO_MMIO_QUEUE_SEL(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x030)
#define VIRTIO_MMIO_QUEUE_NUM_MAX(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x034)
#define VIRTIO_MMIO_QUEUE_NUM(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x038)
#define VIRTIO_MMIO_QUEUE_ALIGN(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x03c)
#define VIRTIO_MMIO_QUEUE_PFN(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x040)
#define VIRTIO_MMIO_QUEUE_NOTIFY(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x050)
#define VIRTIO_MMIO_INTERRUPT_STATUS(base)	*(volatile uint32_t *)((uintptr_t)(base) + 0x060)
#define VIRTIO_MMIO_INTERRUPT_ACK(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x064)
#define VIRTIO_MMIO_STATUS(base)		*(volatile uint32_t *)((uintptr_t)(base) + 0x070)

#define VIRTIO_STATUS_ACKNOWLEDGE		(1u << 0)
#define VIRTIO_STATUS_DRIVER			(1u << 1)
#define VIRTIO_STATUS_DRIVER_OK			(1u << 2)
#define VIRTIO_STATUS_DEVICE_NEEDS_RESET	(1u << 7)
#define VIRTIO_STATUS_FAILED			(1u << 8)

#define VIRTQ_DESC_F_NEXT	(1u << 0)
#define VIRTQ_DESC_F_WRITE	(1u << 1)
#define VIRTQ_DESC_F_INDIRECT	(1u << 2)

#define VIRTQ_SIZE	128
struct virtq_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};
struct virtq_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[VIRTQ_SIZE];
};
struct virtq_used_elem {
	uint32_t id;
	uint32_t len;
};
struct virtq_used {
	uint16_t flags;
	uint16_t idx;
	struct virtq_used_elem ring[VIRTQ_SIZE];
};
struct virtq {
	struct virtq_desc desc[VIRTQ_SIZE];
	struct virtq_avail avail;
	struct virtq_used used;
};

struct virtq_cb {
	struct virtq *queue;
	uint16_t used;
	uint64_t free[(VIRTQ_SIZE + 63) / 64];
};

static inline int
virtq_alloc(struct virtq_cb *cb)
{
	for (size_t i = 0; i < sizeof(cb->free) / sizeof(cb->free[0]); i++) {
		if (cb->free[i] != 0) {
			int a = __builtin_ctzl(cb->free[i]);
			cb->free[i] &= ~(1ul << a);
			return 64 * i + a;
		}
	}
	return -1;
}
static inline void
virtq_free(struct virtq_cb *cb, int index)
{
	cb->free[index / 64] |= (1ul << (index % 64));
}
static inline void
virtq_push(struct virtq_cb *cb, int index)
{
	cb->queue->avail.ring[cb->queue->avail.idx % VIRTQ_SIZE] = index;
	__sync_synchronize();
	cb->queue->avail.idx++;
}
static inline void
virtq_pop(struct virtq_cb *cb, int *id, uint32_t *len)
{
	uint16_t idx = cb->queue->used.idx;
	__sync_synchronize();
	if (idx == cb->used) {
		*id = -1;
		*len = 0;
	} else {
		*id = cb->queue->used.ring[cb->used % VIRTQ_SIZE].id;
		*len = cb->queue->used.ring[cb->used % VIRTQ_SIZE].len;
		cb->used++;
	}
}

