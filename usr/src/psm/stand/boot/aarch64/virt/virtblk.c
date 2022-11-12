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
 * Copyright 2020 Hayashi Naoyuki
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include <sys/byteorder.h>
#include <sys/sysmacros.h>

#include <sys/ethernet.h>
#include <sys/platmod.h>
#include "prom_dev.h"
#include "virtblk.h"
#include "virtio.h"
#include "boot_plat.h"

struct virtio_blk_req {
	uint32_t type;
	uint32_t reserved;
	uint64_t sector;
};
#define VIRTIO_BLK_T_IN		0
#define VIRTIO_BLK_T_OUT	1
#define VIRTIO_BLK_T_FLUSH	4
#define VIRTIO_BLK_S_OK		0
#define VIRTIO_BLK_S_IOERR	1
#define VIRTIO_BLK_S_UNSUPP	2

#define VIRTIO_BLK_F_BARRIER	(1u << 0)
#define VIRTIO_BLK_F_SIZE_MAX	(1u << 1)
#define VIRTIO_BLK_F_SEG_MAX	(1u << 2)
#define VIRTIO_BLK_F_GEOMETRY	(1u << 4)
#define VIRTIO_BLK_F_RO		(1u << 5)
#define VIRTIO_BLK_F_BLK_SIZE	(1u << 6)
#define VIRTIO_BLK_F_SCSI	(1u << 7)
#define VIRTIO_BLK_F_FLUSH	(1u << 9)
#define VIRTIO_BLK_F_TOPOLOGY	(1u << 10)
#define VIRTIO_BLK_F_CONFIG_WCE	(1u << 11)

struct virtio_blk_config {
	uint64_t capacity;
	uint32_t size_max;
	uint32_t seg_max;
	struct virtio_blk_geometry {
		uint16_t cylinders;
		uint8_t heads;
		uint8_t sectors;
	} geometry;
	uint32_t blk_size;
	struct virtio_blk_topology {
		uint8_t physical_block_exp;
		uint8_t alignment_offset;
		uint16_t min_io_size;
		uint32_t opt_io_size;
	} topology;
	uint8_t writeback;
};

#define VIRTIO_MMIO_BLK_CONFIG(base)		((volatile struct virtio_blk_config *)((uintptr_t)(base) + 0x100))


#define BUFFER_SIZE (sizeof(struct virtio_blk_req))

struct virtblk_sc {
	uintptr_t base;
	struct virtq_cb qcb;
};

static struct virtblk_sc *virtblk_dev[3];

static int
virtblk_setup_buffer(struct virtblk_sc *sc)
{
	memset(&sc->qcb, 0, sizeof(struct virtq_cb));
	sc->qcb.queue = (struct virtq *)roundup((uintptr_t)kmem_alloc(sizeof(struct virtq) + MMU_PAGESIZE, 0), MMU_PAGESIZE);
	memset(sc->qcb.queue, 0, sizeof(struct virtq));
	for (int j = 0; j < VIRTQ_SIZE; j++) {
		virtq_free(&sc->qcb, j);
	}
	VIRTIO_MMIO_QUEUE_SEL(sc->base) = 0;
	VIRTIO_MMIO_QUEUE_NUM(sc->base) = VIRTQ_SIZE;
	VIRTIO_MMIO_QUEUE_ALIGN(sc->base) = 4;
	VIRTIO_MMIO_QUEUE_PFN(sc->base) = (((uintptr_t)sc->qcb.queue) >> MMU_PAGESHIFT);
	return 0;
}

static int
virtblk_chip_reset(struct virtblk_sc *sc)
{
	VIRTIO_MMIO_STATUS(sc->base) = 0;
	VIRTIO_MMIO_STATUS(sc->base) |= VIRTIO_STATUS_ACKNOWLEDGE;
	if (VIRTIO_MMIO_STATUS(sc->base) & VIRTIO_STATUS_FAILED)
		return -1;
	VIRTIO_MMIO_STATUS(sc->base) |= VIRTIO_STATUS_DRIVER;
	if (VIRTIO_MMIO_STATUS(sc->base) & VIRTIO_STATUS_FAILED)
		return -1;
	uint32_t features = VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_GEOMETRY | VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_TOPOLOGY;
	VIRTIO_MMIO_HOST_FEATURES_SEL(sc->base) = 0;
	if ((VIRTIO_MMIO_HOST_FEATURES(sc->base) & features) != features)
		return -1;
	VIRTIO_MMIO_GUEST_FEATURES_SEL(sc->base) = 0;
	VIRTIO_MMIO_GUEST_FEATURES(sc->base) = features;

	VIRTIO_MMIO_QUEUE_SEL(sc->base) = 0;
	if (VIRTIO_MMIO_QUEUE_NUM_MAX(sc->base) < VIRTQ_SIZE)
		return -1;

	VIRTIO_MMIO_GUEST_PAGE_SIZE(sc->base) = MMU_PAGESIZE;
	return 0;
}

static int
virtblk_match(const char *name)
{
	pnode_t node = prom_finddevice(name);
	if (node <= 0)
		return 0;
	if (!prom_is_compatible(node, "virtio-blk"))
		return 0;
	return 1;
}
static int
virtblk_open(const char *name)
{
	if (!virtblk_match(name))
		return -1;

	int fd;

	for (fd = 0; fd < sizeof(virtblk_dev) / sizeof(virtblk_dev[0]); fd++) {
		if (virtblk_dev[fd] == NULL)
			break;
	}
	if (fd == sizeof(virtblk_dev) / sizeof(virtblk_dev[0]))
		return -1;
	struct virtblk_sc *sc = kmem_alloc(sizeof(struct virtblk_sc), 0);
	memset(sc, 0, sizeof(struct virtblk_sc));

	uint64_t base;
	if (prom_get_reg_address(prom_finddevice(name), 0, &base) != 0)
		return -1;

	sc->base = base;

	if (virtblk_chip_reset(sc) < 0)
		return -1;

	if (virtblk_setup_buffer(sc) < 0)
		return -1;

	VIRTIO_MMIO_STATUS(sc->base) |= VIRTIO_STATUS_DRIVER_OK;
	VIRTIO_MMIO_QUEUE_NOTIFY(sc->base) = 0;

	virtblk_dev[fd] = sc;
	return fd;
}

static int
virtblk_close(int dev)
{
	if (!(0 <= dev && dev < sizeof(virtblk_dev) / sizeof(virtblk_dev[0])))
		return -1;

	struct virtblk_sc *sc = virtblk_dev[dev];
	if (!sc)
		return -1;

	VIRTIO_MMIO_STATUS(sc->base) = 0;

	virtblk_dev[dev] = NULL;
	return 0;
}

static ssize_t
virtblk_read(int dev, caddr_t buf, size_t buf_len, uint_t startblk)
{
	if (!(0 <= dev && dev < sizeof(virtblk_dev) / sizeof(virtblk_dev[0])))
		return -1;

	struct virtblk_sc *sc = virtblk_dev[dev];
	if (!sc)
		return -1;

	if ((buf_len % 512) != 0)
		return -1;

	size_t req_len = buf_len;
	while (buf_len > 0) {
		int index = virtq_alloc(&sc->qcb);
		struct virtq_desc desc[3] = {0};

		size_t req_len = buf_len;
		if (req_len > 0x10000)
			req_len = 0x10000;

		struct virtio_blk_req req = {
			.type = VIRTIO_BLK_T_IN,
			.sector = startblk,
		};
		uint8_t status = 0;

		desc[0].addr = (uint64_t)&req;
		desc[0].len = sizeof(req);
		desc[0].flags = VIRTQ_DESC_F_NEXT;
		desc[0].next = 1;
		desc[1].addr = (uint64_t)buf;
		desc[1].len = req_len;
		desc[1].flags = VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT;
		desc[1].next = 2;
		desc[2].addr = (uint64_t)&status;
		desc[2].len = 1;
		desc[2].flags = VIRTQ_DESC_F_WRITE;
		desc[2].next = 0;
		sc->qcb.queue->desc[index].addr = (uint64_t)desc;
		sc->qcb.queue->desc[index].len = sizeof(desc);
		sc->qcb.queue->desc[index].flags = VIRTQ_DESC_F_INDIRECT;
		sc->qcb.queue->desc[index].next = 0;

		virtq_push(&sc->qcb, index);
		VIRTIO_MMIO_QUEUE_NOTIFY(sc->base) = 0;

		uint32_t len;
		int id;
		for (;;) {
			virtq_pop(&sc->qcb, &id, &len);
			if (id == index)
				break;
		}
		virtq_free(&sc->qcb, index);
		if (status != VIRTIO_BLK_S_OK)
			return -1;

		buf += req_len;
		buf_len -= req_len;
		startblk += (req_len / 512);
	}

	return req_len;
}

static struct prom_dev virtblk_prom_dev =
{
	.match = virtblk_match,
	.open = virtblk_open,
	.read = virtblk_read,
	.close = virtblk_close,
};

void init_virtblk(void)
{
	prom_register(&virtblk_prom_dev);
}

