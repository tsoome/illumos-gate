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
#include "virtnet.h"
#include "virtio.h"
#include "boot_plat.h"

struct virtio_net_config {
	uint8_t mac[6];
	uint16_t status;
	uint16_t max_virtqueue_pairs;
};

#define VIRTIO_MMIO_NET_CONFIG(base)		((volatile struct virtio_net_config *)((uintptr_t)(base) + 0x100))

struct virtio_net_hdr {
	uint8_t flags;
	uint8_t gso_type;
	uint16_t hdr_len;
	uint16_t gso_size;
	uint16_t csum_start;
	uint16_t csum_offset;
};

#define VIRTIO_NET_F_MAC	(1u << 5)
#define VIRTIO_NET_F_STATUS	(1u << 16)

#define VIRTIO_NET_S_LINK_UP	(1u << 0)
#define VIRTIO_NET_S_ANNOUNCE	(1u << 1)

#define BUFFER_SIZE (1536 + sizeof(struct virtio_net_hdr))

enum {
	VIRTNET_RX_QUEUE,
	VIRTNET_TX_QUEUE,
	VIRTNET_NUM_QUEUE
};

struct virtnet_sc {
	uintptr_t base;
	struct virtq_cb qcb[VIRTNET_NUM_QUEUE];
	caddr_t buffer[VIRTNET_NUM_QUEUE];
};

static struct virtnet_sc *virtnet_dev[3];

static int
virtnet_setup_buffer(struct virtnet_sc *sc)
{
	for (int i = 0; i < VIRTNET_NUM_QUEUE; i++) {
		memset(&sc->qcb[i], 0, sizeof(struct virtq_cb));
		sc->qcb[i].queue = (struct virtq *)roundup((uintptr_t)kmem_alloc(sizeof(struct virtq) + MMU_PAGESIZE, 0), MMU_PAGESIZE);
		memset(sc->qcb[i].queue, 0, sizeof(struct virtq));
		sc->buffer[i] = kmem_alloc(BUFFER_SIZE * VIRTQ_SIZE, 0);
		for (int j = 0; j < VIRTQ_SIZE; j++) {
			sc->qcb[i].queue->desc[j].addr = (uint64_t)(sc->buffer[i] + BUFFER_SIZE * j);
			sc->qcb[i].queue->desc[j].len = BUFFER_SIZE;
			sc->qcb[i].queue->desc[j].flags = 0;
			sc->qcb[i].queue->desc[j].next = 0;
			virtq_free(&sc->qcb[i], j);
		}
		VIRTIO_MMIO_QUEUE_SEL(sc->base) = i;
		VIRTIO_MMIO_QUEUE_NUM(sc->base) = VIRTQ_SIZE;
		VIRTIO_MMIO_QUEUE_ALIGN(sc->base) = 4;
		VIRTIO_MMIO_QUEUE_PFN(sc->base) = (((uintptr_t)sc->qcb[i].queue) >> MMU_PAGESHIFT);
	}
	return 0;
}

static int
virtnet_chip_reset(struct virtnet_sc *sc)
{
	VIRTIO_MMIO_STATUS(sc->base) = 0;
	VIRTIO_MMIO_STATUS(sc->base) |= VIRTIO_STATUS_ACKNOWLEDGE;
	if (VIRTIO_MMIO_STATUS(sc->base) & VIRTIO_STATUS_FAILED)
		return -1;
	VIRTIO_MMIO_STATUS(sc->base) |= VIRTIO_STATUS_DRIVER;
	if (VIRTIO_MMIO_STATUS(sc->base) & VIRTIO_STATUS_FAILED)
		return -1;
	VIRTIO_MMIO_HOST_FEATURES_SEL(sc->base) = 0;
	if ((VIRTIO_MMIO_HOST_FEATURES(sc->base) & VIRTIO_NET_F_MAC) != VIRTIO_NET_F_MAC)
		return -1;
	VIRTIO_MMIO_GUEST_FEATURES_SEL(sc->base) = 0;
	VIRTIO_MMIO_GUEST_FEATURES(sc->base) = VIRTIO_NET_F_MAC;
	for (int i = 0; i < VIRTNET_NUM_QUEUE; i++) {
		VIRTIO_MMIO_QUEUE_SEL(sc->base) = i;
		if (VIRTIO_MMIO_QUEUE_NUM_MAX(sc->base) < VIRTQ_SIZE)
			return -1;
	}
	VIRTIO_MMIO_GUEST_PAGE_SIZE(sc->base) = MMU_PAGESIZE;
	return 0;
}

static int
virtnet_match(const char *name)
{
	pnode_t node = prom_finddevice(name);
	if (node <= 0)
		return 0;
	if (!prom_is_compatible(node, "virtio-net"))
		return 0;
	return 1;
}
static int
virtnet_open(const char *name)
{
	if (!virtnet_match(name))
		return -1;

	int fd;

	for (fd = 0; fd < sizeof(virtnet_dev) / sizeof(virtnet_dev[0]); fd++) {
		if (virtnet_dev[fd] == NULL)
			break;
	}
	if (fd == sizeof(virtnet_dev) / sizeof(virtnet_dev[0]))
		return -1;
	struct virtnet_sc *sc = kmem_alloc(sizeof(struct virtnet_sc), 0);
	memset(sc, 0, sizeof(struct virtnet_sc));

	uint64_t base;
	if (prom_get_reg_address(prom_finddevice(name), 0, &base) != 0)
		return -1;

	sc->base = base;

	if (virtnet_chip_reset(sc) < 0)
		return -1;

	if (virtnet_setup_buffer(sc) < 0)
		return -1;

	VIRTIO_MMIO_STATUS(sc->base) |= VIRTIO_STATUS_DRIVER_OK;

	for (;;) {
		int index = virtq_alloc(&sc->qcb[VIRTNET_RX_QUEUE]);
		if (index < 0)
			break;
		sc->qcb[VIRTNET_RX_QUEUE].queue->desc[index].len = BUFFER_SIZE;
		sc->qcb[VIRTNET_RX_QUEUE].queue->desc[index].flags = VIRTQ_DESC_F_WRITE;
		virtq_push(&sc->qcb[VIRTNET_RX_QUEUE], index);
	}
	VIRTIO_MMIO_QUEUE_NOTIFY(sc->base) = VIRTNET_RX_QUEUE;

	char *str;
	str = "bootp";
	prom_setprop(prom_chosennode(), "net-config-strategy", (caddr_t)str, strlen(str) + 1);
	str = "ethernet,100,rj45,full";
	prom_setprop(prom_chosennode(), "network-interface-type", (caddr_t)str, strlen(str) + 1);
	str = "Ethernet controller";
	prom_setprop(prom_finddevice(name), "model", (caddr_t)str, strlen(str) + 1);
	str = "okay";
	prom_setprop(prom_finddevice(name), "status", (caddr_t)str, strlen(str) + 1);

	virtnet_dev[fd] = sc;
	return fd;
}

static int
virtnet_close(int dev)
{
	if (!(0 <= dev && dev < sizeof(virtnet_dev) / sizeof(virtnet_dev[0])))
		return -1;

	struct virtnet_sc *sc = virtnet_dev[dev];
	if (!sc)
		return -1;
	for (int i = 0; i < VIRTNET_NUM_QUEUE; i++) {
		VIRTIO_MMIO_QUEUE_SEL(sc->base) = i;
		VIRTIO_MMIO_QUEUE_PFN(sc->base) = 0;
	}
	VIRTIO_MMIO_STATUS(sc->base) = 0;

	virtnet_dev[dev] = NULL;
	return 0;
}

static int
virtnet_getmacaddr(ihandle_t dev, caddr_t ea)
{
	if (!(0 <= dev && dev < sizeof(virtnet_dev) / sizeof(virtnet_dev[0])))
		return -1;

	struct virtnet_sc *sc = virtnet_dev[dev];
	if (!sc)
		return -1;
	for (int i = 0; i < 6; i++)
		ea[i] = VIRTIO_MMIO_NET_CONFIG(sc->base)->mac[i];
	return 0;
}

static ssize_t
virtnet_send(int dev, caddr_t data, size_t packet_length, uint_t startblk)
{
	if (!(0 <= dev && dev < sizeof(virtnet_dev) / sizeof(virtnet_dev[0])))
		return -1;

	struct virtnet_sc *sc = virtnet_dev[dev];
	if (!sc)
		return -1;

	int index;
	for (;;) {
		for (;;) {
			int id;
			uint32_t len;
			virtq_pop(&sc->qcb[VIRTNET_TX_QUEUE], &id, &len);
			if (id < 0)
				break;
			virtq_free(&sc->qcb[VIRTNET_TX_QUEUE], id);
		}
		index = virtq_alloc(&sc->qcb[VIRTNET_TX_QUEUE]);
		if (index >= 0)
			break;
	}

	caddr_t buffer = (sc->buffer[VIRTNET_TX_QUEUE] + BUFFER_SIZE * index);
	memset(buffer, 0, sizeof(struct virtio_net_hdr));
	memcpy(buffer + sizeof(struct virtio_net_hdr), data, packet_length);
	sc->qcb[VIRTNET_TX_QUEUE].queue->desc[index].len = sizeof(struct virtio_net_hdr) + packet_length;
	sc->qcb[VIRTNET_TX_QUEUE].queue->desc[index].flags = 0;

	virtq_push(&sc->qcb[VIRTNET_TX_QUEUE], index);
	VIRTIO_MMIO_QUEUE_NOTIFY(sc->base) = VIRTNET_TX_QUEUE;

	return packet_length;
}

static ssize_t
virtnet_recv(int dev, caddr_t buf, size_t buf_len, uint_t startblk)
{
	if (!(0 <= dev && dev < sizeof(virtnet_dev) / sizeof(virtnet_dev[0])))
		return -1;

	struct virtnet_sc *sc = virtnet_dev[dev];
	if (!sc)
		return -1;

	uint32_t len;
	int index;
	virtq_pop(&sc->qcb[VIRTNET_RX_QUEUE], &index, &len);
	if (index < 0)
		return 0;
	caddr_t buffer = (sc->buffer[VIRTNET_RX_QUEUE] + BUFFER_SIZE * index);
	if (len > sizeof(struct virtio_net_hdr)) {
		memcpy(buf, buffer + sizeof(struct virtio_net_hdr), len - sizeof(struct virtio_net_hdr));
	}

	sc->qcb[VIRTNET_RX_QUEUE].queue->desc[index].len = BUFFER_SIZE;
	sc->qcb[VIRTNET_RX_QUEUE].queue->desc[index].flags = VIRTQ_DESC_F_WRITE;
	virtq_push(&sc->qcb[VIRTNET_RX_QUEUE], index);
	VIRTIO_MMIO_QUEUE_NOTIFY(sc->base) = VIRTNET_RX_QUEUE;

	return (len > sizeof(struct virtio_net_hdr)) ? len - sizeof(struct virtio_net_hdr): -1;
}

static struct prom_dev virtnet_prom_dev =
{
	.match = virtnet_match,
	.open = virtnet_open,
	.write = virtnet_send,
	.read = virtnet_recv,
	.close = virtnet_close,
	.getmacaddr = virtnet_getmacaddr,
};

void init_virtnet(void)
{
	prom_register(&virtnet_prom_dev);
}

