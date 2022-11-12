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

#include <sys/platform.h>
#include "prom_dev.h"

#define UART_ADDR	UART_PHYS
#define UART_WFIFO	(*(volatile uint32_t *)(UART_ADDR + 0x00))
#define UART_RFIFO	(*(volatile uint32_t *)(UART_ADDR + 0x04))
#define UART_CONTROL	(*(volatile uint32_t *)(UART_ADDR + 0x08))
#define UART_STATUS	(*(volatile uint32_t *)(UART_ADDR + 0x0C))
#define UART_MISC	(*(volatile uint32_t *)(UART_ADDR + 0x10))
#define UART_REG5	(*(volatile uint32_t *)(UART_ADDR + 0x14))

#define UART_CONTROL_CLR_ERR	(1u << 24)
#define UART_CONTROL_RST_RX	(1u << 23)
#define UART_CONTROL_RST_TX	(1u << 22)
#define UART_CONTROL_ENB_RX	(1u << 13)
#define UART_CONTROL_ENB_TX	(1u << 12)

#define UART_STATUS_RECV_BUSY	(1u << 26)
#define UART_STATUS_XMIT_BUSY	(1u << 25)
#define UART_STATUS_TFIFO_EMPTY	(1u << 22)
#define UART_STATUS_TFIFO_FULL	(1u << 21)
#define UART_STATUS_RFIFO_EMPTY	(1u << 20)
#define UART_STATUS_RFIFO_FULL	(1u << 19)
#define UART_STATUS_ERR_WFIFO	(1u << 18)
#define UART_STATUS_ERR_FRAME	(1u << 17)
#define UART_STATUS_ERR_PARITY	(1u << 16)


static void initialize()
{
	static int initialized = 0;
	if (initialized == 0)
	{
		// initialized by u-boot
		initialized = 1;
	}
}

static ssize_t console_gets(int dev, caddr_t buf, size_t len, uint_t startblk)
{
	int i;
	for (i = 0; i < len; i++) {
		if (UART_STATUS & UART_STATUS_RFIFO_EMPTY)
			break;
		buf[i] = UART_RFIFO;
	}
	return i;
}

static void console_putc(int c)
{
	while (UART_STATUS & UART_STATUS_TFIFO_FULL) {}
	UART_WFIFO = c;
	if (c == '\n')
		console_putc('\r');
	while (!(UART_STATUS & UART_STATUS_TFIFO_EMPTY)) {}
}
static ssize_t console_puts(int dev, caddr_t buf, size_t len, uint_t startblk)
{
	for (int i = 0; i < len; i++)
		console_putc(buf[i]);
	return len;
}

static int console_open(const char *name)
{
	initialize();
	return 0;
}

static int
stdin_match(const char *name)
{
	return !strcmp(name, "stdin");
}

static int
stdout_match(const char *name)
{
	return !strcmp(name, "stdout");
}

static struct prom_dev stdin_dev =
{
	.match = stdin_match,
	.open = console_open,
	.read = console_gets,
};

static struct prom_dev stdout_dev =
{
	.match = stdout_match,
	.open = console_open,
	.write = console_puts,
};

void init_console(void)
{
	prom_register(&stdout_dev);
	prom_register(&stdin_dev);
}
