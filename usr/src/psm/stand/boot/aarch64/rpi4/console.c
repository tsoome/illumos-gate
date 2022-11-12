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
 * Copyright 2021 Hayashi Naoyuki
 */

#include <sys/platform.h>
#include "prom_dev.h"

#define UART_ADDR	UART_PHYS

#define UARTDR		(*(volatile uint32_t *)(UART_ADDR + 0x00))
#define UARTRSR		(*(volatile uint32_t *)(UART_ADDR + 0x04))
#define UARTECR		(*(volatile uint32_t *)(UART_ADDR + 0x04))
#define UARTFR		(*(volatile uint32_t *)(UART_ADDR + 0x18))
#define UARTLCR_H	(*(volatile uint32_t *)(UART_ADDR + 0x2c))
#define UARTCR		(*(volatile uint32_t *)(UART_ADDR + 0x30))
#define UARTIFLS	(*(volatile uint32_t *)(UART_ADDR + 0x34))
#define UARTIMSC	(*(volatile uint32_t *)(UART_ADDR + 0x38))
#define UARTRIS		(*(volatile uint32_t *)(UART_ADDR + 0x3c))
#define UARTMIS		(*(volatile uint32_t *)(UART_ADDR + 0x40))
#define UARTICR		(*(volatile uint32_t *)(UART_ADDR + 0x44))

#define UARTFR_TXFE	(1 << 7)
#define UARTFR_RXFF	(1 << 6)
#define UARTFR_TXFF	(1 << 5)
#define UARTFR_RXFE	(1 << 4)
#define UARTFR_BUSY	(1 << 3)
#define UARTFR_DCD	(1 << 2)
#define UARTFR_DSR	(1 << 1)
#define UARTFR_CTS	(1 << 0)

#define UARTCR_CTSEN	(1 << 15)
#define UARTCR_RTSEN	(1 << 14)
#define UARTCR_RTS	(1 << 11)
#define UARTCR_DTR	(1 << 10)
#define UARTCR_RXE	(1 << 9)
#define UARTCR_TXE	(1 << 8)
#define UARTCR_LBE	(1 << 7)
#define UARTCR_UARTEN	(1 << 0)

#define UARTLCR_H_SPS       (1 << 7)
#define UARTLCR_H_WLEN_8    (3 << 5)
#define UARTLCR_H_WLEN_7    (2 << 5)
#define UARTLCR_H_WLEN_6    (1 << 5)
#define UARTLCR_H_WLEN_5    (0 << 5)
#define UARTLCR_H_FEN       (1 << 4)
#define UARTLCR_H_STP2      (1 << 3)
#define UARTLCR_H_EPS       (1 << 2)
#define UARTLCR_H_PEN       (1 << 1)
#define UARTLCR_H_BRK       (1 << 0)

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
		if (UARTFR & UARTFR_RXFE)
			break;
		buf[i] = (UARTDR & 0xFF);
	}
	return i;
}

static void console_putc(int c)
{
	while (UARTFR & UARTFR_TXFF) {}
	UARTDR = c;
	if (c == '\n')
		console_putc('\r');
	while (!(UARTFR & UARTFR_TXFE)) {}
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
