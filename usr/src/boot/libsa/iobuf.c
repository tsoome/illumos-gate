/*
 * Copyright 2025 Edgecast Cloud LLC.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stand.h>
#include <iobuf.h>

struct io_buffer *
alloc_iob(size_t len)
{
	struct io_buffer *iob;
	void *data;

	data = malloc(len);
	if (data == NULL)
		return (NULL);
	iob = malloc(sizeof (*iob));
	if (iob == NULL) {
		free(data);
		return (NULL);
	}

	iob->io_head = data;
	iob->io_data = iob->io_tail = data;
	iob->io_end = data + len;
	iob->io_queue = NULL;

	return (iob);
}

int
free_iob(struct io_buffer *iob)
{
	if (iob == NULL)
		return (0);

	if (iob->io_queue != NULL)
		return (EBUSY);

	free(iob->io_head);
	free(iob);
	return (0);
}
