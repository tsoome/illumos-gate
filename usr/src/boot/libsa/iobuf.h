/*
 * Copyright 2026 Edgecast Cloud LLC.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/queue.h>

#ifndef IOBUF_H
#define	IOBUF_H

struct io_buffer;
typedef STAILQ_HEAD(ipqueue, io_buffer) ip_queue_t;

struct io_buffer {
	void *io_head;	/* Start of the buffer */
	void *io_data;	/* Start of the data for current owner */
	void *io_tail;	/* End of data */
	void *io_end;	/* End of buffer */

	ip_queue_t *io_queue;	/* Our queue head */
	STAILQ_ENTRY(io_buffer) io_next;	/* Next in queue */
};

/*
 * Reserve space from start of the buffer.
 */
static inline void *iob_reserve(struct io_buffer *iob, size_t len)
{
        iob->io_data += len;
        iob->io_tail += len;

        return (iob->io_data);
}

/*
 * Add data to start of I/O buffer, return pointer to new start of buffer
 */
static inline void *iob_push(struct io_buffer *iob, size_t len)
{
	iob->io_data -= len;
	return (iob->io_data);
}

/*
 * Calculate length of data in an I/O buffer
 */
static inline size_t iob_len(struct io_buffer *iob)
{
	return (iob->io_tail - iob->io_data);
}

/*
 * Space at tail of buffer.
 */
static inline size_t iob_tail_space (struct io_buffer *iob)
{
	return (iob->io_end - iob->io_tail);
}

/*
 * Add data to end of I/O buffer, return pointer to newly added space
 */
static inline void *iob_put(struct io_buffer *iob, size_t len)
{
        void *old_tail = iob->io_tail;
        iob->io_tail += len;
        return (old_tail);
}

/*
 * Remove data from end of I/O buffer
 */
static inline void iob_unput(struct io_buffer *iob, size_t len) {
	iob->io_tail -= len;
}

extern struct io_buffer *alloc_iob(size_t);
extern int free_iob(struct io_buffer *);

#endif	/* IOBUF_H */
