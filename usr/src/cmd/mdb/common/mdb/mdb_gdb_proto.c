#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_gdb.h>
#include <mdb/mdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>

struct gdb_reply {
	char *buf;
	size_t size;
};

static unsigned char
decode_hex_digit(char a)
{
	if (a >= '0' && a <= '9')
		a = a - '0';
	else if (a >= 'a' && a <= 'f')
		a = a - 'a' + 10;
	else if (a >= 'A' && a <= 'F')
		a = a - 'A' + 10;
	else
		ASSERT(0);

	return a;
}

static size_t
unhexdump(char *buf)
{
	size_t out;
	size_t i;

	for (out = 0, i = 0; buf[i] != '\0'; i+= 2, out++) {
		ASSERT(buf[i + 1] != '\0');

		buf[out] = (decode_hex_digit(buf[i]) << 4) |
		    decode_hex_digit(buf[i + 1]);
	}

	return out;
}

static intmax_t
intify(uint8_t *buf, size_t len)
{
	uintmax_t v;
	int i;

	v = 0;
	for (i = 0; i < len; i++)
		v = (v << 8) | buf[i];

	return v;
}

static void
xwrite(int fd, const void *buf, size_t len)
{
	ssize_t ret;

	ret = write(fd, buf, len);
	ASSERT(ret == len);
}

static void
xread(int fd, void *buf, size_t len)
{
	ssize_t ret;

	ret = read(fd, buf, len);
	ASSERT(ret == len);
}

static unsigned char
cksum(const char *data, size_t len)
{
	unsigned sum;
	int i;

	sum = 0;
	for (i = 0; i < len; i++)
		sum += (unsigned char)data[i];

	return (sum % 256);
}

static void
free_reply(struct gdb_reply *reply)
{
	if (!reply)
		return;

	mdb_free(reply->buf, reply->size);
	mdb_free(reply, sizeof(*reply));
}

static void
comm_sendack(gdb_data_t *tgt)
{
	xwrite(tgt->fd, "+", 1);
}

static int
wait_for_ack(gdb_data_t *tgt)
{
	char tmp;

	xread(tgt->fd, &tmp, 1);

	switch (tmp) {
	case '+':
		return 0;
	case '-':
		return 1;
	case '$':
		mdb_printf("%s: got a $ when waiting for ack\n", __func__);
		ASSERT(0);
	}

	mdb_printf("%s: got a '%c' (%u) when waiting for ack\n",
		   __func__, tmp, tmp);
	ASSERT(0);
	return -1;
}

static void comm_sendcmd(gdb_data_t *tgt, const char *cmd, size_t len)
{
	char tmp[3];
	size_t i;

	snprintf(tmp, sizeof(tmp), "%02x", cksum(cmd, len));

	xwrite(tgt->fd, "$", 1);
	xwrite(tgt->fd, cmd, len);
	xwrite(tgt->fd, "#", 1);
	xwrite(tgt->fd, tmp, 2);
}

static struct gdb_reply *
comm_recvreply(gdb_data_t *tgt)
{
	struct gdb_reply *reply;
	uint8_t recvdcksum;
	size_t len;
	char *buf, *new;
	char tmp;

	xread(tgt->fd, &tmp, 1);
	ASSERT(tmp == '$');

	buf = NULL;

	for (len = 0;; len++) {
		xread(tgt->fd, &tmp, 1);

		if (tmp == '#')
			break;

		/* grow our buffer and append latest char */

		new = mdb_alloc(len + 2, UM_SLEEP);

		memcpy(new, buf, len);
		new[len] = tmp;
		new[len + 1] = '\0';

		mdb_free(buf, len);
		buf = new;
	}

	/* get the checksum */
	xread(tgt->fd, &tmp, 1);
	recvdcksum = decode_hex_digit(tmp) * 16;
	xread(tgt->fd, &tmp, 1);
	recvdcksum += decode_hex_digit(tmp);

	if (recvdcksum != cksum(buf, len))
		mdb_printf("%s: checksum mismatch %02x vs. %02x\n",
			   __func__, recvdcksum, cksum(buf, len));

	reply = mdb_zalloc(sizeof (*reply), UM_SLEEP);
	reply->buf = buf;
	reply->size = buf ? (len + 1) : 0;

	return (reply);
}


/*
 * XXX: receiving the confirmation '+' may involve reading back one or more
 * interrupt responses.  If we receive any of these, we (for now) just print
 * them out and discard them.
 */
static struct gdb_reply *
__send_cmd(gdb_data_t *tgt, const char *cmdtosend, boolean_t readreply)
{
	char tmp;

	do {
		comm_sendcmd(tgt, cmdtosend, strlen(cmdtosend));
	} while (wait_for_ack(tgt));

	if (!readreply)
		return NULL;

	return comm_recvreply(tgt);
}

static struct gdb_reply *
send_cmd(gdb_data_t *tgt, const char *cmdtosend)
{
	return __send_cmd(tgt, cmdtosend, B_TRUE);
}

static void
send_cmd_noreply(gdb_data_t *tgt, const char *cmdtosend)
{
	__send_cmd(tgt, cmdtosend, B_FALSE);
}

/* like send_cmd, but it asserts that the response is "OK" */
static void
send_cmd_OK(gdb_data_t *tgt, const char *cmdtosend)
{
	struct gdb_reply *reply;

	reply = send_cmd(tgt, cmdtosend);

	ASSERT(reply);
	ASSERT(!strcmp(reply->buf, "OK"));

	free_reply(reply);
}

void
gdb_comm_greet(gdb_data_t *tgt)
{
	/* connections start with the client sending an ack */
	comm_sendack(tgt);

	/* TODO: send qSupported */
}

int
gdb_comm_get_regs(gdb_data_t *tgt)
{
	const struct mdb_gdb_reginfo *regs = tgt->tgt->reginfo;
	struct gdb_reply *reply;
	size_t explen;
	size_t len;
	char *val;
	int i;

	/*
	 * c: g
	 * s: <many hex digits with register values>
	 */

	reply = send_cmd(tgt, "g");

	len = unhexdump(reply->buf);

	for (i = 0, explen = 0; regs[i].name; i++)
		explen = MAX(explen, regs[i].off + regs[i].size);

	if (len != explen) {
		mdb_printf("%s: reply of wrong length; expected %u, got %u\n",
			   __func__, explen, len);
		return (EPROTO);
	}

	for (i = 0; regs[i].name; i++) {
		const int binlen = regs[i].size;
		uint8_t *buf = (uint8_t *)&reply->buf[regs[i].off];
		uintmax_t v;
		int j;

		/* skip over regs larger than the largest value we can deal with */
		if (binlen > sizeof(uintmax_t))
			continue;

		/* little endian? */
		if (regs[i].le) {
			for (j = 0; j < binlen / 2; j++) {
				uint8_t *a = &buf[j];
				uint8_t *b = &buf[binlen - 1 - j];
				uint8_t tmp;

				tmp = *a;
				*a  = *b;
				*b  = tmp;
			}
		}

		mdb_nv_insert(&tgt->regs, regs[i].name, NULL,
		    intify(buf, binlen), 0);
	}

	free_reply(reply);

	return (0);
}

void
gdb_comm_select_thread(gdb_data_t *tgt, gdb_tid_t tid)
{
	struct gdb_reply *reply;
	char cmd[20];

	/*
	 * c: Hg<tid>
	 * s: OK
	 */

	if (tid == GDB_TID_ALL)
		snprintf(cmd, sizeof(cmd), "Hg-1");
	else
		snprintf(cmd, sizeof(cmd), "Hg%x", tid);

	send_cmd_OK(tgt, cmd);
}

void
gdb_comm_get_mem_byte(gdb_data_t *tgt, uint8_t *byte, uint64_t addr)
{
	struct gdb_reply *reply;
	char cmd[20];
	size_t len;
	char *val;

	/*
	 * c: m<addr in hex>,<len in hex>
	 * s: <many hex digits with memory bytes values>
	 */

	snprintf(cmd, sizeof(cmd), "m%llx,1", addr);

	reply = send_cmd(tgt, cmd);

	len = unhexdump(reply->buf);

	ASSERT(len == 1);

	*byte = reply->buf[0];

	free_reply(reply);
}

static void __process_tid_list(mdb_addrvec_t *list,
			       struct gdb_reply *raw)
{
	gdb_tid_t tid;
	size_t off;

	ASSERT(raw->buf[0] == 'm');

	off = 1;
	while (raw->buf[off]) {
		tid = 0;
		while (raw->buf[off] && raw->buf[off] != ',') {
			tid = (tid << 4) | decode_hex_digit(raw->buf[off]);
			off++;
		}

		ASSERT(tid > 0);

		mdb_addrvec_unshift(list, (uintptr_t)tid);
	}
}

void gdb_comm_get_thread_list(gdb_data_t *tgt, mdb_addrvec_t *list)
{
	struct gdb_reply *reply;

	/*
	 * c: qfThreadInfo
	 * s: m<tid>,<tid>,...
	 * c: qsThreadInfo
	 * s: m<tid>,<tid>,...
	 * c: qsThreadInfo
	 * s: ml
	 */

	reply = send_cmd(tgt, "qfThreadInfo");
	__process_tid_list(list, reply);
	free_reply(reply);

	for (;;) {
		reply = send_cmd(tgt, "qsThreadInfo");

		if (reply->buf[0] == 'l') {
			free_reply(reply);
			break;
		}

		__process_tid_list(list, reply);
		free_reply(reply);
	}
}

void
gdb_comm_cont(gdb_data_t *tgt)
{
	struct gdb_reply *reply;

	/*
	 * c: vCont?
	 * s: vCont;c;C;s;S
	 * c: vCont;c
	 * <no reply from server>
	 */

	/* sanity check that the target supports 'vCont;c' */
	reply = send_cmd(tgt, "vCont?");
	ASSERT(!strcmp(reply->buf, "vCont;c;C;s;S"));
	free_reply(reply);

	send_cmd_noreply(tgt, "vCont;c");
}

#if 0
#define get_halt_reason(data)		gdb_cmd_send((data), "?")
#endif
