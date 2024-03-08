/*
 * Copyright (c) 1998 Michael Smith (msmith@freebsd.org)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <sys/errno.h>
#include <bootstrap.h>
#include <stdbool.h>

#include <efi.h>
#include <efilib.h>
#include <Protocol/SerialIo.h>
#include <Protocol/SuperIo.h>

EFI_GUID gEfiSerialIoProtocolGuid = SERIAL_IO_PROTOCOL;
EFI_GUID gEfiSerialTerminalDeviceTypeGuid = \
	EFI_SERIAL_TERMINAL_DEVICE_TYPE_GUID;
EFI_GUID gEfiSioProtocolGuid = EFI_SIO_PROTOCOL_GUID;

#define	COMC_TXWAIT	0x40000		/* transmit timeout */
#define	COM1_IOADDR	0x3f8
#define	COM2_IOADDR	0x2f8
#define	COM3_IOADDR	0x3e8
#define	COM4_IOADDR	0x2e8

#define	PNP0501		0x501		/* 16550A-compatible COM port */

typedef STAILQ_HEAD(serial_list, serial) serial_list_t;

struct serial {
	STAILQ_ENTRY(serial)	next;
	uint64_t	baudrate;
	uint32_t	timeout;
	uint32_t	receivefifodepth;
	uint32_t	databits;
	EFI_PARITY_TYPE	parity;
	EFI_STOP_BITS_TYPE stopbits;
	bool		ignore_cd;
	bool		rtsdtr_off;
	bool		is_efi_console;	/* EFI Console device */
	EFI_HANDLE	currdev;	/* current serial device */
	EFI_SERIAL_IO_PROTOCOL	*sio;
	char		name;		/* 'a'-'d' or '0'-'9' */
};

/* List of serial ports, set up by efi_serial_ini() */
static serial_list_t serials = STAILQ_HEAD_INITIALIZER(serials);

static void	efi_serial_probe(struct console *);
static int	efi_serial_init(struct console *, int);
static void	efi_serial_putchar(struct console *, int);
static int	efi_serial_getchar(struct console *);
static int	efi_serial_ischar(struct console *);
static int	efi_serial_ioctl(struct console *, int, void *);
static void	efi_serial_devinfo(struct console *);
static bool	efi_serial_setup(struct console *);
static char	*efi_serial_asprint_mode(struct serial *);
static int	efi_serial_parse_mode(struct serial *, const char *);
static int	efi_serial_mode_set(struct env_var *, int, const void *);
static int	efi_serial_cd_set(struct env_var *, int, const void *);
static int	efi_serial_rtsdtr_set(struct env_var *, int, const void *);

extern struct console efi_console;

static bool
efi_serial_append(const char *name, struct serial *port)
{
	EFI_DEVICE_PATH *node, *dev;
	EFI_STATUS status;
	char *buf;
	size_t sz;
	bool rv = true;

	if (port->currdev == NULL)
		return (rv);

	buf = NULL;
	sz = 0;
	status = efi_global_getenv(name, buf, &sz);
	if (status == EFI_BUFFER_TOO_SMALL) {
		buf = malloc(sz);
		if (buf == NULL)
			return (rv);
		status = efi_global_getenv(name, buf, &sz);
	}
	if (EFI_ERROR(status)) {
		free(buf);
		return (rv);
	}

	dev = efi_lookup_devpath(port->currdev);
	if (dev == NULL) {
		free(buf);
		return (rv);
	}

	node = (EFI_DEVICE_PATH *)buf;
	/*
	 * We only need to know if this port is first in list.
	 * This is only important when "os_console" is not set.
	 */
	if (!IsDevicePathEnd(node) && efi_devpath_is_prefix(dev, node))
		rv = false;

	efi_close_devpath(dev);
	free(buf);
	return (rv);
}

static void
efi_serial_setup_env(struct console *tty)
{
	struct serial *port = tty->c_private;
	char name[20];
	char value[20];
	char *env;

	(void) snprintf(name, sizeof (name), "%s-mode", tty->c_name);
	env = getenv(name);
	if (env != NULL)
		(void) efi_serial_parse_mode(port, env);
	env = efi_serial_asprint_mode(port);
	if (env != NULL) {
		(void) unsetenv(name);
		(void) env_setenv(name, EV_VOLATILE, env, efi_serial_mode_set,
		    env_nounset);
		if (port->is_efi_console) {
			(void) snprintf(name, sizeof (name), "%s-spcr-mode",
			    tty->c_name);
			(void) setenv(name, env, 1);
			free(env);

			/* Add us to console list. */
			(void) snprintf(name, sizeof (name), "console");
			env = getenv(name);
			if (env == NULL) {
				(void) setenv(name, tty->c_name, 1);
			} else {
				char *ptr;
				int rv;

				/*
				 * we have "text" already in place,
				 * consult ConOut if we need to add
				 * serial console before or after.
				 */
				if (efi_serial_append("ConOut", port))
					rv = asprintf(&ptr, "%s,%s", env,
					    tty->c_name);
				else
					rv = asprintf(&ptr, "%s,%s",
					    tty->c_name, env);
				if (rv == 0) {
					(void) setenv(name, ptr, 1);
					free(ptr);
				}
			}
		} else {
			free(env);
		}
	}

	(void) snprintf(name, sizeof (name), "%s-ignore-cd", tty->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->ignore_cd = 1;
		else if (strcmp(env, "false") == 0)
			port->ignore_cd = 0;
	}

	(void) snprintf(value, sizeof (value), "%s",
	    port->ignore_cd? "true" : "false");
	(void) unsetenv(name);
	(void) env_setenv(name, EV_VOLATILE, value, efi_serial_cd_set,
	    env_nounset);

	(void) snprintf(name, sizeof (name), "%s-rts-dtr-off", tty->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->rtsdtr_off = 1;
		else if (strcmp(env, "false") == 0)
			port->rtsdtr_off = 0;
	}

	(void) snprintf(value, sizeof (value), "%s",
	    port->rtsdtr_off? "true" : "false");
	(void) unsetenv(name);
	(void) env_setenv(name, EV_VOLATILE, value, efi_serial_rtsdtr_set,
	    env_nounset);
}

static void
efi_check_and_set_condev(struct serial *port, const char *name)
{
	EFI_DEVICE_PATH *node, *dev;
	EFI_STATUS status;
	char *buf;
	size_t sz;

	if (port->currdev == NULL)
		return;

	buf = NULL;
	sz = 0;
	status = efi_global_getenv(name, buf, &sz);
	if (status == EFI_BUFFER_TOO_SMALL) {
		buf = malloc(sz);
		if (buf == NULL)
			return;
		status = efi_global_getenv(name, buf, &sz);
	}
	if (EFI_ERROR(status)) {
		free(buf);
		return;
	}

	dev = efi_lookup_devpath(port->currdev);
	if (dev == NULL) {
		free(buf);
		return;
	}

	node = (EFI_DEVICE_PATH *)buf;
	while (!IsDevicePathEnd(node)) {
		/* Sanity check the node before moving to the next node. */
		if (DevicePathNodeLength(node) < sizeof (*node))
			break;

		if (efi_devpath_is_prefix(dev, node)) {
			port->is_efi_console = true;
			break;
		}

		node = efi_devpath_next_instance(node);
	}

	efi_close_devpath(dev);
	free(buf);
}

/*
 * Get list of super io handles, get device path and check if this
 * device path is parent of serial io device. If so, we can use this
 * super io protocol instance to identify serial port.
 */
static EFI_STATUS
efi_get_sio_serial_name(EFI_HANDLE handle, char *id)
{
	struct serial *port;
	EFI_STATUS status;
	EFI_HANDLE *handles, h;
	uint_t nhandles;
	EFI_DEVICE_PATH *parent, *dp;
	EFI_SIO_PROTOCOL *sio;
	ACPI_RESOURCE_HEADER_PTR rl;
	EFI_ACPI_IO_PORT_DESCRIPTOR *io;
	EFI_ACPI_FIXED_LOCATION_IO_PORT_DESCRIPTOR *fixedio;
	EFI_ACPI_ADDRESS_SPACE_DESCRIPTOR *as;
	UINT64 base_address = 0;
	char name;

	status = efi_get_protocol_handles(&gEfiSioProtocolGuid, &nhandles,
	    &handles);
	if (EFI_ERROR(status))
		return (status);

	dp = efi_lookup_devpath(handle);
	if (dp == NULL) {
		free(handles);
		return (EFI_OUT_OF_RESOURCES);
	}

	h = NULL;
	for (uint_t i = 0; i < nhandles; i++) {
		parent = efi_lookup_devpath(handles[i]);
		if (parent == NULL)
			continue;
		if (efi_devpath_is_prefix(parent, dp)) {
			h = handles[i];
			efi_close_devpath(h);
			break;
		}
		efi_close_devpath(handles[i]);
	}
	efi_close_devpath(dp);
	free(handles);
	if (h == NULL)
		return (EFI_NOT_FOUND);

	status = BS->OpenProtocol(h, &gEfiSioProtocolGuid,
	    (void **)&sio, IH, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(status))
		return (status);

	status = sio->GetResources(sio, &rl);
	if (EFI_ERROR(status)) {
		(void) BS->CloseProtocol(h, &gEfiSioProtocolGuid, IH, NULL);
		return (status);
	}

	while (rl.SmallHeader->Byte != ACPI_END_TAG_DESCRIPTOR &&
	    base_address == 0) {
		switch (rl.SmallHeader->Byte) {
		case ACPI_IO_PORT_DESCRIPTOR:
			io = (EFI_ACPI_IO_PORT_DESCRIPTOR *)rl.SmallHeader;
			if (io->Length != 0)
				base_address = io->BaseAddressMin;
			break;

		case ACPI_FIXED_LOCATION_IO_PORT_DESCRIPTOR:
			fixedio =
			    (EFI_ACPI_FIXED_LOCATION_IO_PORT_DESCRIPTOR *)
			    rl.SmallHeader;
			if (fixedio->Length != 0)
				base_address = fixedio->BaseAddress;
			break;

		case ACPI_ADDRESS_SPACE_DESCRIPTOR:
			as = (void *)rl.SmallHeader;
			if (as->AddrLen != 0)
				base_address = as->AddrRangeMin;
			break;
		}

		if (rl.SmallHeader->Bits.Type == 0) {
			rl.SmallHeader = (ACPI_SMALL_RESOURCE_HEADER *)
			    ((UINT8 *)rl.SmallHeader +
			    rl.SmallHeader->Bits.Length +
			    sizeof (rl.SmallHeader));
		} else {
			rl.LargeHeader = (ACPI_LARGE_RESOURCE_HEADER *)
			    ((UINT8 *)rl.LargeHeader +
			    rl.LargeHeader->Length +
			    sizeof (rl.LargeHeader));
		}
	}

	/*
	 * On x86, we name COM1-COM4 as ttya-ttyd.
	 */
	switch (base_address) {
	case COM1_IOADDR:
		name = 'a';
		break;

	case COM2_IOADDR:
		name = 'b';
		break;

	case COM3_IOADDR:
		name = 'c';
		break;

	case COM4_IOADDR:
		name = 'd';
		break;

	default:
		name = '0';
		STAILQ_FOREACH(port, &serials, next) {
			if (port->name == name)
				name++;
		}
		break;
	}
	*id = name;

	(void) BS->CloseProtocol(h, &gEfiSioProtocolGuid, IH, NULL);
	return (status);
}

static void
efi_set_serial_name(struct console *tty)
{
	struct serial *p, *port = tty->c_private;
	EFI_STATUS status;

	/* Try to detect actual IO protocol */
	status = efi_get_sio_serial_name(port->currdev, &port->name);
	if (EFI_ERROR(status)) {
		port->name = '0';
		STAILQ_FOREACH(p, &serials, next) {
			if (p->name == port->name)
				port->name++;
		}
	}

	(void) asprintf(&tty->c_name, "tty%c", port->name);
	(void) asprintf(&tty->c_desc, "serial port %c", port->name);
}

static uint_t
efi_serial_create_port(uint_t c, EFI_HANDLE handle)
{
	struct console *tty;
	struct serial *port;
	EFI_STATUS status;

	tty = calloc(1, sizeof (*tty));
	if (tty == NULL) {
		/* Out of memory?! can not continue */
		consoles[c] = tty;
		return (c);
	}
	port = calloc(1, sizeof (*port));
	if (port == NULL) {
		free(tty);
		consoles[c] = NULL;
		return (c);
	}

	/* Set up port descriptor */
	port->currdev = handle;
	status = BS->OpenProtocol(handle, &gEfiSerialIoProtocolGuid,
	    (void **)&port->sio, IH, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(status)) {
		free(tty);
		free(port);
		consoles[c] = NULL;
		return (c);
	}

	port->baudrate = port->sio->Mode->BaudRate;
	port->timeout = port->sio->Mode->Timeout;
	port->receivefifodepth = port->sio->Mode->ReceiveFifoDepth;
	port->databits = port->sio->Mode->DataBits;
	port->parity = port->sio->Mode->Parity;
	port->stopbits = port->sio->Mode->StopBits;
	port->ignore_cd = 1;		/* ignore cd */
	port->rtsdtr_off = 0;		/* rts-dtr is on */

	/* Set up serial device descriptor */
	tty->c_private = port;
	efi_set_serial_name(tty);
	tty->c_flags = C_PRESENTIN | C_PRESENTOUT;
	tty->c_probe = efi_serial_probe;
	tty->c_init = efi_serial_init;
	tty->c_out = efi_serial_putchar;
	tty->c_in = efi_serial_getchar;
	tty->c_ready = efi_serial_ischar;
	tty->c_ioctl = efi_serial_ioctl;
	tty->c_devinfo = efi_serial_devinfo;
	STAILQ_INSERT_TAIL(&serials, port, next);
	consoles[c++] = tty;
	consoles[c] = NULL;

	/* check if we are listed in ConIn */
	efi_check_and_set_condev(port, "ConIn");
	efi_serial_setup_env(tty);
	return (c);
}

/*
 * Set up list of possible serial consoles.
 * This function is run very early, so we do not expect to
 * run out of memory, and on error, we can not print output.
 */
void
efi_serial_ini(void)
{
	EFI_STATUS status;
	EFI_HANDLE *handles;
	uint_t c, n, index, nhandles;
	struct console **tmp;

	status = efi_get_protocol_handles(&gEfiSerialIoProtocolGuid, &nhandles,
	    &handles);
	if (EFI_ERROR(status))
		return;

	if (nhandles == 0)
		return;

	n = nhandles;
	c = cons_array_size();
	if (c == 0)
		n++;	/* For NULL pointer */

	tmp = realloc(consoles, (c + n) * sizeof (*consoles));
	if (tmp == NULL) {
		free(handles);
		return;
	}
	consoles = tmp;
	if (c > 0)
		c--;

	for (index = 0; index < nhandles; index++) {
		c = efi_serial_create_port(c, handles[index]);
	}
	free(handles);
}

#if 0
/*
 * Find serial device number from device path.
 * Return -1 if not found.
 */
static int
efi_serial_get_index(EFI_DEVICE_PATH *devpath, int idx)
{
	ACPI_HID_DEVICE_PATH  *acpi;

	while (!IsDevicePathEnd(devpath)) {
		if (DevicePathType(devpath) == MESSAGING_DEVICE_PATH &&
		    DevicePathSubType(devpath) == MSG_UART_DP)
			return (idx);

		if (DevicePathType(devpath) == ACPI_DEVICE_PATH &&
		    (DevicePathSubType(devpath) == ACPI_DP ||
		    DevicePathSubType(devpath) == ACPI_EXTENDED_DP)) {

			acpi = (ACPI_HID_DEVICE_PATH *)devpath;
			if (acpi->HID == EISA_PNP_ID(PNP0501)) {
				return (acpi->UID);
			}
		}

		devpath = NextDevicePathNode(devpath);
	}
	return (-1);
}

/*
 * The order of handles from LocateHandle() is not known, we need to
 * iterate handles, pick device path for handle, and check the device
 * number.
 */
static EFI_HANDLE
efi_serial_get_handle(int port)
{
	EFI_STATUS status;
	EFI_HANDLE *handles, handle;
	EFI_DEVICE_PATH *devpath;
	int index, nhandles;

	if (port == -1)
		return (NULL);

	handles = NULL;
	nhandles = 0;
	status = efi_serial_get_handles(&handles, &nhandles);
	if (EFI_ERROR(status))
		return (NULL);

	handle = NULL;
	for (index = 0; index < nhandles; index++) {
		devpath = efi_lookup_devpath(handles[index]);
		if (port == efi_serial_get_index(devpath, index))
			handle = (handles[index]);
		efi_close_devpath(handles[index]);
	}

	/*
	 * In case we did fail to identify the device by path, use port as
	 * array index. Note, we did check port == -1 above.
	 */
	if (port < nhandles && handle == NULL)
		handle = handles[port];

	free(handles);
	return (handle);
}
#endif

static void
efi_serial_probe(struct console *cp)
{
	cp->c_flags = C_PRESENTIN | C_PRESENTOUT;
}

static int
efi_serial_init(struct console *cp, int arg __unused)
{

	if (efi_serial_setup(cp))
		return (CMD_OK);

	cp->c_flags = 0;
	return (CMD_ERROR);
}

static void
efi_serial_putchar(struct console *cp, int c)
{
	int wait;
	EFI_STATUS status;
	UINTN bufsz = 1;
	char cb = c;
	struct serial *sp = cp->c_private;

	if (sp->sio == NULL)
		return;

	for (wait = COMC_TXWAIT; wait > 0; wait--) {
		status = sp->sio->Write(sp->sio, &bufsz, &cb);
		if (status != EFI_TIMEOUT)
			break;
	}
}

static int
efi_serial_getchar(struct console *cp)
{
	EFI_STATUS status;
	UINTN bufsz = 1;
	char c;
	struct serial *sp = cp->c_private;

	/*
	 * if this device is also used as ConIn, some firmwares
	 * fail to return all input via SIO protocol.
	 */
	if (sp->is_efi_console) {
		return (efi_console.c_in(&efi_console));
	}

	if (sp->sio == NULL || !efi_serial_ischar(cp))
		return (-1);

	status = sp->sio->Read(sp->sio, &bufsz, &c);
	if (EFI_ERROR(status) || bufsz == 0)
		return (-1);

	return (c);
}

static int
efi_serial_ischar(struct console *cp)
{
	EFI_STATUS status;
	uint32_t control;
	struct serial *sp = cp->c_private;

	/*
	 * if this device is also used as ConIn, some firmwares
	 * fail to return all input via SIO protocol.
	 */
	if (sp->is_efi_console) {
		return (efi_console.c_ready(&efi_console));
	}

	if (sp->sio == NULL)
		return (0);

	status = sp->sio->GetControl(sp->sio, &control);
	if (EFI_ERROR(status))
		return (0);

	return (!(control & EFI_SERIAL_INPUT_BUFFER_EMPTY));
}

static int
efi_serial_ioctl(struct console *cp __unused, int cmd __unused,
    void *data __unused)
{
	return (ENOTTY);
}

static void
efi_serial_devinfo(struct console *cp)
{
	struct serial *port = cp->c_private;
	EFI_DEVICE_PATH *dp;
	CHAR16 *text;

	if (port->currdev == NULL) {
		printf("\tdevice is not present");
		return;
	}

	dp = efi_lookup_devpath(port->currdev);
	if (dp == NULL)
		return;

	text = efi_devpath_name(dp);
	if (text == NULL)
		return;

	printf("\t%S", text);
	efi_free_devpath_name(text);
	efi_close_devpath(port->currdev);
}

static char *
efi_serial_asprint_mode(struct serial *sp)
{
	char par, *buf;
	char *stop;

	if (sp == NULL)
		return (NULL);

	switch (sp->parity) {
	case NoParity:
		par = 'n';
		break;
	case EvenParity:
		par = 'e';
		break;
	case OddParity:
		par = 'o';
		break;
	case MarkParity:
		par = 'm';
		break;
	case SpaceParity:
		par = 's';
		break;
	default:
		par = 'n';
		break;
	}

	switch (sp->stopbits) {
	case OneStopBit:
		stop = "1";
		break;
	case TwoStopBits:
		stop = "2";
		break;
	case OneFiveStopBits:
		stop = "1.5";
		break;
	default:
		stop = "1";
		break;
	}

	(void) asprintf(&buf, "%ju,%d,%c,%s,-", sp->baudrate, sp->databits,
	    par, stop);
	return (buf);
}

static int
efi_serial_parse_mode(struct serial *sp, const char *value)
{
	unsigned long n;
	uint64_t baudrate;
	uint8_t databits = 8;
	int parity = NoParity;
	int stopbits = OneStopBit;
	char *ep;

	if (value == NULL || *value == '\0')
		return (CMD_ERROR);

	errno = 0;
	n = strtoul(value, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);
	baudrate = n;

	ep++;
	n = strtoul(ep, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);

	switch (n) {
	case 5: databits = 5;
		break;
	case 6: databits = 6;
		break;
	case 7: databits = 7;
		break;
	case 8: databits = 8;
		break;
	default:
		return (CMD_ERROR);
	}

	ep++;
	switch (*ep++) {
	case 'n': parity = NoParity;
		break;
	case 'e': parity = EvenParity;
		break;
	case 'o': parity = OddParity;
		break;
	case 'm': parity = MarkParity;
		break;
	case 's': parity = SpaceParity;
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '1': stopbits = OneStopBit;
		if (ep[0] == '.' && ep[1] == '5') {
			ep += 2;
			stopbits = OneFiveStopBits;
		}
		break;
	case '2': stopbits = TwoStopBits;
		break;
	default:
		return (CMD_ERROR);
	}

	/* handshake is ignored, but we check syntax anyhow */
	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '-':
	case 'h':
	case 's':
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep != '\0')
		return (CMD_ERROR);

	sp->baudrate = baudrate;
	sp->databits = databits;
	sp->parity = parity;
	sp->stopbits = stopbits;
	return (CMD_OK);
}

static int
efi_serial_mode_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_ERROR);

	if (efi_serial_parse_mode(cp->c_private, value) == CMD_ERROR)
		return (CMD_ERROR);

	(void) efi_serial_setup(cp);

	(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

static int
efi_serial_cd_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	struct serial *sp;

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_ERROR);

	sp = cp->c_private;
	if (strcmp(value, "true") == 0)
		sp->ignore_cd = 1;
	else if (strcmp(value, "false") == 0)
		sp->ignore_cd = 0;
	else
		return (CMD_ERROR);

	(void) efi_serial_setup(cp);

	(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

static int
efi_serial_rtsdtr_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	struct serial *sp;

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_ERROR);

	sp = cp->c_private;
	if (strcmp(value, "true") == 0)
		sp->rtsdtr_off = 1;
	else if (strcmp(value, "false") == 0)
		sp->rtsdtr_off = 0;
	else
		return (CMD_ERROR);

	(void) efi_serial_setup(cp);

	(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

/*
 * In case of error, we also reset ACTIVE flags, so the console
 * framefork will try alternate consoles.
 */
static bool
efi_serial_setup(struct console *cp)
{
	EFI_STATUS status;
	UINT32 control;
	struct serial *sp = cp->c_private;
	uint64_t baudrate;
	uint32_t timeout, receivefifodepth, databits;
	EFI_PARITY_TYPE parity;
	EFI_STOP_BITS_TYPE stopbits;
	bool change = false;

	/* port is not usable */
	if (sp->sio == NULL)
		return (false);

	if (sp->sio->Reset != NULL) {
		status = sp->sio->Reset(sp->sio);
		if (EFI_ERROR(status))
			return (false);
	}

	if (sp->baudrate == sp->sio->Mode->BaudRate) {
		baudrate = 0;
	} else {
		baudrate = sp->baudrate;
		change = true;
	}
	if (sp->receivefifodepth == sp->sio->Mode->ReceiveFifoDepth) {
		receivefifodepth = 0;
	} else {
		receivefifodepth = sp->receivefifodepth;
		change = true;
	}
	if (sp->timeout == sp->sio->Mode->Timeout) {
		timeout = 0;
	} else {
		timeout = sp->timeout;
		change = true;
	}
	if (sp->parity == sp->sio->Mode->Parity) {
		parity = DefaultParity;
	} else {
		parity = sp->parity;
		change = true;
	}
	if (sp->databits == sp->sio->Mode->DataBits) {
		databits = 0;
	} else {
		databits = sp->databits;
		change = true;
	}
	if (sp->stopbits == sp->sio->Mode->StopBits) {
		stopbits = DefaultStopBits;
	} else {
		stopbits = sp->stopbits;
		change = true;
	}

	if (change && sp->sio->SetAttributes != NULL) {
		status = sp->sio->SetAttributes(sp->sio, baudrate,
		    receivefifodepth, timeout, parity, databits, stopbits);
		if (EFI_ERROR(status))
			return (false);
	}

	status = sp->sio->GetControl(sp->sio, &control);
	if (EFI_ERROR(status))
		return (false);
	if (sp->rtsdtr_off) {
		control &= ~(EFI_SERIAL_REQUEST_TO_SEND |
		    EFI_SERIAL_DATA_TERMINAL_READY);
	} else {
		control |= EFI_SERIAL_REQUEST_TO_SEND;
	}

	(void) sp->sio->SetControl(sp->sio, control);

	/* Mark this port usable. */
	cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
	return (true);
}
