/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Toomas Soome <tsoome@me.com>
 * Copyright 2026 Copyright 2025 Edgecast Cloud LLC.
 */

#include <sys/cdefs.h>
#include <stand.h>
#include <bootstrap.h>

extern struct file_format multiboot2;
extern struct file_format dboot;

struct file_format *file_formats[] = {
	&dboot,
	&multiboot2,
	NULL
};

COMMAND_SET(dboot, "dboot", "enable or disable dboot", command_dboot);

static int
command_dboot(int argc, char *argv[])
{
	if (argc == 1) {
		printf("Default boot is %s\n",
		    file_formats[0] == &dboot ? "dboot" : "multiboot2");
		return (CMD_OK);
	}
	if (argc > 2) {
		command_errmsg = "wrong number of arguments";
		return (CMD_ERROR);
	}
	if (strcmp(argv[1], "enable") == 0) {
		file_formats[0] = &dboot;
		file_formats[1] = &multiboot2;
		return (CMD_OK);
	}
	if (strcmp(argv[1], "disable") == 0) {
		file_formats[0] = &multiboot2;
		file_formats[1] = &dboot;
		return (CMD_OK);
	}
	command_errmsg = "unknown argument";
	return (CMD_ERROR);
}
