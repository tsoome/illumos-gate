/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#include <libfdt.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/systm.h>
#include <sys/sunddi.h>


static struct fdt_header *fdtp;

static phandle_t get_phandle(int offset)
{
	int len;
	const void *prop = fdt_getprop(fdtp, offset, "phandle", &len);
	if (prop == NULL || len != sizeof(uint32_t)) {
		uint32_t phandle = fdt_get_max_phandle(fdtp) + 1;
		uint32_t v = htonl(phandle);
		int r = fdt_setprop(fdtp, offset, "phandle", &v, sizeof(uint32_t));
		if (r != 0)
			return -1;
		return phandle;
	}

	uint32_t v ;
	memcpy(&v, prop, sizeof(uint32_t));
	return ntohl(v);
}

pnode_t
prom_findnode_by_phandle(phandle_t phandle)
{
	int offset = fdt_node_offset_by_phandle(fdtp, phandle);
	if (offset < 0)
		return -1;
	return (pnode_t)phandle;
}

int
prom_getprop(pnode_t nodeid, const char *name, caddr_t value)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);

	if (offset < 0)
		return -1;

	int len;
	const void *prop = fdt_getprop(fdtp, offset, name, &len);

	if (prop == NULL) {
		if (strcmp(name, "name") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');

			if (!name_ptr)
				return -1;

			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}
			memcpy(value, name_ptr, len);
			value[len] = '\0';

			return len + 1;
		}
		if (strcmp(name, "addr") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return -1;
			}
			if (len == 0)
				return -1;
			memcpy(value, p, len);
			value[len] = '\0';
			return len + 1;
		}
		return -1;
	}

	memcpy(value, prop, len);
	return len;
}

int
prom_setprop(pnode_t nodeid, const char *name, const caddr_t value, int len)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return -1;

	int r;
	if (strcmp(name, "name") == 0) {
		if (strchr(value, '@')) {
			r = fdt_set_name(fdtp, offset, value);
		} else {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			const char *p = strchr(name_ptr, '@');
			if (p) {
				const char *addr = p + 1;
				char *buf = __builtin_alloca(strlen(value) + 1 + strlen(addr) + 1);
				strcpy(buf, value);
				strcat(buf, "@");
				strcat(buf, addr);
				r = fdt_set_name(fdtp, offset, buf);
			} else {
				r = fdt_set_name(fdtp, offset, value);
			}
		}
	} else if (strcmp(name, "addr") == 0) {
		int name_len = prom_getproplen(nodeid, "name");
		char *buf = __builtin_alloca(name_len  + 1 + strlen(value) + 1);
		prom_getprop(nodeid, "name", buf);
		strcat(buf, "@");
		strcat(buf, value);
		r = fdt_set_name(fdtp, offset, buf);
	} else {
		r = fdt_setprop(fdtp, offset, name, value, len);
	}

	return r == 0?len:-1;
}

int
prom_getproplen(pnode_t nodeid, const char *name)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);

	if (offset < 0)
		return -1;

	int len;
	const struct fdt_property *prop = fdt_get_property(fdtp, offset, name, &len);

	if (prop == NULL) {
		if (strcmp(name, "name") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			if (!name_ptr)
				return -1;
			const char *p = strchr(name_ptr, '@');
			if (p) {
				len = p - name_ptr;
			} else {
				len = strlen(name_ptr);
			}

			return len + 1;
		}
		if (strcmp(name, "addr") == 0) {
			const char *name_ptr = fdt_get_name(fdtp, offset, &len);
			if (!name_ptr)
				return -1;
			const char *p = strchr(name_ptr, '@');
			if (p) {
				p++;
				len = strlen(p);
			} else {
				return -1;
			}
			if (len == 0)
				return -1;
			return len + 1;
		}

		return  -1;
	}

	return len;
}

pnode_t
prom_finddevice(const char *device)
{
	int offset = fdt_path_offset(fdtp, device);
	if (offset < 0)
		return OBP_BADNODE;

	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return OBP_BADNODE;

	return (pnode_t)phandle;
}

pnode_t
prom_rootnode(void)
{
	pnode_t root = prom_finddevice("/");
	if (root < 0) {
		return OBP_NONODE;
	}
	return root;
}

pnode_t
prom_chosennode(void)
{
	pnode_t node = prom_finddevice("/chosen");
	if (node != OBP_BADNODE)
		return node;
	return OBP_NONODE;
}

pnode_t
prom_optionsnode(void)
{
	pnode_t node = prom_finddevice("/options");
	if (node != OBP_BADNODE)
		return node;
	return OBP_NONODE;
}

char *
prom_nextprop(pnode_t nodeid, const char *name, char *next)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return NULL;

	*next = '\0';
	offset = fdt_first_property_offset(fdtp, offset);
	if (offset < 0) {
		return next;
	}

	const struct fdt_property *data;
	for (;;) {
		data = fdt_get_property_by_offset(fdtp, offset, NULL);
		const char* name0 = fdt_string(fdtp, fdt32_to_cpu(data->nameoff));
		if (name0) {
			if (*name == '\0') {
				strcpy(next, name0);
				return next;
			}
			if (strcmp(name, name0) == 0)
				break;
		}
		offset = fdt_next_property_offset(fdtp, offset);
		if (offset < 0) {
			return next;
		}
	}
	offset = fdt_next_property_offset(fdtp, offset);
	if (offset < 0) {
		return next;
	}
	data = fdt_get_property_by_offset(fdtp, offset, NULL);
	strcpy(next, (char*)fdt_string(fdtp, fdt32_to_cpu(data->nameoff)));
	return next;
}

pnode_t
prom_nextnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return prom_rootnode();

	int offset = fdt_node_offset_by_phandle(fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return OBP_BADNODE;

	int depth = 1;
	for (;;) {
		offset = fdt_next_node(fdtp, offset, &depth);
		if (offset < 0)
			return OBP_NONODE;
		if (depth == 1)
			break;
	}

	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return OBP_NONODE;
	return (pnode_t)phandle;
}

pnode_t
prom_childnode(pnode_t nodeid)
{
	if (nodeid == OBP_NONODE)
		return prom_rootnode();

	int offset = fdt_node_offset_by_phandle(fdtp, (phandle_t)nodeid);
	if (offset < 0)
		return OBP_NONODE;

	int depth = 0;
	for (;;) {
		offset = fdt_next_node(fdtp, offset, &depth);
		if (offset < 0)
			return OBP_NONODE;
		if (depth == 0)
			return OBP_NONODE;
		if (depth == 1)
			break;
	}
	phandle_t phandle = get_phandle(offset);
	if (phandle < 0)
		return OBP_NONODE;
	return (pnode_t)phandle;
}

pnode_t
prom_parentnode(pnode_t nodeid)
{
	int offset = fdt_node_offset_by_phandle(fdtp, (pnode_t)nodeid);
	if (offset < 0)
		return OBP_NONODE;

	int parent_offset = fdt_parent_offset(fdtp, offset);
	if (parent_offset < 0)
		return OBP_NONODE;
	phandle_t phandle = get_phandle(parent_offset);
	if (phandle < 0)
		return OBP_NONODE;
	return (pnode_t)phandle;
}

char *
prom_decode_composite_string(void *buf, size_t buflen, char *prev)
{
	if ((buf == 0) || (buflen == 0) || ((int)buflen == -1))
		return ((char *)0);

	if (prev == 0)
		return ((char *)buf);

	prev += strlen(prev) + 1;
	if (prev >= ((char *)buf + buflen))
		return ((char *)0);
	return (prev);
}

int
prom_bounded_getprop(pnode_t nodeid, char *name, caddr_t value, int len)
{
	int prop_len = prom_getproplen(nodeid, name);
	if (prop_len < 0 || len < prop_len) {
		return -1;
	}

	return prom_getprop(nodeid, name, value);
}

pnode_t
prom_alias_node(void)
{
	return (OBP_BADNODE);
}

/*ARGSUSED*/
void
prom_pathname(char *buf)
{
	/* nothing, just to get consconfig_dacf to compile */
}

void
prom_init(char *pgmname, void *cookie)
{
	int err;
	fdtp = cookie;

	err = fdt_check_header(fdtp);
	if (err == 0) {
		phandle_t chosen = prom_chosennode();
		if (chosen == OBP_NONODE) {
			fdt_add_subnode(fdtp, fdt_node_offset_by_phandle(fdtp, prom_rootnode()), "chosen");
		}
	} else {
		fdtp = 0;
	}
}

static void
prom_dump_node(dev_info_t *dip)
{
	ddi_prop_t *hwprop;

	prom_printf("name=%s\n", ddi_node_name(dip));
	hwprop = DEVI(dip)->devi_hw_prop_ptr;
	while (hwprop != NULL) {
		prom_printf("    prop=%s\n", hwprop->prop_name);
		hwprop = hwprop->prop_next;
	}
}

static void
prom_dump_peers(dev_info_t *dip)
{
	while (dip) {
		prom_dump_node(dip);
		dip = ddi_get_next_sibling(dip);
	}
}

void
prom_setup(void)
{
	//prom_dump_peers(ddi_root_node());
}

static void
prom_walk_dev(pnode_t nodeid, void(*func)(pnode_t, void*), void *arg)
{
	func(nodeid, arg);

	pnode_t child = prom_childnode(nodeid);
	while (child > 0) {
		prom_walk_dev(child, func, arg);
		child = prom_nextnode(child);
	}
}

void
prom_walk(void(*func)(pnode_t, void*), void *arg)
{
	prom_walk_dev(prom_rootnode(), func, arg);
}
