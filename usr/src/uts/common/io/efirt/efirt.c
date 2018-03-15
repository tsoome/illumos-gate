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
 * Copyright 2018 Toomas Soome <tsoome@me.com>
 */

#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/psm.h>
#include <sys/smp_impldefs.h>
#include "efirt.h"

static int efirt_open(dev_t *devp, int flag, int otyp, struct cred *credp);
static int efirt_close(dev_t dev, int flag, int otyp, struct cred *credp);
static int efirt_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int efirt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int efirt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct cb_ops efirt_cb_ops = {
	.cb_open = efirt_open,
	.cb_close = efirt_close,
	.cb_strategy = nodev,	/* no strategy */
	.cb_print = nodev,	/* no print */
	.cb_dump = nodev,	/* no dump */
	.cb_read = nodev,	/* no read */
	.cb_write = nodev,	/* no write */
	.cb_ioctl = efirt_ioctl,
	.cb_devmap = nodev,	/* no devmap */
	.cb_mmap = nodev,	/* no mmap */
	.cb_segmap = nodev,	/* no segmap */
	.cb_chpoll = nochpoll,	/* no chpoll entry point */
	.cb_prop_op = ddi_prop_op,
	.cb_str = NULL,
	.cb_flag = D_NEW | D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops efirt_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = nulldev,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = efirt_attach,
	.devo_detach = efirt_detach,
	.devo_reset = nodev,
	.devo_cb_ops = &efirt_cb_ops,
	.devo_bus_ops = NULL,
	.devo_power = NULL,
	.devo_quiesce = ddi_quiesce_not_needed
};

extern struct mod_ops mod_driverops;

static struct modldrv Modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "efirt driver v1.0",
	.drv_dev_ops = &efirt_ops
};

static struct modlinkage Modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &Modldrv, NULL }
};

/*
 * This bit of static data is used by the DDI to
 * keep track of the per-instance driver "soft state"
 */
void *efirt_state;

int
_init(void)
{
	int rv;

	rv = ddi_soft_state_init(&efirt_state, sizeof (struct efirt_state), 1);
	if (rv != DDI_SUCCESS)
		return (rv);

	rv = mod_install(&Modlinkage);
	if (rv != DDI_SUCCESS) {
		ddi_soft_state_fini(&efirt_state);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&Modlinkage, modinfop));
}

int
_fini(void)
{
	int rv;

	rv = mod_remove(&Modlinkage);
	if (rv == DDI_SUCCESS)
		ddi_soft_state_fini(&efirt_state);
	return (rv);
}

static int
efirt_get_systype(dev_info_t *root)
{
	int rv;
	long val;
	char *systype, *end;


	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, root, DDI_PROP_DONTPASS,
	    "efi-systype", &systype) != DDI_PROP_SUCCESS)
		return (0);

	rv = ddi_strtol(systype, &end, 10, &val);
	ddi_prop_free(systype);
	if (rv != 0 || systype == end) {
		return (0);
	}

	switch (val) {
	case 32:
		rv = EFIRT_INIT_ARCH32;
		break;
	case 64:
		rv = EFIRT_INIT_ARCH64;
		break;
	default:
		rv = 0;
		break;
	}
	return (rv);
}

static int
efirt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance, systype;
	struct efirt_state *softp;
	uint32_t size;
	uint64_t systab;
	caddr_t ptr;
	dev_info_t *root;
	EFI_TABLE_HEADER *et;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	root = ddi_root_node();
	systab = (uint64_t)ddi_prop_get_int64(DDI_DEV_T_ANY, root,
	    DDI_PROP_DONTPASS, "efi-systab", 0);

	if (systab == 0 || systab == DDI_PROP_NOT_FOUND)
		return (DDI_FAILURE);

	systype = efirt_get_systype(root);
	if (systype == 0)
		return (DDI_FAILURE);

	et = (EFI_TABLE_HEADER *)psm_map_phys(systab, sizeof (*et),
	    PSM_PROT_READ);
	if (et == NULL)
		return (DDI_FAILURE);
	size = et->HeaderSize;
	psm_unmap_phys((caddr_t)et, sizeof (*et));
	ptr = psm_map_phys(systab, size, PSM_PROT_READ);
	if (ptr == NULL)
		return (DDI_FAILURE);

	/* Use the instance number as the minor number */
	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(efirt_state, instance) == DDI_FAILURE)
		return (DDI_FAILURE);

	softp = ddi_get_soft_state(efirt_state, instance);
	ASSERT(softp != NULL);

	if (ddi_create_minor_node(dip, EFIRT_MINOR_NAME,
		S_IFCHR, instance, DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Minor creation failed!");
		return (DDI_FAILURE);
	}
	softp->efi_init_state |= EFIRT_INIT_MINOR | systype;
	if (systype == EFIRT_INIT_ARCH32)
		softp->efi_systab_u.efi_systab32 = (EFI_SYSTEM_TABLE32 *)ptr;
	else
		softp->efi_systab_u.efi_systab64 = (EFI_SYSTEM_TABLE64 *)ptr;

	softp->efi_dip = dip;
	mutex_init(&softp->efi_mutex, NULL, MUTEX_DRIVER, 0);
	softp->efi_buffer = kmem_alloc(EFIRT_BUFLEN, KM_SLEEP);
	ddi_report_dev(dip);    /* Announce we've attached! */

	return (DDI_SUCCESS);
}

static int
efirt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	struct efirt_state *softp;
	caddr_t ptr;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/* Use the instance number as the minor number */
	instance = ddi_get_instance(dip);

	softp = ddi_get_soft_state(efirt_state, instance);

	ASSERT(softp != NULL);
	if (softp->efi_init_state & EFIRT_INIT_MINOR) {
		/* Remove minor nodes associated with dip */
		ddi_remove_minor_node(dip, NULL);
	}
	ptr = (caddr_t)softp->efi_systab_u.efi_systab64;
	psm_unmap_phys(ptr, softp->efi_systab_u.efi_systab64->Hdr.HeaderSize);

	ASSERT(softp->efi_buffer != NULL);
	kmem_free(softp->efi_buffer, EFIRT_BUFLEN);

	ddi_soft_state_free(efirt_state, instance);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
efirt_open(dev_t *devp, int flag, int otyp, struct cred *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
efirt_close(dev_t dev, int flag, int otyp, struct cred *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
efirt_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp,
    int *rvalp)
{
	return (ENOTTY);
}
