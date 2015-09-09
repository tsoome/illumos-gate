#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_gdb.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>

#define TRACE(msg)	mdb_printf("%s:%d: %s(): %s\n", __FILE__, __LINE__, __func__, (msg))
#define GNOTSUP(name)				\
	static int gdb_##name()			\
	{					\
		TRACE("not impl");		\
		return (mdb_tgt_notsup());	\
	}
#define GNULL(name)				\
	static void *gdb_##name()		\
	{					\
		TRACE("not impl");		\
		return (mdb_tgt_null());	\
	}
#define GNOP(name)				\
	static void *gdb_##name()		\
	{					\
		TRACE("not impl/nop");		\
		return (0);			\
	}

GNOTSUP(setflags)
GNOTSUP(aread)
GNOTSUP(awrite)
GNOTSUP(lookup_by_name)
GNOTSUP(symbol_iter)
GNOTSUP(mapping_iter)
GNOTSUP(run)

/*
 * ::step [ over | out ] [SIG]
 */
static int
gdb_step(mdb_tgt_t *target, mdb_tgt_status_t *tstatus)
{
	mdb_printf("gdb_step\n");
	return (DCMD_USAGE);
}

GNOTSUP(step_out)
GNOTSUP(next)
GNOTSUP(signal)
GNOTSUP(setareg)
GNOTSUP(vwrite)

GNULL(addr_to_map)
GNULL(name_to_map)
GNULL(addr_to_ctf)
GNULL(name_to_ctf)
GNULL(add_vbrkpt)
GNULL(add_sbrkpt)
GNULL(add_pwapt)
GNULL(add_vwapt)
GNULL(add_iowapt)
GNULL(add_sysenter)
GNULL(add_sysexit)
GNULL(add_signal)
GNULL(add_fault)

GNOP(deactivate)
GNOP(stack_iter)

static int
gdb_auxv(mdb_tgt_t *t, const auxv_t **auxvp)
{
	return (0);
}

static int
gdb_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	gdb_data_t *data = t->t_data;
	const struct mdb_gdb_reginfo *regs = data->tgt->reginfo;

	if (argc != 0)
		return (DCMD_USAGE);

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE); // XXX: thread id

	if (gdb_comm_get_regs(data))
		return (DCMD_ERR);

	data->tgt->print_regs(&data->regs);

	return (DCMD_OK);
}

static const mdb_dcmd_t gdb_dcmds[] = {
#if 0
	{ "$c", "?[cnt]", "print stack backtrace", gdb_stack },
	{ "$C", "?[cnt]", "print stack backtrace", gdb_stackv },
#endif
	{ "$r", "?", "print general-purpose registers", gdb_regs },
#if 0
	{ "$x", "?", "print floating point registers", gdb_fpregs },
	{ "$X", "?", "print floating point registers", gdb_fpregs },
	{ "$y", "?", "print floating point registers", gdb_fpregs },
	{ "$Y", "?", "print floating point registers", gdb_fpregs },
	{ "$?", "?", "print status and registers", gdb_regstatus },
#endif
	{ "regs", "?", "print general-purpose registers", gdb_regs },
#if 0
	{ "fpregs", "?[-dqs]", "print floating point registers", gdb_fpregs },
	{ "stack", "?[cnt]", "print stack backtrace", gdb_stack },
	{ "stackregs", "?", "print stack backtrace and registers", gdb_stackr },
	{ "status", NULL, "print summary of current target", gdb_status_dcmd },
#endif
	{ NULL, },
};

static int
gdb_tid_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_data = mdb_zalloc(sizeof (mdb_addrvec_t), UM_SLEEP);
	mdb_addrvec_create(wsp->walk_data);

	gdb_comm_get_thread_list(mdb.m_target->t_data, wsp->walk_data);

	return (WALK_NEXT);
}

static void
gdb_tid_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_addrvec_destroy(wsp->walk_data);
	mdb_free(wsp->walk_data, sizeof (mdb_addrvec_t));
}

static int
gdb_tid_walk_step(mdb_walk_state_t *wsp)
{
	if (mdb_addrvec_length(wsp->walk_data) != 0)
		return wsp->walk_callback(mdb_addrvec_shift(wsp->walk_data),
		    NULL, wsp->walk_cbdata);

	return (WALK_DONE);
}

static const mdb_walker_t gdb_walkers[] = {
	{ "thread", "walk list of valid thread identifiers",
	    gdb_tid_walk_init, gdb_tid_walk_step, gdb_tid_walk_fini },
	{ NULL, },
};

static int
gdb_setcontext(mdb_tgt_t *t, void *context)
{
	gdb_data_t *data = t->t_data;
	gdb_tid_t tid = (intptr_t)context;

	/* don't allow non-positive tids */
	if (tid <= 0)
		return (DCMD_ERR);

	if (tid == data->tid)
		return (DCMD_OK);

	gdb_comm_select_thread(data, tid);
	data->tid = tid;

	return (DCMD_OK);
}

static void
gdb_activate(mdb_tgt_t *t)
{
	TRACE("");
	mdb_prop_postmortem = FALSE;
	mdb_prop_kernel = FALSE;
	mdb_prop_datamodel = MDB_TGT_MODEL_NATIVE;

	gdb_comm_greet(t->t_data);
	/* XXX: we should select GDB_TID_ANY, and then query */
	gdb_comm_select_thread(t->t_data, 1);

	(void) mdb_tgt_register_dcmds(t, &gdb_dcmds[0], MDB_MOD_FORCE);
	(void) mdb_tgt_register_walkers(t, &gdb_walkers[0], MDB_MOD_FORCE);
}

static void
gdb_periodic(mdb_tgt_t *t)
{
}

static const char *
gdb_name(mdb_tgt_t *t)
{
	return ("gdb");
}

static const char *
gdb_isa(mdb_tgt_t *t)
{
	gdb_data_t *data = t->t_data;

	return (data->tgt->isa);
}

static const char *
gdb_platform(mdb_tgt_t *t)
{
	gdb_data_t *data = t->t_data;

	return (data->tgt->platform);
}

static ssize_t
gdb_vread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	char *ptr = buf;
	ssize_t ret = nbytes;

	for (; nbytes; nbytes--, addr++, ptr++)
		gdb_comm_get_mem_byte(t->t_data, (uint8_t *)ptr, addr);

	return (ret);
}

static int
gdb_uname(mdb_tgt_t *t, struct utsname *utsp)
{
	TRACE("");
	(void) strcpy(utsp->sysname, "sysname");
	(void) strcpy(utsp->nodename, "nodename");
	(void) strcpy(utsp->release, "release");
	(void) strcpy(utsp->version, "version");
	(void) strcpy(utsp->machine, "machine");

	return (0);
}

static int
gdb_dmodel(mdb_tgt_t *t)
{
	gdb_data_t *data = t->t_data;

	return data->tgt->dmodel;
}

static int
gdb_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	TRACE("");
	bzero(tsp, sizeof (mdb_tgt_status_t));

	tsp->st_state = MDB_TGT_STOPPED;
	// XXX: tsp->st_tid = X;
	// XXX: tsp->st_pc  = X;
	// XXX: tsp->st_flags = X;

	return (0);
}

static int
gdb_lookup_by_addr(mdb_tgt_t *t, uintptr_t addr, uint_t flags,
    char *buf, size_t nbytes, GElf_Sym *symp, mdb_syminfo_t *sip)
{
	return (set_errno(EMDB_NOSYMADDR));
}

static int
gdb_cont(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	/* XXX: this should block waiting for ^C or similar */
	gdb_comm_cont(t->t_data);

	/* XXX: this should be set in the above function */
	tsp->st_state = MDB_TGT_RUNNING;

	return (0);
}

static int
gdb_getareg(mdb_tgt_t *t, mdb_tgt_tid_t tid, const char *rname,
    mdb_tgt_reg_t *rp)
{
	gdb_data_t *data = t->t_data;
	mdb_var_t *v;
	int ret;

	(void) gdb_comm_get_regs(data);

	if ((v = mdb_nv_lookup(&data->regs, rname))) {
		*rp = mdb_nv_get_value(v);
		ret = 0;
	} else {
		ret = 1;
	}

	return (ret);
}

void mdb_gdb_tgt_destroy(mdb_tgt_t *t);

static const mdb_tgt_ops_t gdb_ops = {
	.t_setflags = (int (*)()) gdb_setflags,
	.t_setcontext = gdb_setcontext,
	.t_activate = gdb_activate,
	.t_deactivate = (void (*)()) gdb_deactivate,
	.t_periodic = gdb_periodic,
	.t_destroy = mdb_gdb_tgt_destroy,
	.t_name = gdb_name,
	.t_isa = gdb_isa,
	.t_platform = gdb_platform,
	.t_uname = gdb_uname,
	.t_dmodel = gdb_dmodel,
	.t_aread = (ssize_t (*)()) gdb_aread,
	.t_awrite = (ssize_t (*)()) gdb_awrite,
	.t_vread = gdb_vread,
	.t_vwrite = (ssize_t (*)()) gdb_vwrite,
	.t_pread = (ssize_t (*)()) mdb_tgt_notsup,
	.t_pwrite = (ssize_t (*)()) mdb_tgt_notsup,
	.t_fread = (ssize_t (*)()) mdb_tgt_notsup,
	.t_fwrite = (ssize_t (*)()) mdb_tgt_notsup,
	.t_ioread = (ssize_t (*)()) mdb_tgt_notsup,
	.t_iowrite = (ssize_t (*)()) mdb_tgt_notsup,
	.t_vtop = (int (*)()) mdb_tgt_notsup,
	.t_lookup_by_name = (int (*)()) gdb_lookup_by_name,
	.t_lookup_by_addr = gdb_lookup_by_addr,
	.t_symbol_iter = (int (*)()) gdb_symbol_iter,
	.t_mapping_iter = (int (*)()) gdb_mapping_iter,
	.t_addr_to_map = (const mdb_map_t *(*)()) gdb_addr_to_map,
	.t_name_to_map = (const mdb_map_t *(*)()) gdb_name_to_map,
	.t_addr_to_ctf = (struct ctf_file *(*)()) gdb_addr_to_ctf,
	.t_name_to_ctf = (struct ctf_file *(*)()) gdb_name_to_ctf,
	.t_status = gdb_status,
	.t_run = (int (*)()) gdb_run,
	.t_step = (int (*)()) gdb_step,
	.t_step_out = (int (*)()) gdb_step_out,
	.t_next = (int (*)()) gdb_next,
	.t_cont = gdb_cont,
	.t_signal = (int (*)()) gdb_signal,
	.t_add_vbrkpt = (int (*)()) gdb_add_vbrkpt,
	.t_add_sbrkpt = (int (*)()) gdb_add_sbrkpt,
	.t_add_pwapt = (int (*)()) gdb_add_pwapt,
	.t_add_vwapt = (int (*)()) gdb_add_vwapt,
	.t_add_iowapt = (int (*)()) gdb_add_iowapt,
	.t_add_sysenter = (int (*)()) gdb_add_sysenter,
	.t_add_sysexit = (int (*)()) gdb_add_sysexit,
	.t_add_signal = (int (*)()) gdb_add_signal,
	.t_add_fault = (int (*)()) gdb_add_fault,
	.t_getareg = gdb_getareg,
	.t_putareg = (int (*)()) gdb_setareg,
	.t_stack_iter = (int (*)()) gdb_stack_iter,
	.t_auxv = gdb_auxv
};

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int
mdb_gdb_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	extern const struct mdb_gdb_tgt mdb_gdb_tgt_ia32;
	struct addrinfo hints, *res, *r;
	gdb_data_t *data;
	char *target = NULL, *host, *port;
	int rv, tlen = 0;

	host = "localhost";
	port = "1234";

	if (argc == 1) {
		target = strdup(argv[0]);
		tlen = strlen(target);
		if (target[tlen-1] != ']' && strrchr(target, ':') != NULL) {
			port = strrchr(target, ':');
			if (target != port)
				host = target;
			*port++ = '\0';
		} else
			host = target;
	}
	if (*host == '[') {
		int len = strlen(host);
		host[len-1] = '\0';
		host++;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(host, port, &hints, &res)) != 0) {
		mdb_printf("failed to resolve '%s:%s': %s\n", host, port,
		    gai_strerror(rv));

		if (target != NULL)
			mdb_free(target, tlen+1);
		return (-1);
	}

	data = mdb_zalloc(sizeof (gdb_data_t), UM_SLEEP);

	for (r = res; r != NULL; r = r->ai_next) {
		data->fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (data->fd == -1)
			continue;

		rv = connect(data->fd, r->ai_addr, r->ai_addrlen);
		if (rv == -1) {
			(void) close(data->fd);
			continue;
		}
		break;
	}
	if (r == NULL) {
		mdb_printf("failed to connect '%s:%s'\n", host, port);
		if (data->fd != -1)
			(void) close(data->fd);
		if (target != NULL)
			mdb_free(target, tlen + 1);
		mdb_free(data, sizeof (gdb_data_t));
		return (-1);
	}

	if (target != NULL)
		mdb_free(target, tlen+1);

	data->tgt = &mdb_gdb_tgt_ia32;
	data->tid = 0;
	(void) mdb_nv_create(&data->regs, UM_SLEEP);

	t->t_ops = &gdb_ops;
	t->t_data = data;

	return (0);
}

void
mdb_gdb_tgt_destroy(mdb_tgt_t *t)
{
	gdb_data_t *data = t->t_data;

	(void) close(data->fd);
	mdb_nv_destroy(&data->regs);

	mdb_free(data, sizeof (gdb_data_t));
}
