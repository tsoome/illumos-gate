#include <mdb/mdb_addrvec.h>

/*
 * GDB uses positive integers to specify thread IDs.  Additionally, it uses
 * some non-positive values to indicate special thread selection criteria.
 *
 * -1   = select all threads
 *  0   = select any thread
 *  1.. = select thread with ID
 */
typedef int gdb_tid_t;

#define	GDB_TID_ALL	-1
#define	GDB_TID_ANY	0

struct mdb_gdb_reginfo {
	const char *name;
	unsigned size:15;
	unsigned off:16;
	unsigned le:1;
};

struct mdb_gdb_tgt {
	const struct mdb_gdb_reginfo *reginfo;
	const char *isa;
	const char *platform;
	const int dmodel;

	void (*print_regs)(mdb_nv_t *);
};

typedef struct gdb_data {
	/* arch specific target info */
	const struct mdb_gdb_tgt *tgt;

	/* current state */
	mdb_nv_t regs;
	gdb_tid_t tid;

	/* the socket to the stub */
	int fd;
} gdb_data_t;

extern void gdb_comm_greet(gdb_data_t *tgt);
extern void gdb_comm_cont(gdb_data_t *tgt);
extern int gdb_comm_get_regs(gdb_data_t *tgt);
extern void gdb_comm_get_mem_byte(gdb_data_t *tgt, uint8_t *byte, uint64_t addr);
extern void gdb_comm_select_thread(gdb_data_t *tgt, int tid);
extern void gdb_comm_get_thread_list(gdb_data_t *tgt, mdb_addrvec_t *list);
