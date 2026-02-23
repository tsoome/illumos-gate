
OBJS += multiboot_tramp.o \
        boot_mmu.o \
        dboot.o \
	start.o \
	cpuid.o \
	trap.o \
	exec.o \
	exc.o

OBJS += nullconsole.o \
	spinconsole.o

boot_mmu.o dboot.o := CPPFLAGS += -I$(SRC)/uts/intel -D_BOOT_TARGET_amd64
boot_mmu.o dboot.o := CPPFLAGS += -I$(SRC)/uts/i86pc
