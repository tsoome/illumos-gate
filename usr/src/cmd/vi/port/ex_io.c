/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#include "ex.h"
#include "ex_argv.h"
#include "ex_temp.h"
#include "ex_tty.h"
#include "ex_vis.h"
#include <crypt.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef getchar
#undef getchar
#endif
#ifdef putchar
#undef putchar
#endif
/*
 * File input/output, source, preserve and recover
 */

/*
 * Following remember where . was in the previous file for return
 * on file switching.
 */
int	altdot;
int	oldadot;
bool	wasalt;
short	isalt;

long	cntch;			/* Count of characters on unit io */
#ifndef VMUNIX
short	cntln;			/* Count of lines " */
#else
int	cntln;
#endif
long	cntnull;		/* Count of nulls " */
long	cntodd;			/* Count of non-ascii characters " */

static void chkmdln(unsigned char *);
static int samei(struct stat64 *, char *);
static int iostats(void);
static int edfile(void);
extern int getchar(void);
extern int putchar(int);
extern int _mbftowc(char *, wchar_t *, int (*)(void), int *);

/*
 * Parse file name for command encoded by comm.
 * If comm is E then command is doomed and we are
 * parsing just so user won't have to retype the name.
 */
void
filename(int comm)
{
	int c = comm, d;
	int i;

	d = getchar();
	if (endcmd(d)) {
		if (savedfile[0] == 0 && comm != 'f')
			error(value(vi_TERSE) ?
			    (unsigned char *)gettext("No file") :
			    (unsigned char *)gettext("No current filename"));
		CP((char *)file, (char *)savedfile);
		wasalt = (isalt > 0) ? isalt-1 : 0;
		isalt = 0;
		oldadot = altdot;
		if (c == 'e' || c == 'E')
			altdot = lineDOT();
		if (d == EOF)
			ungetchar(d);
	} else {
		ungetchar(d);
		getone();
		eol();
		if (savedfile[0] == 0 && c != 'E' && c != 'e') {
			c = 'e';
			edited = 0;
		}
		wasalt = strcmp((char *)file, (char *)altfile) == 0;
		oldadot = altdot;
		switch (c) {

		case 'f':
			edited = 0;
			/* FALLTHROUGH */

		case 'e':
			if (savedfile[0]) {
				altdot = lineDOT();
				CP((char *)altfile, (char *)savedfile);
			}
			CP((char *)savedfile, (char *)file);
			break;

		default:
			if (file[0]) {
				if (c != 'E')
					altdot = lineDOT();
				CP((char *)altfile, (char *)file);
			}
			break;
		}
	}
	if ((hush && comm != 'f') || comm == 'E')
		return;
	if (file[0] != 0) {
		lprintf((unsigned char *)"\"%s\"", file);
		if (comm == 'f') {
			if (value(vi_READONLY))
				viprintf((unsigned char *)gettext(
				    " [Read only]"));
			if (!edited)
				viprintf((unsigned char *)gettext(
				    " [Not edited]"));
			if (tchng)
				viprintf((unsigned char *)gettext(
				    " [Modified]"));
		}
		flush();
	} else
		viprintf((unsigned char *)gettext("No file "));
	if (comm == 'f') {
		if (!(i = lineDOL()))
			i++;
		/*
		 * TRANSLATION_NOTE
		 *	Reference order of arguments must not
		 *	be changed using '%digit$', since vi's
		 *	viprintf() does not support it.
		 */
		viprintf((unsigned char *)gettext(" line %d of %d --%ld%%--"),
		    lineDOT(), lineDOL(), (long)(100 * lineDOT() / i));
	}
}

/*
 * Get the argument words for a command into genbuf
 * expanding # and %.
 */
int
getargs(void)
{
	int c;
	unsigned char *cp, *fp;
	static unsigned char fpatbuf[32];	/* hence limit on :next +/pat */
	char	multic[MB_LEN_MAX + 1];
	int	len;
	wchar_t	wc;

	pastwh();
	if (peekchar() == '+') {
		for (cp = fpatbuf;;) {
			if (!isascii(c = peekchar()) && (c != EOF)) {
				if ((len = _mbftowc(multic, &wc, getchar,
				    &peekc)) > 0) {
					if ((cp + len) >=
					    &fpatbuf[sizeof(fpatbuf)])
						error((unsigned char *)gettext(
						    "Pattern too long"));
					strncpy((char *)cp, multic, len);
					cp += len;
					continue;
				}
			}

			c = getchar();
			*cp++ = c;
			if (cp >= &fpatbuf[sizeof(fpatbuf)])
				error((unsigned char *)gettext(
				    "Pattern too long"));
			if (c == '\\' && isspace(peekchar()))
				c = getchar();
			if (c == EOF || isspace(c)) {
				ungetchar(c);
				*--cp = 0;
				firstpat = &fpatbuf[1];
				break;
			}
		}
	}
	if (skipend())
		return (0);
	CP((char *)genbuf, "echo "); cp = &genbuf[5];
	for (;;) {
		if (!isascii(c = peekchar())) {
			if (endcmd(c) && c != '"')
				break;
			if ((len = _mbftowc(multic, &wc, getchar, &peekc)) > 0) {
				if ((cp + len) > &genbuf[LBSIZE - 2])
					error((unsigned char *)gettext(
					    "Argument buffer overflow"));
				strncpy((char *)cp, multic, len);
				cp += len;
				continue;
			}
		}

		if (endcmd(c) && c != '"')
			break;

		c = getchar();
		switch (c) {

		case '\\':
			if (any(peekchar(), (unsigned char *)"#%|"))
				c = getchar();
			/* FALLTHROUGH */

		default:
			if (cp > &genbuf[LBSIZE - 2])
flong:
				error((unsigned char *)gettext(
				    "Argument buffer overflow"));
			*cp++ = c;
			break;

		case '#':
			fp = (unsigned char *)altfile;
			if (*fp == 0)
				error(value(vi_TERSE) ?
				    (unsigned char *)gettext(
				    "No alternate filename") :
				    (unsigned char *)gettext(
				    "No alternate filename to substitute "
				    "for #"));
			goto filexp;

		case '%':
			fp = savedfile;
			if (*fp == 0)
				error(value(vi_TERSE) ?
				    (unsigned char *)gettext(
				    "No current filename") :
				    (unsigned char *)gettext(
				    "No current filename to substitute "
				    "for %%"));
filexp:
			while (*fp) {
				if (cp > &genbuf[LBSIZE - 2])
					goto flong;
				*cp++ = *fp++;
			}
			break;
		}
	}
	*cp = 0;
	return (1);
}

/*
 * Glob the argument words in genbuf, or if no globbing
 * is implied, just split them up directly.
 */
void
glob(struct glob *gp)
{
	int pvec[2];
	unsigned char **argv = gp->argv;
	unsigned char *cp = gp->argspac;
	int c;
	unsigned char ch;
	int nleft = NCARGS;

	gp->argc0 = 0;
	if (gscan() == 0) {
		unsigned char *v = genbuf + 5;		/* strlen("echo ") */

		for (;;) {
			while (isspace(*v))
				v++;
			if (!*v)
				break;
			*argv++ = cp;
			while (*v && !isspace(*v))
				*cp++ = *v++;
			*cp++ = 0;
			gp->argc0++;
		}
		*argv = 0;
		return;
	}
	if (pipe(pvec) < 0)
		error((unsigned char *)gettext("Can't make pipe to glob"));
	pid = fork();
	io = pvec[0];
	if (pid < 0) {
		close(pvec[1]);
		error((unsigned char *)gettext("Can't fork to do glob"));
	}
	if (pid == 0) {
		int oerrno;

		close(1);
		dup(pvec[1]);
		close(pvec[0]);
		close(2);	/* so errors don't mess up the screen */
		open("/dev/null", 1);
		execlp((char *)svalue(vi_SHELL), "sh", "-c", genbuf, (char *)0);
		oerrno = errno; close(1); dup(2); errno = oerrno;
		filioerr(svalue(vi_SHELL));
	}
	close(pvec[1]);
	do {
		*argv = cp;
		for (;;) {
			if (read(io, &ch, 1) != 1) {
				close(io);
				c = -1;
			} else
				c = ch;
			if (c <= 0 || isspace(c))
				break;
			*cp++ = c;
			if (--nleft <= 0)
				error((unsigned char *)gettext(
				    "Arg list too long"));
		}
		if (cp != *argv) {
			--nleft;
			*cp++ = 0;
			gp->argc0++;
			if (gp->argc0 >= NARGS)
				error((unsigned char *)gettext(
				    "Arg list too long"));
			argv++;
		}
	} while (c >= 0);
	waitfor();
	if (gp->argc0 == 0)
		error((unsigned char *)gettext("No match"));
}

/*
 * Scan genbuf for shell metacharacters.
 * Set is union of v7 shell and csh metas.
 */
int
gscan(void)
{
	unsigned char *cp;
	int	len;

	for (cp = genbuf; *cp; cp += len) {
		if (any(*cp, (unsigned char *)"~{[*?$`'\"\\"))
			return (1);
		if ((len = mblen((char *)cp, MB_CUR_MAX)) <= 0)
			len = 1;
	}
	return (0);
}

/*
 * Parse one filename into file.
 */
struct glob G;
void
getone(void)
{
	unsigned char *str;

	if (getargs() == 0)
		error((unsigned char *)gettext("Missing filename"));
	glob(&G);
	if (G.argc0 > 1)
		error(value(vi_TERSE) ?
		    (unsigned char *)gettext("Ambiguous") :
		    (unsigned char *)gettext("Too many file names"));
	if (G.argc0 < 1)
		error((unsigned char *)gettext("Missing filename"));
	str = G.argv[G.argc0 - 1];
	if (strlen((char *)str) > FNSIZE - 4)
		error((unsigned char *)gettext("Filename too long"));

	CP((char *)file, (char *)str);
}

/*
 * Read a file from the world.
 * C is command, 'e' if this really an edit (or a recover).
 */
void
rop(int c)
{
	struct stat64 stbuf;
	static int ovro;	/* old value(vi_READONLY) */
	static int denied;	/* 1 if READONLY was set due to file permissions */

	io = open((char *)file, O_RDONLY);
	if (io < 0) {
		if (c == 'e' && errno == ENOENT) {
			edited++;
			/*
			 * If the user just did "ex foo" they're probably
			 * creating a new file.  Don't be an error, since
			 * this is ugly, and it messes up the + option.
			 */
			if (!seenprompt) {
				viprintf((unsigned char *)gettext(
				    " [New file]"));
				noonl();
				return;
			}
		}

		if (value(vi_READONLY) && denied) {
			value(vi_READONLY) = ovro;
			denied = 0;
		}
		syserror(0);
	}
	if (fstat64(io, &stbuf))
		syserror(0);
	switch (FTYPE(stbuf) & S_IFMT) {

	case S_IFBLK:
		error((unsigned char *)gettext(" Block special file"));
		/* FALLTHROUGH */

	case S_IFCHR:
		if (isatty(io))
			error((unsigned char *)gettext(" Teletype"));
		if (samei(&stbuf, "/dev/null"))
			break;
		error((unsigned char *)gettext(" Character special file"));
		/* FALLTHROUGH */

	case S_IFDIR:
		error((unsigned char *)gettext(" Directory"));

	}
	if (c != 'r') {
		if (value(vi_READONLY) && denied) {
			value(vi_READONLY) = ovro;
			denied = 0;
		}
		if ((FMODE(stbuf) & 0222) == 0 || access((char *)file, 2) < 0) {
			ovro = value(vi_READONLY);
			denied = 1;
			value(vi_READONLY) = 1;
		}
	}
	if (hush == 0 && value(vi_READONLY)) {
		viprintf((unsigned char *)gettext(" [Read only]"));
		flush();
	}
	if (c == 'r')
		setdot();
	else
		setall();

	/* If it is a read command, then we must set dot to addr1
	 * (value of N in :Nr ).  In the default case, addr1 will
	 * already be set to dot.
	 *
	 * Next, it is necessary to mark the beginning (undap1) and
	 * ending (undap2) addresses affected (for undo).  Note that
	 * rop2() and rop3() will adjust the value of undap2.
	 */
	if (FIXUNDO && inopen && c == 'r') {
		dot = addr1;
		undap1 = undap2 = dot + 1;
	}
	rop2();
	rop3(c);
}

void
rop2(void)
{
	line *first, *last, *a;

	deletenone();
	clrstats();
	first = addr2 + 1;
	(void)append(getfile, addr2);
	last = dot;
	if (value(vi_MODELINES))
		for (a=first; a<=last; a++) {
			if (a==first+5 && last-first > 10)
				a = last - 4;
			getaline(*a);
			chkmdln(linebuf);
		}
}

void
rop3(int c)
{

	if (iostats() == 0 && c == 'e')
		edited++;
	if (c == 'e') {
		if (wasalt || firstpat) {
			line *addr = zero + oldadot;

			if (addr > dol)
				addr = dol;
			if (firstpat) {
				globp = (*firstpat) ? firstpat : (unsigned char *)"$";
				commands(1,1);
				firstpat = 0;
			} else if (addr >= one) {
				if (inopen)
					dot = addr;
				markpr(addr);
			} else
				goto other;
		} else
other:
			if (dol > zero) {
				if (inopen)
					dot = one;
				markpr(one);
			}
		if(FIXUNDO)
			undkind = UNDNONE;
		if (inopen) {
			vcline = 0;
			vreplace(0, lines, lineDOL());
		}
	}
	if (laste) {
#ifdef VMUNIX
		tlaste();
#endif
		laste = 0;
		sync();
	}
}

/*
 * Are these two really the same inode?
 */
static int
samei(struct stat64 *sp, char *cp)
{
	struct stat64 stb;

	if (stat64((char *)cp, &stb) < 0)
		return (0);
	return (IDENTICAL((*sp), stb));
}

/* Returns from edited() */
#define	EDF	0		/* Edited file */
#define	NOTEDF	-1		/* Not edited file */
#define	PARTBUF	1		/* Write of partial buffer to Edited file */

/*
 * Write a file.
 * if dofname call filename, else use savedfile.
 */
void
wop(bool dofname)
{
	int c, exclam, nonexist;
	line *saddr1, *saddr2;
	struct stat64 stbuf;
	char *messagep;

	c = 0;
	exclam = 0;
	if (dofname) {
		if (peekchar() == '!')
			exclam++, ignchar();
		(void)skipwh();
		while (peekchar() == '>')
			ignchar(), c++, (void)skipwh();
		if (c != 0 && c != 2)
			error((unsigned char *)gettext(
			    "Write forms are 'w' and 'w>>'"));
		filename('w');
	} else {
		if (savedfile[0] == 0)
			error(value(vi_TERSE) ?
			    (unsigned char *)gettext("No file") :
			    (unsigned char *)gettext("No current filename"));
		saddr1=addr1;
		saddr2=addr2;
		addr1=one;
		addr2=dol;
		CP((char *)file, (char *)savedfile);
		if (inopen) {
			vclrech(0);
			splitw++;
		}
		lprintf((unsigned char *)"\"%s\"", file);
	}
	nonexist = stat64((char *)file, &stbuf);
	switch (c) {

	case 0:
		if (!exclam && (!value(vi_WRITEANY) || value(vi_READONLY)))
		switch (edfile()) {

		case NOTEDF:
			if (nonexist)
				break;
			if (ISCHR(stbuf)) {
				if (samei(&stbuf, "/dev/null"))
					break;
				if (samei(&stbuf, "/dev/tty"))
					break;
			}
			io = open((char *)file, O_WRONLY);
			if (io < 0)
				syserror(0);
			if (!isatty(io))
				serror(value(vi_TERSE) ?
				    (unsigned char *)gettext(" File exists") :
(unsigned char *)gettext(" File exists - use \"w! %s\" to overwrite"),
				    file);
			close(io);
			break;

		case EDF:
			if (value(vi_READONLY))
				error((unsigned char *)gettext(
				    " File is read only"));
			break;

		case PARTBUF:
			if (value(vi_READONLY))
				error((unsigned char *)gettext(
				    " File is read only"));
			error((unsigned char *)gettext(
			    " Use \"w!\" to write partial buffer"));
		}
cre:
/*
		synctmp();
*/
		io = creat((char *)file, 0666);
		if (io < 0)
			syserror(0);
		writing = 1;
		if (hush == 0) {
			if (nonexist)
				viprintf((unsigned char *)gettext(
				    " [New file]"));
			else if (value(vi_WRITEANY) && edfile() != EDF)
				viprintf((unsigned char *)gettext(
				    " [Existing file]"));
		}
		break;

	case 2:
		io = open((char *)file, O_WRONLY);
		if (io < 0) {
			if (exclam || value(vi_WRITEANY))
				goto cre;
			syserror(0);
		}
		lseek(io, 0l, 2);
		break;
	}
	if (write_quit && inopen && (argc == 0 || morargc == argc))
		setty(normf);
	putfile(0);
	if (fsync(io) < 0) {
		/*
		 * For NFS files write in putfile doesn't return error, but
		 * fsync does.  So, catch it here.
		 */
		messagep = (char *)gettext(
		    "\r\nYour file has been preserved\r\n");
		(void) preserve();
		write(1, messagep, strlen(messagep));

		wrerror();
	}
	(void)iostats();
	if (c != 2 && addr1 == one && addr2 == dol) {
		if (savedfile != NULL &&
		    strcmp((char *)file, (char *)savedfile) == 0)
			edited = 1;
		sync();
	}
	if (!dofname) {
		addr1 = saddr1;
		addr2 = saddr2;
	}
	writing = 0;
}

/*
 * Is file the edited file?
 * Work here is that it is not considered edited
 * if this is a partial buffer, and distinguish
 * all cases.
 */
static int
edfile(void)
{

	if (!edited || savedfile == NULL ||
	    strcmp((char *)file, (char *)savedfile) != 0)
		return (NOTEDF);
	return (addr1 == one && addr2 == dol ? EDF : PARTBUF);
}

/*
 * Extract the next line from the io stream.
 */
unsigned char *nextip;

int
getfile(void)
{
	short c;
	unsigned char *lp;
	unsigned char *fp;

	lp = linebuf;
	fp = nextip;
	do {
		if (--ninbuf < 0) {
			ninbuf = read(io, genbuf, LBSIZE) - 1;
			if (ninbuf < 0) {
				if (lp != linebuf) {
					lp++;
					viprintf((unsigned char *)
					    gettext(" [Incomplete last line]"));
					break;
				}
				return (EOF);
			}
			if(crflag == -1) {
				if(isencrypt((char *)genbuf, ninbuf + 1))
					crflag = 2;
				else
					crflag = -2;
			}
			if (crflag > 0 && run_crypt(cntch, (char *)genbuf,
			    ninbuf+1, perm) == -1) {
					smerror((unsigned char *)gettext(
					    "Cannot decrypt block of text\n"));
					break;
			}
			fp = genbuf;
			cntch += ninbuf+1;
		}
		if (lp >= &linebuf[LBSIZE]) {
			error((unsigned char *)gettext(" Line too long"));
		}
		c = *fp++;
		if (c == 0) {
			cntnull++;
			continue;
		}
		*lp++ = c;
	} while (c != '\n');
	*--lp = 0;
	nextip = fp;
	cntln++;
	return (0);
}

/*
 * Write a range onto the io stream.
 */
void
putfile(int isfilter)
{
	line *a1;
	unsigned char *lp;
	unsigned char *fp;
	int nib;
	bool ochng = chng;
	char *messagep;

	chng = 1;		/* set to force file recovery procedures in */
				/* the event of an interrupt during write   */
	a1 = addr1;
	clrstats();
	cntln = addr2 - a1 + 1;
	nib = BUFSIZE;
	fp = genbuf;
	do {
		getaline(*a1++);
		lp = linebuf;
		for (;;) {
			if (--nib < 0) {
				nib = fp - genbuf;
                		if(kflag && !isfilter)
                                        if (run_crypt(cntch, (char *)genbuf,
					    nib, perm) == -1)
						wrerror();
				if (write(io, genbuf, nib) != nib) {
				    messagep = (char *)gettext(
					"\r\nYour file has been preserved\r\n");
				    (void) preserve();
				    write(1, messagep, strlen(messagep));

				    if (!isfilter)
					wrerror();
				    return;
				}
				cntch += nib;
				nib = BUFSIZE - 1;
				fp = genbuf;
			}
			if ((*fp++ = *lp++) == 0) {
				fp[-1] = '\n';
				break;
			}
		}
	} while (a1 <= addr2);
	nib = fp - genbuf;
	if(kflag && !isfilter)
		if (run_crypt(cntch, (char *)genbuf, nib, perm) == -1)
			wrerror();
	if ((cntch == 0) && (nib == 1)) {
		cntln = 0;
		return;
	}
	if (write(io, genbuf, nib) != nib) {
		messagep = (char *)gettext(
		    "\r\nYour file has been preserved\r\n");
		(void) preserve();
		write(1, messagep, strlen(messagep));

		if(!isfilter)
			wrerror();
		return;
	}
	cntch += nib;
	chng = ochng;			/* reset chng to original value */
}

/*
 * A write error has occurred;  if the file being written was
 * the edited file then we consider it to have changed since it is
 * now likely scrambled.
 */
void
wrerror(void)
{

	if (savedfile != NULL &&
	    strcmp((char *)file, (char *)savedfile) == 0 && edited)
		change();
	syserror(1);
}

/*
 * Source command, handles nested sources.
 * Traps errors since it mungs unit 0 during the source.
 */
short slevel;
short ttyindes;

void
source(fil, okfail)
	unsigned char *fil;
	bool okfail;
{
	jmp_buf osetexit;
	int saveinp, ointty, oerrno;
	unsigned char *saveglobp;
	short savepeekc;

	signal(SIGINT, SIG_IGN);
	saveinp = dup(0);
	savepeekc = peekc;
	saveglobp = globp;
	peekc = 0; globp = 0;
	if (saveinp < 0)
		error((unsigned char *)gettext("Too many nested sources"));
	if (slevel <= 0)
		ttyindes = saveinp;
	close(0);
	if (open((char *)fil, 0) < 0) {
		oerrno = errno;
		setrupt();
		dup(saveinp);
		close(saveinp);
		errno = oerrno;
		if (!okfail)
			filioerr(fil);
		return;
	}
	slevel++;
	ointty = intty;
	intty = isatty(0);
	oprompt = value(vi_PROMPT);
	value(vi_PROMPT) &= intty;
	getexit(osetexit);
	setrupt();
	if (setexit() == 0)
		commands(1, 1);
	else if (slevel > 1) {
		close(0);
		dup(saveinp);
		close(saveinp);
		slevel--;
		resexit(osetexit);
		reset();
	}
	intty = ointty;
	value(vi_PROMPT) = oprompt;
	close(0);
	dup(saveinp);
	close(saveinp);
	globp = saveglobp;
	peekc = savepeekc;
	slevel--;
	resexit(osetexit);
}

/*
 * Clear io statistics before a read or write.
 */
void
clrstats(void)
{

	ninbuf = 0;
	cntch = 0;
	cntln = 0;
	cntnull = 0;
	cntodd = 0;
}

/*
 * Io is finished, close the unit and print statistics.
 */
static int
iostats(void)
{

	close(io);
	io = -1;
	if (hush == 0) {
		if (value(vi_TERSE))
			viprintf((unsigned char *)" %d/%D", cntln, cntch);
		else if (cntln == 1 && cntch == 1) {
			viprintf((unsigned char *)gettext(
			    " 1 line, 1 character"));
		} else if (cntln == 1 && cntch != 1) {
			viprintf((unsigned char *)gettext(
			    " 1 line, %D characters"), cntch);
		} else if (cntln != 1 && cntch != 1) {
			/*
			 * TRANSLATION_NOTE
			 *	Reference order of arguments must not
			 *	be changed using '%digit$', since vi's
			 *	viprintf() does not support it.
			 */
			viprintf((unsigned char *)gettext(
			    " %d lines, %D characters"), cntln, cntch);
		} else {
			/* ridiculous */
			viprintf((unsigned char *)gettext(
			    " %d lines, 1 character"), cntln);
		}
		if (cntnull || cntodd) {
			viprintf((unsigned char *)" (");
			if (cntnull) {
				viprintf((unsigned char *)
				    gettext("%D null"), cntnull);
				if (cntodd)
					viprintf((unsigned char *)", ");
			}
			if (cntodd)
				viprintf((unsigned char *)
				    gettext("%D non-ASCII"), cntodd);
			putchar(')');
		}
		noonl();
		flush();
	}
	return (cntnull != 0 || cntodd != 0);
}


static void
chkmdln(unsigned char *aline)
{
	unsigned char *beg, *end;
	unsigned char cmdbuf[1024];
	bool savetty;
	int  savepeekc;
	int  savechng;
	unsigned char	*savefirstpat;
	unsigned char	*p;
	int	len;

	beg = (unsigned char *)strchr((char *)aline, ':');
	if (beg == NULL)
		return;
	if ((len = beg - aline) < 2)
		return;

	p = aline;
	if ((beg - aline) != 2) {
		if ((p = beg - ((unsigned int)MB_CUR_MAX * 2) - 2) < aline)
			p = aline;
		for ( ; p < (beg - 2); p += len) {
			if ((len = mblen((char *)p, MB_CUR_MAX)) <= 0)
				len = 1;
		}
		if (p != (beg - 2))
			return;
	}

	if (!((beg[-2] == 'e' && p[-1] == 'x')
	||    (beg[-2] == 'v' && beg[-1] == 'i')))
	 	return;

	strncpy((char *)cmdbuf, (char *)beg+1, sizeof cmdbuf);
	end = (unsigned char *)strrchr((char *)cmdbuf, ':');
	if (end == NULL)
		return;
	*end = 0;
	globp = cmdbuf;
	savepeekc = peekc;
	peekc = 0;
	savetty = intty;
	intty = 0;
	savechng = chng;
	savefirstpat = firstpat;
	firstpat = (unsigned char *)"";
	commands(1, 1);
	peekc = savepeekc;
	globp = 0;
	intty = savetty;
	/* chng being increased indicates that text was changed */
	if (savechng < chng)
		laste = 0;
	firstpat = savefirstpat;
}
