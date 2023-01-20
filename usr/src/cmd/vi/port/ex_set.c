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
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/* Copyright (c) 1981 Regents of the University of California */

#include "ex.h"
#include "ex_temp.h"
#include "ex_tty.h"
#include <string.h>

extern int getchar(void);
extern int putchar(int);

/*
 * Set command.
 */
unsigned char	optname[ONMSZ];

void
set(void)
{
	unsigned char *cp;
	struct option *op;
	int c;
	bool no;
	extern short ospeed;
#ifdef TRACE
	int k, label;
	line *tmpadr;
#endif

	setnoaddr();
	if (skipend()) {
		if (peekchar() != EOF)
			ignchar();
		propts();
		return;
	}
	do {
		cp = optname;
		do {
			if (cp < &optname[ONMSZ - 2])
				*cp++ = getchar();
		} while (isalnum(peekchar()));
		*cp = 0;
		cp = optname;
		if (eq("all", (char *)cp)) {
			if (inopen)
				pofix();
			prall();
			goto next;
		}
		no = 0;
#ifdef TRACE
 		/*
 		 * General purpose test code for looking at address of those
 		 * invisible marks (as well as the visible ones).
 		 */
 		if (eq("marks", cp)) {
			viprintf((unsigned char *)"Marks   Address\n\r");
			viprintf((unsigned char *)
			    "					\n");
			viprintf((unsigned char *)"\n");
			for (k = 0; k <= 25; k++)
				viprintf((unsigned char *)"Mark:%c\t%d\n",
				    k+'a', names[k]);
			goto next;
 		}

		/*
		 * General purpose test code for looking at
		 * named registers.
		 */

		if (eq("named",cp)) {
			if (inopen)
				pofix();
			shownam();
			goto next;
		}

		/*
	   	 * General purpose test code for looking at
		 * numbered registers.
		 */

		if (eq("nbrreg",cp)) {
			if (inopen)
				pofix();
			shownbr();
			goto next;
		}

		/*
 		 * General purpose test code for looking at addresses
		 * in the edit and save areas of VI.
 		 */

 		if (eq("buffers",cp)) {
 			if (inopen)
				pofix();
			viprintf((unsigned char *)
			    "\nLabels   Address	Contents\n");
 			viprintf((unsigned char *)
			    "======   =======	========");
			for (tmpadr = zero; tmpadr <= dol; tmpadr++) {
 				label =0;
				if (tmpadr == zero) {
					viprintf((unsigned char *)"ZERO:\t");
 					label = 2;
 				}
 				if (tmpadr == one) {
					if (label > 0)
						viprintf((unsigned char *)"\nONE:\t");
					else
						viprintf((unsigned char *)"ONE:\t");
 					label = 1;
 				}
 				if (tmpadr == dot) {
					if (label > 0)
						viprintf((unsigned char *)"\nDOT:\t");
					else
						viprintf((unsigned char *)"DOT:\t");
 					label = 1;
 				}
 				if (tmpadr == undap1) {
 					if (label > 0)
						viprintf((unsigned char *)"\nUNDAP1:\t");
 					else
						viprintf((unsigned char *)"UNDAP1:\t");
 					label = 1;
 				}
 				if (tmpadr == undap2) {
 					if (label > 0)
						viprintf((unsigned char *)"\nUNDAP2:\t");
 					else
						viprintf((unsigned char *)"UNDAP2:\t");
 					label = 1;
 				}
 				if (tmpadr == unddel) {
 					if (label > 0)
						viprintf((unsigned char *)"\nUNDDEL:\t");
 					else
						viprintf((unsigned char *)"UNDDEL:\t");
 					label = 1;
 				}
 				if (tmpadr == dol) {
 					if (label > 0)
						viprintf((unsigned char *)"\nDOL:\t");
 					else
						viprintf((unsigned char *)"DOL:\t");
 					label = 1;
 				}
 				for (k=0; k<=25; k++)
 					if (names[k] == (*tmpadr &~ 01)) {
 						if (label > 0)
							viprintf(
							    (unsigned char *)
"\nMark:%c\t%d\t", k+'a', names[k]);
 						else
							viprintf(
							    (unsigned char *)
"Mark:%c\t%d\t", k+'a', names[k]);
 						label=1;
 					}
 				if (label == 0)
 					continue;

 				if (label == 2)
					viprintf((unsigned char *)"%d\n",
					    tmpadr);
 				else  {
					viprintf((unsigned char *)"%d\t",
					    tmpadr);
 					getaline(*tmpadr);
 					pline(lineno(tmpadr));
 					putchar('\n');
 				}
 			}

 			for (tmpadr = dol+1; tmpadr <= unddol; tmpadr++) {
 				label =0;
 				if (tmpadr == dol+1) {
					viprintf((unsigned char *)"DOL+1:\t");
 					label = 1;
 				}
 				if (tmpadr == unddel) {
 					if (label > 0)
						viprintf((unsigned char *)
						    "\nUNDDEL:\t");
 					else
						viprintf((unsigned char *)
						    "UNDDEL:\t");
 					label = 1;
 				}
 				if (tmpadr == unddol) {
 					if (label > 0)
						viprintf((unsigned char *)
						    "\nUNDDOL:\t");
 					else
						viprintf((unsigned char *)
						    "UNDDOL:\t");
 					label = 1;
 				}
 				for (k=0; k<=25; k++)
 					if (names[k] == (*tmpadr &~ 01)) {
 						if (label > 0)
							viprintf(
							    (unsigned char *)
"\nMark:%c\t%d\t", k+'a', names[k]);
 						else
							viprintf(
							    (unsigned char *)
"Mark:%c\t%d\t", k+'a', names[k]);
 						label=1;
 					}
 				if (label == 0)
 					continue;
 				if (label == 2)
					viprintf((unsigned char *)"%d\n",
					    tmpadr);
 				else  {
					viprintf((unsigned char *)"%d\t",
					    tmpadr);
 					getaline(*tmpadr);
 					pline(lineno(tmpadr));
 					putchar('\n');
 				}
 			}
 			goto next;
 		}
#endif
		if (cp[0] == 'n' && cp[1] == 'o' && cp[2] != 'v') {
			cp += 2;
			no++;
		}
		/* Implement w300, w1200, and w9600 specially */
		if (eq((char *)cp, "w300")) {
			if (ospeed >= B1200) {
dontset:
				(void)getchar();	/* = */
				(void)getnum();	/* value */
				continue;
			}
			cp = (unsigned char *)"window";
		} else if (eq((char *)cp, "w1200")) {
			if (ospeed < B1200 || ospeed >= B2400)
				goto dontset;
			cp = (unsigned char *)"window";
		} else if (eq((char *)cp, "w9600")) {
			if (ospeed < B2400)
				goto dontset;
			cp = (unsigned char *)"window";
		}
		for (op = options; op < &options[vi_NOPTS]; op++)
			if (eq((char *)op->oname, (char *)cp) ||
			    eq((char *)op->oabbrev, (char *)cp))
				break;
		if (op->oname == 0)
			serror(value(vi_TERSE) ? (unsigned char *)
			    gettext("%s: No such option") :
			    (unsigned char *)
gettext("%s: No such option - 'set all' gives all option values"), cp);
		c = skipwh();
		if (peekchar() == '?') {
			ignchar();
printone:
			propt(op);
			noonl();
			goto next;
		}
		if (op->otype == ONOFF) {
			op->ovalue = 1 - no;
			if (op == &options[vi_PROMPT])
				oprompt = 1 - no;
			goto next;
		}
		if (no)
			serror((unsigned char *)
			    gettext("Option %s is not a toggle"), op->oname);
		if (c != 0 || setend())
			goto printone;
		if (getchar() != '=')
			serror(value(vi_TERSE) ? (unsigned char *)
			    gettext("Missing =") :
			    (unsigned char *)
			    gettext("Missing = in assignment to option %s"),
			    op->oname);
		switch (op->otype) {

		case NUMERIC:
			if (!isdigit(peekchar()))
				error(value(vi_TERSE) ?
				    (unsigned char *)gettext(
				    "Digits required") :
				    (unsigned char *)gettext(
				    "Digits required after ="));
			op->ovalue = getnum();
			if (value(vi_TABSTOP) <= 0)
				value(vi_TABSTOP) = TABS;
			if (op == &options[vi_WINDOW]) {
				if (value(vi_WINDOW) >= lines)
					value(vi_WINDOW) = lines-1;
				vsetsiz(value(vi_WINDOW));
			}
			break;

		case STRING:
		case OTERM:
			cp = optname;
			while (!setend()) {
				if (cp >= &optname[ONMSZ])
					error(value(vi_TERSE) ?
					    (unsigned char *)gettext(
					    "String too long") :
					    (unsigned char *)gettext(
					    "String too long in option "
					    "assignment"));
				/* adb change:  allow whitepace in strings */
				if ((*cp = getchar()) == '\\')
					if (peekchar() != EOF)
						*cp = getchar();
				cp++;
			}
			*cp = 0;
			if (op->otype == OTERM) {
/*
 * At first glance it seems like we shouldn't care if the terminal type
 * is changed inside visual mode, as long as we assume the screen is
 * a mess and redraw it. However, it's a much harder problem than that.
 * If you happen to change from 1 crt to another that both have the same
 * size screen, it's OK. But if the screen size if different, the stuff
 * that gets initialized in vop() will be wrong. This could be overcome
 * by redoing the initialization, e.g. making the first 90% of vop into
 * a subroutine. However, the most useful case is where you forgot to do
 * a setenv before you went into the editor and it thinks you're on a dumb
 * terminal. Ex treats this like hardcopy and goes into HARDOPEN mode.
 * This loses because the first part of vop calls oop in this case.
 */
				if (inopen)
					error((unsigned char *)gettext(
					    "Can't change type of terminal "
					    "from within open/visual"));
				unterm();
				setterm(optname);
			} else {
				CP((char *)op->osvalue, (char *)optname);
				op->odefault = 1;
			}
			break;
		}
next:
		flush();
	} while (!skipend());
	eol();
}

void
unterm(void)
{
	/*
	 *  All terminal mapped statements must be deleted.
	 *  All user-defined mapped statements, cap=descr,
	 *  are left unchanged.
	 */

	int i;

	for (i=0; i < MAXNOMACS; i++) {

		/*
		 * Unmap any terminal-defined arrow keys
		 */

		if (arrows[i].cap && arrows[i].descr &&
		    strcmp((char *)arrows[i].cap, (char *)arrows[i].descr))
			addmac(arrows[i].cap, NOSTR, NOSTR, arrows);

		/*
		 * Unmap any terminal-defined function keys
		 */

		if (immacs[i].cap && immacs[i].descr &&
		    strcmp((char *)immacs[i].cap, (char *)immacs[i].descr))
			addmac(immacs[i].cap, NOSTR, NOSTR, immacs);

	}
}


int
setend(void)
{

	return (iswhite(peekchar()) || endcmd(peekchar()));
}

void
prall(void)
{
	int incr = (vi_NOPTS + 2) / 3;
	int rows = incr;
	struct option *op = options;

	for (; rows; rows--, op++) {
		propt(op);
		gotab(24);
		propt(&op[incr]);
		if (&op[2*incr] < &options[vi_NOPTS]) {
			gotab(56);
			propt(&op[2 * incr]);
		}
		putNFL();
	}
}

void
propts(void)
{
	struct option *op;

	for (op = options; op < &options[vi_NOPTS]; op++) {
		if (op == &options[vi_TTYTYPE])
			continue;
		switch (op->otype) {

		case ONOFF:
		case NUMERIC:
			if (op->ovalue == op->odefault)
				continue;
			break;

		case STRING:
			if (op->odefault == 0)
				continue;
			break;
		}
		propt(op);
		putchar(' ');
	}
	noonl();
	flush();
}

void
propt(struct option *op)
{
	unsigned char *name;

	name = (unsigned char *)op->oname;

	switch (op->otype) {

	case ONOFF:
		viprintf((unsigned char *)"%s%s", op->ovalue ? "" : "no", name);
		break;

	case NUMERIC:
		viprintf((unsigned char *)"%s=%d", name, op->ovalue);
		break;

	case STRING:
	case OTERM:
		viprintf((unsigned char *)"%s=%s", name, op->osvalue);
		break;
	}
}
