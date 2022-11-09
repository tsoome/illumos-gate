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

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Utility functions
 */
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <sgs.h>
#include <libintl.h>
#include <debug.h>
#include "msg.h"
#include "_libld.h"

/*
 * Determine if a shared object definition structure already exists and if
 * not create one.  These definitions provide for recording information
 * regarding shared objects that are still to be processed.  Once processed
 * shared objects are maintained on the ofl_sos list.  The information
 * recorded in this structure includes:
 *
 *  o	DT_USED requirements.  In these cases definitions are added during
 *	mapfile processing of `-' entries (see map_dash()).
 *
 *  o	implicit NEEDED entries.  As shared objects are processed from the
 *	command line so any of their dependencies are recorded in these
 *	structures for later processing (see process_dynamic()).
 *
 *  o	version requirements.  Any explicit shared objects that have version
 *	dependencies on other objects have their version requirements recorded.
 *	In these cases definitions are added during mapfile processing of `-'
 *	entries (see map_dash()).  Also, shared objects may have versioning
 *	requirements on their NEEDED entries.  These cases are added during
 *	their version processing (see vers_need_process()).
 *
 *	Note: Both process_dynamic() and vers_need_process() may generate the
 *	initial version definition structure because you can't rely on what
 *	section (.dynamic or .SUNW_version) may be processed first from	any
 *	input file.
 */
Sdf_desc *
sdf_find(const char *name, APlist *alp)
{
	Aliste		idx;
	Sdf_desc	*sdf;

	for (APLIST_TRAVERSE(alp, idx, sdf))
		if (strcmp(name, sdf->sdf_name) == 0)
			return (sdf);

	return (NULL);
}

Sdf_desc *
sdf_add(const char *name, APlist **alpp)
{
	Sdf_desc	*sdf;

	if ((sdf = libld_calloc(1, sizeof (Sdf_desc))) == NULL)
		return ((Sdf_desc *)S_ERROR);

	sdf->sdf_name = name;

	if (aplist_append(alpp, sdf, AL_CNT_OFL_LIBS) == NULL)
		return ((Sdf_desc *)S_ERROR);

	return (sdf);
}

/*
 * Add a string, separated by a colon, to an existing string.  Typically used
 * to maintain filter, rpath and audit names, of which there is normally only
 * one string supplied anyway.
 */
char *
add_string(char *old, char *str)
{
	char	*new;

	if (old) {
		char	*_str;
		size_t	len;

		/*
		 * If an original string exists, make sure this new string
		 * doesn't get duplicated.
		 */
		if ((_str = strstr(old, str)) != NULL) {
			if (((_str == old) ||
			    (*(_str - 1) == *(MSG_ORIG(MSG_STR_COLON)))) &&
			    (_str += strlen(str)) &&
			    ((*_str == '\0') ||
			    (*_str == *(MSG_ORIG(MSG_STR_COLON)))))
				return (old);
		}

		len = strlen(old) + strlen(str) + 2;
		if ((new = libld_calloc(1, len)) == NULL)
			return ((char *)S_ERROR);
		(void) snprintf(new, len, MSG_ORIG(MSG_FMT_COLPATH), old, str);
	} else {
		if ((new = libld_malloc(strlen(str) + 1)) == NULL)
			return ((char *)S_ERROR);
		(void) strcpy(new, str);
	}

	return (new);
}

/*
 * The GNU ld '-wrap=XXX' and '--wrap=XXX' options correspond to our
 * '-z wrap=XXX'. When str2chr() does this conversion, we end up with
 * the return character set to 'z' and optarg set to 'XXX'. This callback
 * changes optarg to include the missing wrap= prefix.
 *
 * exit:
 *	Returns c on success, or '?' on error.
 */
static int
str2chr_wrap_cb(int c)
{
	char    *str;
	size_t  len = MSG_ARG_WRAP_SIZE + strlen(optarg) + 1;

	if ((str = libld_malloc(len)) == NULL)
		return ('?');
	(void) snprintf(str, len, MSG_ORIG(MSG_FMT_STRCAT),
	    MSG_ORIG(MSG_ARG_WRAP), optarg);
	optarg = str;
	return (c);
}

/*
 * Determine whether this string, possibly with an associated option, should
 * be translated to an option character.  If so, update the optind and optarg
 * and optopt as described for short options in getopt(3c).
 *
 * entry:
 *	lml - Link map list for debug messages
 *	ndx - Starting optind for current item
 *	argc, argv - Command line arguments
 *	arg - Option to be examined
 *	c, opt - Option character (c) and corresponding long name (opt)
 *	optsz - 0 if option does not accept a value. If option does
 *		accept a value, strlen(opt), giving the offset to the
 *		value if the option and value are combined in one string.
 *	cbfunc - NULL, or pointer to function to call if a translation is
 *		successful.
 */
static int
str2chr(Lm_list *lml, int ndx, int argc, char **argv, char *arg, int c,
    const char *opt, size_t optsz, int (*cbfunc)(int))
{
	if (optsz == 0) {
		/*
		 * Compare a single option (ie. there's no associated option
		 * argument).
		 */
		if (strcmp(arg, opt) == 0) {
			DBG_CALL(Dbg_args_str2chr(lml, ndx, opt, c));
			optind += 1;
			optopt = c;
			return (c);
		}
	} else if ((strcmp(arg, opt) == 0) ||
	    ((arg[optsz] == '=') && strncmp(arg, opt, optsz) == 0)) {
		/*
		 * Otherwise, compare the option name, which may be
		 * concatenated with the option argument.
		 */
		DBG_CALL(Dbg_args_str2chr(lml, ndx, opt, c));

		if (arg[optsz] == '\0') {
			/*
			 * Optarg is the next argument (white space separated).
			 * Make sure an optarg is available, and if not return
			 * a failure to prevent any fall-through to the generic
			 * getopt() processing.
			 *
			 * Since we'll be completely failing this option we
			 * don't want to update optopt with the translation,
			 * but also need to set it to _something_.  Setting it
			 * to the '-' of the argument causes us to behave
			 * correctly.
			 */
			if ((++optind + 1) > argc) {
				optopt = arg[0];
				return ('?');
			}
			optarg = argv[optind];
			optind++;
		} else {
			/*
			 * GNU option/option argument pairs can be represented
			 * with a "=" separator.  If this is the case, remove
			 * the separator.
			 */
			optarg = &arg[optsz];
			optind++;
			if (*optarg == '=') {
				if (*(++optarg) == '\0') {
					optopt = arg[0];
					return ('?');
				}
			}
		}

		if (cbfunc != NULL)
			c = (*cbfunc)(c);
		optopt = c;
		return (c);
	}
	return (0);
}

/*
 * Parse an individual option.  The intent of this function is to determine if
 * any known, non-Solaris options have been passed to ld(1).  This condition
 * can occur as a result of build configuration tools, because of users
 * familiarity with other systems, or simply the users preferences.  If a known
 * non-Solaris option can be determined, translate that option into the Solaris
 * counterpart.
 *
 * This function will probably never be a complete solution, as new, non-Solaris
 * options are discovered, their translation will have to be added.  Other
 * non-Solaris options are incompatible with the Solaris link-editor, and will
 * never be recognized.  We support what we can.
 */
int
ld_getopt(Lm_list *lml, int ndx, int argc, char **argv)
{
	int	c;

	if ((optind < argc) && argv[optind] && (argv[optind][0] == '-')) {
		char	*arg = &argv[optind][1];

		switch (*arg) {
		case 'r':
			/* Translate -rpath <optarg> to -R <optarg> */
			if ((c = str2chr(lml, ndx, argc, argv, arg, 'R',
			    MSG_ORIG(MSG_ARG_T_RPATH),
			    MSG_ARG_T_RPATH_SIZE, NULL)) != 0) {
				return (c);
			}
			break;
		case 's':
			/* Translate -shared to -G */
			if ((c = str2chr(lml, ndx, argc, argv, arg, 'G',
			    MSG_ORIG(MSG_ARG_T_SHARED), 0, NULL)) != 0) {
				return (c);

			/* Translate -soname <optarg> to -h <optarg> */
			} else if ((c = str2chr(lml, ndx, argc, argv, arg, 'h',
			    MSG_ORIG(MSG_ARG_T_SONAME),
			    MSG_ARG_T_SONAME_SIZE, NULL)) != 0) {
				return (c);
			}
			break;
		case 'w':
			/* Translate -wrap to -z wrap= */
			if ((c = str2chr(lml, ndx, argc, argv, arg, 'z',
			    MSG_ORIG(MSG_ARG_T_WRAP) + 1,
			    MSG_ARG_T_WRAP_SIZE - 1, str2chr_wrap_cb)) != 0) {
				return (c);
			}
			break;
		case '(':
			/*
			 * Translate -( to -z rescan-start
			 */
			if ((c = str2chr(lml, ndx, argc, argv,
			    arg, 'z', MSG_ORIG(MSG_ARG_T_OPAR), 0, NULL)) !=
			    0) {
				optarg = (char *)MSG_ORIG(MSG_ARG_RESCAN_START);
				return (c);
			}
			break;
		case ')':
			/*
			 * Translate -) to -z rescan-end
			 */
			if ((c = str2chr(lml, ndx, argc, argv,
			    arg, 'z', MSG_ORIG(MSG_ARG_T_CPAR), 0, NULL)) !=
			    0) {
				optarg = (char *)MSG_ORIG(MSG_ARG_RESCAN_END);
				return (c);
			}
			break;
		case '-':
			switch (*(arg + 1)) {
			case 'a':
				/*
				 * Translate --allow-multiple-definition to
				 * -zmuldefs
				 */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'z',
				    MSG_ORIG(MSG_ARG_T_MULDEFS), 0, NULL)) !=
				    0) {
					optarg =
					    (char *)MSG_ORIG(MSG_ARG_MULDEFS);
					return (c);

				/*
				 * Translate --auxiliary <optarg> to
				 * -f <optarg>
				 */
				} else if ((c = str2chr(lml, argc, ndx, argv,
				    arg, 'f', MSG_ORIG(MSG_ARG_T_AUXFLTR),
				    MSG_ARG_T_AUXFLTR_SIZE, NULL)) != 0) {
					return (c);
				}
				break;
			case 'd':
				/*
				 * Translate --dynamic-linker <optarg> to
				 * -I <optarg>
				 */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'I',
				    MSG_ORIG(MSG_ARG_T_INTERP),
				    MSG_ARG_T_INTERP_SIZE, NULL)) != 0) {
					return (c);
				}
				break;
			case 'e':
				/* Translate --entry <optarg> to -e <optarg> */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'e',
				    MSG_ORIG(MSG_ARG_T_ENTRY),
				    MSG_ARG_T_ENTRY_SIZE, NULL)) != 0) {
					return (c);
				}
				/*
				 * Translate --end-group to -z rescan-end
				 */
				if ((c = str2chr(lml, ndx, argc, argv,
				    arg, 'z', MSG_ORIG(MSG_ARG_T_ENDGROUP),
				    0, NULL)) != 0) {
					optarg = (char *)
					    MSG_ORIG(MSG_ARG_RESCAN_END);
					return (c);
				}
				break;
			case 'f':
				/*
				 * Translate --fatal-warnings to
				 * -z fatal-warnings.
				 */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'z',
				    MSG_ORIG(MSG_ARG_T_FATWARN),
				    0, NULL)) != 0) {
					optarg = (char *)
					    MSG_ORIG(MSG_ARG_FATWARN);
					return (c);
				}
				/* Translate --filter <optarg> to -F <optarg> */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'F',
				    MSG_ORIG(MSG_ARG_T_STDFLTR),
				    MSG_ARG_T_STDFLTR_SIZE, NULL)) != 0) {
					return (c);
				}
				break;
			case 'h':
				/* Translate --help to -zhelp */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'z',
				    MSG_ORIG(MSG_ARG_T_HELP), 0, NULL)) !=
				    0) {
					optarg = (char *)MSG_ORIG(MSG_ARG_HELP);
					return (c);
				}
				break;
			case 'l':
				/*
				 * Translate --library <optarg> to -l <optarg>
				 */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'l',
				    MSG_ORIG(MSG_ARG_T_LIBRARY),
				    MSG_ARG_T_LIBRARY_SIZE, NULL)) != 0) {
					return (c);

				/*
				 * Translate --library-path <optarg> to
				 * -L <optarg>
				 */
				} else if ((c = str2chr(lml, ndx, argc, argv,
				    arg, 'L', MSG_ORIG(MSG_ARG_T_LIBPATH),
				    MSG_ARG_T_LIBPATH_SIZE, NULL)) != 0) {
					return (c);
				}
				break;
			case 'n':
				/*
				 * Translate --no-fatal-warnings to
				 * -z nofatal-warnings.
				 */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'z',
				    MSG_ORIG(MSG_ARG_T_NOFATWARN),
				    0, NULL)) != 0) {
					optarg = (char *)
					    MSG_ORIG(MSG_ARG_NOFATWARN);
					return (c);
				}

				/* Translate --no-undefined to -zdefs */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'z',
				    MSG_ORIG(MSG_ARG_T_NOUNDEF), 0, NULL)) !=
				    0) {
					optarg = (char *)MSG_ORIG(MSG_ARG_DEFS);
					return (c);

				/*
				 * Translate --no-whole-archive to
				 * -z defaultextract
				 */
				} else if ((c = str2chr(lml, ndx, argc, argv,
				    arg, 'z', MSG_ORIG(MSG_ARG_T_NOWHOLEARC),
				    0, NULL)) != 0) {
					optarg =
					    (char *)MSG_ORIG(MSG_ARG_DFLEXTRT);
					return (c);
				}
				break;
			case 'o':
				/* Translate --output <optarg> to -o <optarg> */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'o',
				    MSG_ORIG(MSG_ARG_T_OUTPUT),
				    MSG_ARG_T_OUTPUT_SIZE, NULL)) != 0) {
					return (c);
				}
				break;
			case 'r':
				/* Translate --relocatable to -r */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'r',
				    MSG_ORIG(MSG_ARG_T_RELOCATABLE), 0,
				    NULL)) != 0) {
					return (c);
				}
				break;
			case 's':
				/* Translate --strip-all to -s */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 's',
				    MSG_ORIG(MSG_ARG_T_STRIP), 0, NULL)) !=
				    0) {
					return (c);
				}
				/*
				 * Translate --start-group to -z rescan-start
				 */
				if ((c = str2chr(lml, ndx, argc, argv,
				    arg, 'z', MSG_ORIG(MSG_ARG_T_STARTGROUP),
				    0, NULL)) != 0) {
					optarg = (char *)
					    MSG_ORIG(MSG_ARG_RESCAN_START);
					return (c);
				}
				break;
			case 'u':
				/*
				 * Translate --undefined <optarg> to
				 * -u <optarg>
				 */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'u',
				    MSG_ORIG(MSG_ARG_T_UNDEF),
				    MSG_ARG_T_UNDEF_SIZE, NULL)) != 0) {
					return (c);
				}
				break;
			case 'v':
				/* Translate --version to -V */
				if ((c = str2chr(lml, ndx, argc, argv, arg, 'V',
				    MSG_ORIG(MSG_ARG_T_VERSION), 0, NULL)) !=
				    0) {
					return (c);
				}
				break;
			case 'w':
				/*
				 * Translate --whole-archive to -z alltextract
				 */
				if ((c = str2chr(lml, ndx, argc, argv,
				    arg, 'z', MSG_ORIG(MSG_ARG_T_WHOLEARC),
				    0, NULL)) != 0) {
					optarg =
					    (char *)MSG_ORIG(MSG_ARG_ALLEXTRT);
					return (c);
				}
				/*
				 * Translate --wrap to -z wrap=
				 */
				if ((c = str2chr(lml, ndx, argc, argv,
				    arg, 'z', MSG_ORIG(MSG_ARG_T_WRAP),
				    MSG_ARG_T_WRAP_SIZE, str2chr_wrap_cb)) !=
				    0) {
					return (c);
				}
				break;
			}
			break;
		}
	}

	if ((c = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != -1) {
		/*
		 * It is possible that a "-Wl," argument has been used to
		 * specify an option.  This isn't advertized ld(1) syntax, but
		 * compiler drivers and configuration tools, have been known to
		 * pass this compiler option to ld(1).  Strip off the "-Wl,"
		 * prefix and pass the option through.
		 */
		if ((c == 'W') && (strncmp(optarg,
		    MSG_ORIG(MSG_ARG_T_WL), MSG_ARG_T_WL_SIZE) == 0)) {
			DBG_CALL(Dbg_args_Wldel(lml, ndx, optarg));
			c = optarg[MSG_ARG_T_WL_SIZE];
			optarg += MSG_ARG_T_WL_SIZE + 1;
		}
	}

	return (c);
}

/*
 * A compare routine for Isd_node AVL trees.
 */
int
isdavl_compare(const void *n1, const void *n2)
{
	uint_t		hash1, hash2;
	const char	*st1, *st2;
	int		rc;

	hash1 = ((Isd_node *)n1)->isd_hash;
	hash2 = ((Isd_node *)n2)->isd_hash;

	if (hash1 > hash2)
		return (1);
	if (hash1 < hash2)
		return (-1);

	st1 = ((Isd_node *)n1)->isd_name;
	st2 = ((Isd_node *)n2)->isd_name;

	rc = strcmp(st1, st2);
	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);
	return (0);
}

/*
 * Messaging support - funnel everything through dgettext().
 */
const char *
_libld_msg(Msg mid)
{
	return (dgettext(MSG_ORIG(MSG_SUNW_OST_SGS), MSG_ORIG(mid)));
}

/*
 * Determine whether a symbol name should be demangled.
 */
const char *
demangle(const char *name)
{
	if (demangle_flag)
		return (Elf_demangle_name(name));
	else
		return (name);
}

/*
 * Compare a series of platform or machine hardware names.
 */
int
cap_names_match(Alist *alp1, Alist *alp2)
{
	Capstr		*capstr1;
	Aliste		idx1;
	Word		nitems, match;

	if ((nitems = alist_nitems(alp1)) != alist_nitems(alp2))
		return (1);

	match = 0;
	for (ALIST_TRAVERSE(alp1, idx1, capstr1)) {
		Capstr		*capstr2;
		Aliste		idx2;

		for (ALIST_TRAVERSE(alp2, idx2, capstr2)) {
			if (strcmp(capstr1->cs_str, capstr2->cs_str))
				continue;

			match++;
			break;
		}
	}

	if (nitems == match)
		return (0);

	return (1);
}
