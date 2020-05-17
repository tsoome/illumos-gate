/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * return in path the full path name of the probe(1)
 * information for lang and tool using proc
 * if attr != 0 then path attribute assignments placed here
 *
 * if path==0 then the space is malloc'd
 *
 * op:
 *
 *	-3	return non-writable path name with no generation
 *	-2	return path name with no generation
 *	-1	return no $HOME path name with no generation
 *	0	verbose probe
 *	1	silent probe
 *
 * 0 returned if the info does not exist and cannot be generated
 */

#include <ast.h>
#include <error.h>
#include <ls.h>
#include <proc.h>

#ifndef PROBE
#define PROBE		"probe"
#endif

#if defined(ST_RDONLY) || defined(ST_NOSUID)

/*
 * return non-0 if path is in a readonly or non-setuid fs
 */

static int
rofs(const char* path)
{
	struct statvfs	vfs;
	struct stat	st;

	if (!statvfs(path, &vfs))
	{
#if defined(ST_RDONLY)
		if (vfs.f_flag & ST_RDONLY)
			return 1;
#endif
#if defined(ST_NOSUID)
		if ((vfs.f_flag & ST_NOSUID) && (stat(path, &st) || st.st_uid != getuid() && st.st_uid != geteuid()))
			return 1;
#endif
	}
	return 0;
}

#else

#define rofs(p)		0

#endif

char*
pathprobe(char* path, char* attr, const char* lang, const char* tool, const char* aproc, int op)
{
	char*		proc = (char*)aproc;
	char*		p;
	char*		k;
	char*		x;
	char**		ap;
	int		n;
	int		v;
	int		force;
	ssize_t		r;
	char*		e;
	char*		np;
	char*		nx;
	char*		probe;
	const char*	dirs;
	const char*	dir;
	Proc_t*		pp;
	Sfio_t*		sp;
	char		buf[PATH_MAX];
	char		cmd[PATH_MAX];
	char		exe[PATH_MAX];
	char		lib[PATH_MAX];
	char		ver[PATH_MAX];
	char		key[16];
	char*		arg[8];
	long		ops[2];
	unsigned long	ptime;
	struct stat	st;
	struct stat	ps;
	char*		lpath;

	if (*proc != '/')
	{
		if (p = strchr(proc, ' '))
		{
			strncopy(buf, proc, p - proc + 1);
			proc = buf;
		}
		if (!(proc = pathpath(cmd, proc, NiL, PATH_ABSOLUTE|PATH_REGULAR|PATH_EXECUTE)))
			proc = (char*)aproc;
		else if (p)
		{
			n = strlen(proc);
			strncopy(proc + n, p, PATH_MAX - n - 1);
		}
	}
	if (!path)
		lpath = buf;
	else
		lpath = path;

	probe = PROBE;
	x = lib + sizeof(lib) - 1;
	k = lib + sfsprintf(lib, x - lib, "lib/%s/", probe);
	p = k + sfsprintf(k, x - k, "%s/%s/", lang, tool);
	pathkey(key, attr, lang, tool, proc);
	if (op >= -2)
	{
		strncopy(p, key, x - p);
		if (pathpath(lpath, lib, "", PATH_ABSOLUTE) && !stat(lpath, &st) && (st.st_mode & S_IWUSR))
			return lpath == buf ? strdup(buf) : path;
	}
	e = strncopy(p, probe, x - p);
	if (!pathpath(lpath, lib, "", PATH_ABSOLUTE|PATH_EXECUTE) || stat(lpath, &ps))
		return 0;
	for (;;)
	{
		ptime = ps.st_mtime;
		n = strlen(lpath);
		if (n < (PATH_MAX - 5))
		{
			strcpy(lpath + n, ".ini");
			if (!stat(lpath, &st) && st.st_size && ptime < (unsigned long)st.st_mtime)
				ptime = st.st_mtime;
			lpath[n] = 0;
		}
		np = lpath + n - (e - k);
		nx = lpath + PATH_MAX - 1;
		strncopy(np, probe, nx - np);
		if (!stat(lpath, &st))
			break;

		/*
		 * yes lib/probe/<lang>/<proc>/probe
		 *  no lib/probe/probe
		 *
		 * do a manual pathaccess() to find a dir with both
		 */

		sfsprintf(exe, sizeof(exe), "lib/%s/%s", probe, probe);
		dirs = pathbin();
		for (;;)
		{
			if (!(dir = dirs))
				return 0;
			dirs = pathcat(lpath, dir, ':', "..", exe);
			pathcanon(lpath, 0);
			if (*lpath == '/' && pathexists(lpath, PATH_REGULAR|PATH_EXECUTE))
			{
				pathcat(lpath, dir, ':', "..", lib);
				pathcanon(lpath, 0);
				if (*lpath == '/' && pathexists(lpath, PATH_REGULAR|PATH_EXECUTE) && !stat(lpath, &ps))
					break;
			}
		}
	}
	strncopy(p, key, x - p);
	p = np;
	x = nx;
	strcpy(exe, lpath);
	if (op >= -1 && (!(st.st_mode & S_ISUID) && ps.st_uid != geteuid() || rofs(lpath)))
	{
		if (!(p = getenv("HOME")))
			return 0;
		p = lpath + sfsprintf(lpath, PATH_MAX - 1, "%s/.%s/%s/", p, probe, HOSTTYPE);
	}
	strncopy(p, k, x - p);
	force = 0;
	if (op >= 0 && !stat(lpath, &st))
	{
		if (ptime <= (unsigned long)st.st_mtime || ptime <= (unsigned long)st.st_ctime)
		{
			/*
			 * verify (<sep><name><sep><option><sep><value>)* header
			 */

			if (sp = sfopen(NiL, lpath, "r"))
			{
				if (x = sfgetr(sp, '\n', 1))
				{
					while (*x && *x != ' ')
						x++;
					while (*x == ' ')
						x++;
					if (n = *x++)
						for (;;)
						{
							for (k = x; *x && *x != n; x++);
							if (!*x)
								break;
							*x++ = 0;
							for (p = x; *x && *x != n; x++);
							if (!*x)
								break;
							*x++ = 0;
							for (e = x; *x && *x != n; x++);
							if (!*x)
								break;
							*x++ = 0;
							if (streq(k, "VERSION"))
							{
								ap = arg;
								*ap++ = proc;
								*ap++ = p;
								*ap = 0;
								ops[0] =  PROC_FD_DUP(1, 2, 0);
								ops[1] = 0;
								if (pp = procopen(proc, arg, NiL, ops, PROC_READ))
								{
									if ((v = x - e) >= sizeof(ver))
										v = sizeof(ver) - 1;
									for (k = p = ver;; k++)
									{
										if (k >= p)
										{
											if (v <= 0 || (r = read(pp->rfd, k, v)) <= 0)
												break;
											v -= r;
											p = k + r;
										}
										if (*k == '\n' || *k == '\r')
											break;
										if (*k == n)
											*k = ' ';
									}
									*k = 0;
									if (strcmp(ver, e))
									{
										force = 1;
										error(0, "probe processor %s version \"%s\" changed -- expected \"%s\"", proc, ver, e);
									}
									procclose(pp);
								}
								break;
							}
						}
				}
				sfclose(sp);
			}
			if (!force)
				op = -1;
		}
		if (op >= 0 && (st.st_mode & S_IWUSR))
		{
			if (op == 0)
				error(0, "%s probe information for %s language processor %s must be manually regenerated", tool, lang, proc);
			op = -1;
			force = 0;
		}
	}
	if (op >= 0)
	{
		ap = arg;
		*ap++ = exe;
		if (force)
			*ap++ = "-f";
		if (op > 0)
			*ap++ = "-s";
		*ap++ = (char*)lang;
		*ap++ = (char*)tool;
		*ap++ = proc;
		*ap = 0;
		if (procrun(exe, arg, 0))
			return 0;
		if (eaccess(lpath, R_OK))
			return 0;
	}
	return lpath == buf ? strdup(buf) : path;
}
