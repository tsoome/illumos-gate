/*
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (C) 2004-2008  Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2001-2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: port_after.h.in,v 1.60 2008/02/28 05:34:17 marka Exp $ */

#ifndef port_after_h
#define port_after_h

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#if (!defined(BSD)) || (BSD < 199306)
#include <sys/bitypes.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */

#ifdef REENABLE_SEND
#undef send
#endif

#undef NEED_PSELECT
#undef HAVE_SA_LEN
#undef HAVE_MINIMUM_IFREQ
#undef NEED_STRSEP
#undef NEED_STRERROR
#ifdef NEED_STRERROR
const char *isc_strerror(int);
#define strerror isc_strerror
#endif
/* HAS_INET6_STRUCTS and HAVE_SIN6_SCOPE_ID are defined by port_ipv6.h
 * #define HAS_INET6_STRUCTS 1
 * #define HAVE_SIN6_SCOPE_ID 1
 */
#include <port_ipv6.h>

#undef NEED_IN6ADDR_ANY
#undef HAS_IN_ADDR6
#define HAVE_SOCKADDR_STORAGE 1
#undef NEED_GETTIMEOFDAY
#define HAVE_STRNDUP
#undef USE_FIONBIO_IOCTL
#undef INNETGR_ARGS

#undef USE_IFNAMELINKID
#define PORT_NONBLOCK O_NONBLOCK

#ifndef _POSIX_PATH_MAX
#define _POSIX_PATH_MAX 255
#endif
#ifndef PATH_MAX
#define PATH_MAX _POSIX_PATH_MAX
#endif

/*
 * We need to know the IPv6 address family number even on IPv4-only systems.
 * Note that this is NOT a protocol constant, and that if the system has its
 * own AF_INET6, different from ours below, all of BIND's libraries and
 * executables will need to be recompiled after the system <sys/socket.h>
 * has had this type added.  The type number below is correct on most BSD-
 * derived systems for which AF_INET6 is defined.
 */
#ifndef AF_INET6
#define AF_INET6        24
#endif

#ifndef PF_INET6
#define PF_INET6        AF_INET6
#endif

#ifdef HAS_IN_ADDR6
/* Map to pre-RFC structure. */
#define in6_addr in_addr6
#endif

#ifndef HAS_INET6_STRUCTS
/* Replace with structure from later rev of O/S if known. */
struct in6_addr {
	u_int8_t        s6_addr[16];
};

#define IN6ADDR_ANY_INIT \
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}

#define IN6ADDR_LOOPBACK_INIT \
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}

/* Replace with structure from later rev of O/S if known. */
struct sockaddr_in6 {
#ifdef  HAVE_SA_LEN
	u_int8_t        sin6_len;       /* length of this struct */
	u_int8_t        sin6_family;    /* AF_INET6 */
#else
	u_int16_t       sin6_family;    /* AF_INET6 */
#endif
	u_int16_t       sin6_port;      /* transport layer port # */
	u_int32_t       sin6_flowinfo;  /* IPv6 flow information */
	struct in6_addr sin6_addr;      /* IPv6 address */
	u_int32_t       sin6_scope_id;  /* set of interfaces for a scope */
};
#endif  /* HAS_INET6_STRUCTS */

#ifdef BROKEN_IN6ADDR_INIT_MACROS
#undef IN6ADDR_ANY_INIT
#undef IN6ADDR_LOOPBACK_INIT
#endif

#ifdef _AIX
#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT {{{ 0, 0, 0, 0 }}}
#endif
#ifndef IN6ADDR_LOOPBACK_INIT
#if BYTE_ORDER == BIG_ENDIAN
#define IN6ADDR_LOOPBACK_INIT {{{ 0, 0, 0, 1 }}}
#else
#define IN6ADDR_LOOPBACK_INIT {{{0, 0, 0, 0x01000000}}}
#endif
#endif
#endif

#ifndef IN6ADDR_ANY_INIT
#ifdef s6_addr
#define IN6ADDR_ANY_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#else
#define IN6ADDR_ANY_INIT \
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}
#endif

#endif
#ifndef IN6ADDR_LOOPBACK_INIT
#ifdef s6_addr
#define IN6ADDR_LOOPBACK_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#else
#define IN6ADDR_LOOPBACK_INIT \
	{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}
#endif
#endif

#ifndef HAVE_SOCKADDR_STORAGE
#define __SS_MAXSIZE 128
#define __SS_ALLIGSIZE (sizeof (long))

struct sockaddr_storage {
#ifdef  HAVE_SA_LEN
	u_int8_t        ss_len;       /* address length */
	u_int8_t        ss_family;    /* address family */
	char            __ss_pad1[__SS_ALLIGSIZE - 2 * sizeof(u_int8_t)];
	long            __ss_align;
	char            __ss_pad2[__SS_MAXSIZE - 2 * __SS_ALLIGSIZE];
#else
	u_int16_t       ss_family;    /* address family */
	char            __ss_pad1[__SS_ALLIGSIZE - sizeof(u_int16_t)];
	long            __ss_align;
	char            __ss_pad2[__SS_MAXSIZE - 2 * __SS_ALLIGSIZE];
#endif
};
#endif


#if !defined(HAS_INET6_STRUCTS) || defined(NEED_IN6ADDR_ANY)
#define in6addr_any isc_in6addr_any
extern const struct in6_addr in6addr_any;
#endif

/*
 * IN6_ARE_ADDR_EQUAL, IN6_IS_ADDR_UNSPECIFIED, IN6_IS_ADDR_V4COMPAT and
 * IN6_IS_ADDR_V4MAPPED are broken in glibc 2.1.
 */
#ifdef __GLIBC__
#if __GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 2)
#undef IN6_ARE_ADDR_EQUAL
#undef IN6_IS_ADDR_UNSPECIFIED
#undef IN6_IS_ADDR_V4COMPAT
#undef IN6_IS_ADDR_V4MAPPED
#endif
#endif

#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) \
   (memcmp(&(a)->s6_addr[0], &(b)->s6_addr[0], sizeof(struct in6_addr)) == 0)
#endif

#ifndef IN6_IS_ADDR_UNSPECIFIED
#define IN6_IS_ADDR_UNSPECIFIED(a)      \
	IN6_ARE_ADDR_EQUAL(a, &in6addr_any)
#endif

#ifndef IN6_IS_ADDR_LOOPBACK
extern const struct in6_addr isc_in6addr_loopback;
#define IN6_IS_ADDR_LOOPBACK(a) \
	IN6_ARE_ADDR_EQUAL(a, &isc_in6addr_loopback)
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a)	\
	((a)->s6_addr[0] == 0x00 && (a)->s6_addr[1] == 0x00 && \
	(a)->s6_addr[2] == 0x00 && (a)->s6_addr[3] == 0x00 && \
	(a)->s6_addr[4] == 0x00 && (a)->s6_addr[5] == 0x00 && \
	(a)->s6_addr[6] == 0x00 && (a)->s6_addr[9] == 0x00 && \
	(a)->s6_addr[8] == 0x00 && (a)->s6_addr[9] == 0x00 && \
	(a)->s6_addr[10] == 0xff && (a)->s6_addr[11] == 0xff)
#endif

#ifndef IN6_IS_ADDR_SITELOCAL
#define IN6_IS_ADDR_SITELOCAL(a)        \
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))
#endif

#ifndef IN6_IS_ADDR_LINKLOCAL
#define IN6_IS_ADDR_LINKLOCAL(a)        \
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#endif

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a)        ((a)->s6_addr[0] == 0xff)
#endif

#ifndef __IPV6_ADDR_MC_SCOPE
#define __IPV6_ADDR_MC_SCOPE(a)         ((a)->s6_addr[1] & 0x0f)
#endif

#ifndef __IPV6_ADDR_SCOPE_SITELOCAL
#define __IPV6_ADDR_SCOPE_SITELOCAL 0x05
#endif
#ifndef __IPV6_ADDR_SCOPE_ORGLOCAL
#define __IPV6_ADDR_SCOPE_ORGLOCAL  0x08
#endif

#ifndef IN6_IS_ADDR_MC_SITELOCAL
#define IN6_IS_ADDR_MC_SITELOCAL(a)     \
	(IN6_IS_ADDR_MULTICAST(a) &&    \
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_SITELOCAL))
#endif

#ifndef IN6_IS_ADDR_MC_ORGLOCAL
#define IN6_IS_ADDR_MC_ORGLOCAL(a)      \
	(IN6_IS_ADDR_MULTICAST(a) &&    \
	 (__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_ORGLOCAL))
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

#ifndef INET6_ADDRSTRLEN
/* sizeof("aaaa:bbbb:cccc:dddd:eeee:ffff:123.123.123.123") */
#define INET6_ADDRSTRLEN 46
#endif

#ifndef MIN
#define MIN(x,y) (((x) <= (y)) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x,y) (((x) >= (y)) ? (x) : (y))
#endif

#ifdef NEED_STRSEP
char * strsep(char **stringp, const char *delim);
#endif

#ifndef ALIGN
#define ALIGN(p) (((uintptr_t)(p) + (sizeof(long) - 1)) & ~(sizeof(long) - 1))
#endif

#ifdef NEED_SETGROUPENT
int setgroupent(int stayopen);
#endif

#ifdef NEED_GETGROUPLIST
int getgrouplist(GETGROUPLIST_ARGS);
#endif

#ifdef POSIX_GETGRNAM_R
int
__posix_getgrnam_r(const char *, struct group *, char *, int, struct group **);
#endif

#ifdef NEED_GETGRNAM_R
int
getgrnam_r(const char *,  struct group *, char *, size_t, struct group **);
#endif

#ifdef POSIX_GETGRGID_R
int
__posix_getgrgid_r(gid_t, struct group *, char *, int, struct group **) ;
#endif

#ifdef NEED_GETGRGID_R
int
getgrgid_r(gid_t, struct group *, char *, size_t, struct group **);
#endif

#ifdef NEED_GETGRENT_R
GROUP_R_RETURN getgrent_r(struct group *gptr, GROUP_R_ARGS);
#endif

#ifdef NEED_SETGRENT_R
GROUP_R_SET_RETURN setgrent_r(GROUP_R_ENT_ARGS);
#endif

#ifdef NEED_ENDGRENT_R
GROUP_R_END_RETURN endgrent_r(GROUP_R_ENT_ARGS);
#endif

#if defined(NEED_INNETGR_R) && defined(NGR_R_RETURN)
NGR_R_RETURN
innetgr_r(const char *, const char *, const char *, const char *);
#endif

#ifdef NEED_SETNETGRENT_R
#ifdef NGR_R_SET_ARGS
NGR_R_SET_RETURN setnetgrent_r(NGR_R_SET_CONST char *netgroup, NGR_R_SET_ARGS);
#else
NGR_R_SET_RETURN setnetgrent_r(NGR_R_SET_CONST char *netgroup);
#endif
#endif

#ifdef NEED_ENDNETGRENT_R
#ifdef NGR_R_END_ARGS
NGR_R_END_RETURN endnetgrent_r(NGR_R_END_ARGS);
#else
NGR_R_END_RETURN endnetgrent_r(void);
#endif
#endif

#ifdef POSIX_GETPWNAM_R
int
__posix_getpwnam_r(const char *login,  struct passwd *pwptr,
		char *buf, size_t buflen, struct passwd **result);
#endif

#ifdef NEED_GETPWNAM_R
int
getpwnam_r(const char *login,  struct passwd *pwptr,
		char *buf, size_t buflen, struct passwd **result);
#endif

#ifdef POSIX_GETPWUID_R
int
__posix_getpwuid_r(uid_t uid, struct passwd *pwptr,
		char *buf, int buflen, struct passwd **result);
#endif

#ifdef NEED_GETPWUID_R
int
getpwuid_r(uid_t uid, struct passwd *pwptr,
		char *buf, size_t buflen, struct passwd **result);
#endif

#ifdef NEED_SETPWENT_R
#ifdef PASS_R_ENT_ARGS
PASS_R_SET_RETURN setpwent_r(PASS_R_ENT_ARGS);
#else
PASS_R_SET_RETURN setpwent_r(void);
#endif

#endif

#ifdef NEED_SETPASSENT_R
#ifdef PASS_R_ENT_ARGS
PASS_R_SET_RETURN setpassent_r(int stayopen, PASS_R_ENT_ARGS);
#else
PASS_R_SET_RETURN setpassent_r(int stayopen);
#endif
#endif

#ifdef NEED_GETPWENT_R
PASS_R_RETURN getpwent_r(struct passwd *pwptr, PASS_R_ARGS);
#endif

#ifdef NEED_ENDPWENT_R
void endpwent_r(void);
#endif

#ifdef NEED_SETPASSENT
int setpassent(int stayopen);
#endif

#define gettimeofday isc__gettimeofday
#ifdef NEED_GETTIMEOFDAY
int isc__gettimeofday(struct timeval *tvp, struct _TIMEZONE *tzp);
#else
int isc__gettimeofday(struct timeval *tp, struct timezone *tzp);
#endif

int getnetgrent(NGR_R_CONST char **machinep, NGR_R_CONST char **userp,
		NGR_R_CONST char **domainp);

#ifdef NGR_R_ARGS
int getnetgrent_r(NGR_R_CONST char **machinep, NGR_R_CONST char **userp,
		  NGR_R_CONST char **domainp, NGR_R_ARGS);
#endif

/* setnetgrent and endnetgrent are defined in sunw_port_after.h
#ifdef SETNETGRENT_ARGS
void setnetgrent(SETNETGRENT_ARGS);
#else
void setnetgrent(const char *netgroup);
#endif

void endnetgrent(void);
*/

#ifdef INNETGR_ARGS
int innetgr(INNETGR_ARGS);
#else
int innetgr(const char *netgroup, const char *machine,
	    const char *user, const char *domain);
#endif

#ifdef NGR_R_SET_ARGS
NGR_R_SET_RETURN
setnetgrent_r(NGR_R_SET_CONST char *netgroup, NGR_R_SET_ARGS);
#else
NGR_R_SET_RETURN
setnetgrent_r(NGR_R_SET_CONST char *netgroup);
#endif

#ifdef NEED_STRTOUL
unsigned long strtoul(const char *, char **, int);
#endif

#ifdef NEED_SUN4PROTOS
#include <stdarg.h>
#ifndef __SIZE_TYPE__
#define __SIZE_TYPE__ int
#endif
struct sockaddr;
struct iovec;
struct timeval;
struct timezone;
int fprintf(FILE *, const char *, ...);
int getsockname(int, struct sockaddr *, int *);
int getpeername(int, struct sockaddr *, int *);
int socket(int, int, int);
int connect(int, const struct sockaddr *, int);
int writev(int, struct iovec *, int);
int readv(int, struct iovec *, int);
int send(int, const char *, int, int);
void bzero(char *, int);
int recvfrom(int, char *, int, int, struct sockaddr *, int *);
int syslog(int, const char *, ... );
int printf(const char *, ...);
__SIZE_TYPE__ fread(void *, __SIZE_TYPE__, __SIZE_TYPE__, FILE *);
__SIZE_TYPE__ fwrite(const void *, __SIZE_TYPE__, __SIZE_TYPE__, FILE *);
int fclose(FILE *);
int ungetc(int, FILE *);
int scanf(const char *, ...);
int sscanf(const char *, const char *, ... );
int tolower(int);
int toupper(int);
int strcasecmp(const char *, const char *);
int strncasecmp(const char *, const char *, int);
int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
#ifdef gettimeofday
#undef gettimeofday
int gettimeofday(struct timeval *, struct timezone *);
#define gettimeofday isc__gettimeofday
#else
int gettimeofday(struct timeval *, struct timezone *);
#endif
long strtol(const char*, char **, int);
int fseek(FILE *, long, int);
int setsockopt(int, int, int, const char *, int);
int bind(int, const struct sockaddr *, int);
void bcopy(char *, char *, int);
int fputc(char, FILE *);
int listen(int, int);
int accept(int, struct sockaddr *, int *);
int getsockopt(int, int, int, char *, int *);
int vfprintf(FILE *, const char *, va_list);
int fflush(FILE *);
int fgetc(FILE *);
int fputs(const char *, FILE *);
int fchown(int, int, int);
void setbuf(FILE *, char *);
int gethostname(char *, int);
int rename(const char *, const char *);
time_t time(time_t *);
int fscanf(FILE *, const char *, ...);
int sscanf(const char *, const char *, ...);
int ioctl(int, int, caddr_t);
void perror(const char *);

#if !defined(__USE_FIXED_PROTOTYPES__) && !defined(__cplusplus) && !defined(__STRICT_ANSI__)
/*
 * 'gcc -ansi' changes the prototype for vsprintf().
 * Use this prototype when 'gcc -ansi' is not in effect.
 */
char *vsprintf(char *, const char *, va_list);
#endif
#endif

/* Solaris-specific changes */
#include "sunw_port_after.h"

#endif	/* port_after_h */
