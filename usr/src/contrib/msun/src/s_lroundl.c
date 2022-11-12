#include <sys/cdefs.h>
#include <limits.h>
__FBSDID("$FreeBSD$");

#define _type		long double
#define	roundit		roundl
#define dtype		long
#define	DTYPE_MIN	LONG_MIN
#define	DTYPE_MAX	LONG_MAX
#define	fn		lroundl

#include "s_lround.c"
