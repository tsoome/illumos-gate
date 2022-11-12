#include <sys/cdefs.h>
#include <limits.h>
__FBSDID("$FreeBSD$");

#define _type		long double
#define	roundit		roundl
#define dtype		long long
#define	DTYPE_MIN	LLONG_MIN
#define	DTYPE_MAX	LLONG_MAX
#define	fn		llroundl

#include "s_lround.c"
