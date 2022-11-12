#include <sys/cdefs.h>
#include <limits.h>
__FBSDID("$FreeBSD$");

#define _type		float
#define	roundit		roundf
#define dtype		long long
#define	DTYPE_MIN	LLONG_MIN
#define	DTYPE_MAX	LLONG_MAX
#define	fn		llroundf

#include "s_lround.c"
