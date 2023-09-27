#include "check_debug.h"

void *ioremap();
void iounmap(void *);

int *a, *b, *c;
int func(void)
{
	a = ioremap();
	b = ioremap();
	c = a;
	iounmap(c);
	return -1;
}
/*
 * check-name: smatch equivalent variables #4
 * check-command: smatch -p=kernel --spammy -I.. sm_equiv4.c
 *
 * check-output-start
sm_equiv4.c:13 func() warn: 'b' from ioremap() not released on lines: 13.
 * check-output-end
 */
