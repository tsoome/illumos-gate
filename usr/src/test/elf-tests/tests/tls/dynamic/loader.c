#include <dlfcn.h>
#include <err.h>
#include <link.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
	void *lib = NULL;
	void (*entry)(void);

	if (argc != 2)
		errx(2, "Usage: loader <module>");

	if ((lib = dlopen(argv[1], RTLD_LAZY)) == NULL)
		errx(1, "Could not load %s: %s", argv[1], dlerror());

	if ((entry = dlsym(lib, "test")) == NULL)
		errx(1, "No 'test' entry point in %s: %s", argv[1], dlerror());

	entry();

	return (EXIT_SUCCESS);
}
