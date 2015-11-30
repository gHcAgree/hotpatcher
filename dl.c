#include <stdio.h>
#include <stdlib.h>

#include <dlfcn.h>

unsigned long find_dl_func(const char *lib, const char *func)
{
	void *dl_handle;
	unsigned long func_addr;
	char *err;

	dl_handle = dlopen(lib, RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);
	if (!dl_handle) {
		fprintf(stderr, "dlopen failed (%m)\n");
		exit(1);
	}

	dlerror();	// clear any existing error

	func_addr = (unsigned long)dlsym(dl_handle, func);
	err = dlerror();
	if (err) {
		fprintf(stderr, "dlsym failed (%s)\n", err);
		exit(2);
	}

	fprintf(stdout, "found function [%s] addr = [%lu]\n", func, func_addr);

	dlclose(dl_handle);

	return func_addr;
}