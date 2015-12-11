#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>    // mprotect

#include "hotpatcher.h"

#define PATH_MAX 256

void hdebug(const char *msg)
{
    fprintf(stdout, "%s\n", msg);
}

const char *my_exe_path(void)
{
	static __thread char path[PATH_MAX];
	ssize_t ret;

	if (path[0] == '\0') {
		ret = readlink("/proc/self/exe", path, sizeof(path));
		if (ret == -1)
			return NULL;
	}

	return path;
}

int make_text_writable(unsigned long ip)
{
	unsigned long start = ip & ~(getpagesize() - 1);

	return mprotect((void *)start, getpagesize() + INSN_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);
}
