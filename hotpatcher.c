#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <bfd.h>

#include "utils.h"
#include "hotpatcher.h"

/* assume that mcount call exists in the first FIND_MCOUNT_RANGE bytes */
#define FIND_MCOUNT_RANGE 32
#define OPCODE_CALL       0xe8
#define OPCODE_LEAVE      0xc9

union instruction {
	unsigned char start[INSN_SIZE];
	struct {
		char opcode;
		int offset;
	} __attribute__((packed));
};

struct caller {
	unsigned long addr;
	unsigned long mcount;
	const char *name;
	const char *section;
};

static struct caller *callers;
static size_t nr_callers;

unsigned long hpatch_function_addr;   // new function address

extern void mcount(void);             // gcc defined
extern unsigned long find_dl_func(const char *lib, const char *func);
extern const char *my_exe_path(void);
extern int make_text_writable(unsigned long ip);
extern void hpatch_caller(void);

int hello(int user)
{
	printf("hello %d\n", user);
	return 666;
}

static int caller_cmp(const struct caller *a, const struct caller *b)
{
	return strcmp(a->name, b->name);
}

static unsigned char *get_new_call(unsigned long ip, unsigned long addr)
{
	static union instruction code;

	code.opcode = OPCODE_CALL;
	code.offset = (int)(addr - ip - INSN_SIZE);

	return code.start;
}

static void replace_call(unsigned long ip, unsigned long func)
{
	unsigned char *new;

	new = get_new_call(ip, func);
	memcpy((void *)ip, new, INSN_SIZE);
}

static unsigned long find_mcount_call(unsigned long entry_addr)
{
	unsigned long start = entry_addr;
	unsigned long end = entry_addr + FIND_MCOUNT_RANGE;

	while (start < end) {
		union instruction *code;
		unsigned long addr;

		code = memchr((void *)start, OPCODE_CALL, end - start);
		addr = (unsigned long)code;

		if (code == NULL)
			break;

		if ((int)((unsigned long)mcount - addr - INSN_SIZE) ==
		    code->offset)
			return addr;

		start = addr + 1;
	}

	return 0;
}

unsigned long find_hpatch_function()
{
	unsigned long offset;

	offset = hpatch_function_addr;

	return offset;
}

unsigned long find_leave_addr(unsigned long entry_addr)
{
	unsigned long start = entry_addr;

    union instruction *code;
    unsigned long addr;

    code = rawmemchr((void *)start, OPCODE_LEAVE);
    addr = (unsigned long)code;


    if (code == NULL)
        return entry_addr;

    return addr;
}

static struct caller *lookup_caller(const char *name)
{
	const struct caller key = {
		.name = name,
	};

	return xbsearch(&key, callers, nr_callers, caller_cmp);
}

static bfd *get_bfd(void)
{
	const char *fname = my_exe_path();
	bfd *abfd;

	if (!fname) {
		fprintf(stderr, "get my_exe_path failed\n");
		return NULL;
	}

	abfd = bfd_openr(fname, NULL);
	if (abfd == 0) {
		fprintf(stderr, "cannot open %s\n", fname);
		return NULL;
	}

	if (!bfd_check_format(abfd, bfd_object)) {
		fprintf(stderr, "invalid format\n");
		return NULL;
	}

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
		fprintf(stderr, "no symbols found\n");
		return NULL;
	}

	return abfd;
}

static void init_callers()
{
	int max_symtab_size;
	asymbol **symtab;
	int symcount;
	bfd *abfd;

	abfd = get_bfd();
	if (!abfd) {
		fprintf(stderr, "get_bfd failed\n");
		return;
	}

	max_symtab_size = bfd_get_symtab_upper_bound(abfd);
	if (max_symtab_size < 0) {
		fprintf(stderr, "failed to get symtab size\n");
		return;
	}

	symtab = malloc(max_symtab_size);
	symcount = bfd_canonicalize_symtab(abfd, symtab);

	callers = calloc(symcount, sizeof(*callers));
	for (int i = 0; i < symcount; i++) {
		asymbol *sym = symtab[i];
		unsigned long ip, addr = bfd_asymbol_value(sym);
		const char *name = bfd_asymbol_name(sym);
		const char *section = bfd_get_section_name(abfd, bfd_get_section(sym));

		if (addr == 0 || !(sym->flags & BSF_FUNCTION))
			/* sym is not a function */
			continue;

		ip = find_mcount_call(addr);
		if (ip == 0)
			continue;

		if (make_text_writable(ip) < 0) {
			fprintf(stderr, "can't make %lu writable\n", ip);
			exit(1);
		}

		callers[nr_callers].addr = addr;
		callers[nr_callers].mcount = ip;
		callers[nr_callers].name = strdup(name);
		callers[nr_callers].section = strdup(section);
		nr_callers++;
	}

	xqsort(callers, nr_callers, caller_cmp);

	free(symtab);
	bfd_close(abfd);
}

void do_hpatch(const char *funcname, const char *libname)
{
	struct caller *target;

	target = lookup_caller(funcname);
	if (target == NULL) {
		fprintf(stderr, "no such function found to do hotpatch\n");
		return;
	}

	hpatch_function_addr = find_dl_func(libname, funcname);

	replace_call(target->mcount, (unsigned long)hpatch_caller);
}

static void usage()
{
	const char *usage = "Usage: hotpatcher <function_name> <lib_file>";

	printf("%s\n", usage);
	exit(1);
}

int main(int argc, char *argv[])
{
	int ret;
	char *funcname;
	char *libname;

	init_callers();

	if (argc != 3)
		usage();

	funcname = argv[1];
	libname = argv[2];

	printf("== before patch ==\n");
	hello(901);

	do_hpatch(funcname, libname);

	printf("== after patch ==\n");
	hello(901);

	return 0;
}
