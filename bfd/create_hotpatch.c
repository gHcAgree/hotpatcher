#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <bfd.h>

#include "list.h"

static asymbol **symtab;
static arelent **relpp;

enum status {
	NEW,
	CHANGED,
	SAME
};

struct hp_symbol;

struct hp_section {
	struct list_node list;
	struct hp_section *twin;
	asection *raw_sec;
	enum status status;
	int include;
	int ignore;
	struct list_head relas;
};

struct hp_symbol {
	struct list_node list;
	struct hp_symbol *twin;
	asymbol *raw_sym;
	enum status status;
	int include;
	int strip;
};

struct hp_rela {
	struct list_node list;
	arelent *raw_rel;
	struct hp_symbol *sym;
};

struct hp_bfd {
	bfd *raw_bfd;
	struct list_head sections;
	struct list_head symbols;
};

int is_reloc_section(struct hp_section *sec)
{
	return (sec->raw_sec->flags & SEC_RELOC) ? 1 : 0; 
}

int is_text_section(struct hp_section *sec)
{
	return (sec->raw_sec->flags & SEC_CODE) ? 1 : 0;
}

int is_debug_section(struct hp_section *sec)
{
	return (sec->raw_sec->flags & SEC_DEBUGGING) ? 1 : 0;
}

int is_group_section(struct hp_section *sec)
{
	return (sec->raw_sec->flags & SEC_GROUP) ? 1 : 0;
}

struct hp_section *find_section_by_name(struct hp_bfd *hbfd, const char *name)
{
	struct hp_section *sec;

	list_for_each_entry(sec, &hbfd->sections, list)
		if (!strcmp(bfd_get_section_name(hbfd->raw_bfd, sec->raw_sec), name))
			return sec;

	return NULL;
}

struct hp_symbol *find_symbol_by_name(struct hp_bfd *hbfd, const char *name)
{
	struct hp_symbol *sym;

	list_for_each_entry(sym, &hbfd->symbols, list)
		if (!strcmp(bfd_asymbol_name(sym->raw_sym), name))
			return sym;

	return NULL;
}

void build_section_list(struct hp_bfd *hbfd)
{
	struct hp_section *hp_sec;
	asection *asec;

	for (asec = hbfd->raw_bfd->sections; asec != NULL; asec = asec->next) {
		hp_sec = malloc(sizeof(*hp_sec));
		INIT_LIST_NODE(&hp_sec->list);
		hp_sec->twin = NULL;
		hp_sec->raw_sec = asec;
		hp_sec->status = SAME;
		hp_sec->include = 0;
		hp_sec->ignore = 1;
		INIT_LIST_HEAD(&hp_sec->relas);

		list_add_tail(&hp_sec->list, &hbfd->sections);
	}
}

void build_symbol_list(struct hp_bfd *hbfd)
{
	struct hp_symbol *hp_sym;
	long storage, symcount;

	storage = bfd_get_symtab_upper_bound(hbfd->raw_bfd);
	if (storage < 0) {
		fprintf(stderr, "failed to get symtab upper bound\n");
		exit(1);
	}

	if (storage)
		symtab = malloc(storage);

	symcount = bfd_canonicalize_symtab(hbfd->raw_bfd, symtab);
	if (symcount < 0) {
		fprintf(stderr, "no symbols found\n");
		exit(1);
	}

	for (int i = 0; i < symcount; i++) {
		hp_sym = malloc(sizeof(*hp_sym));
		hp_sym->twin = NULL;
		hp_sym->raw_sym = symtab[i];
		hp_sym->status = SAME;
		hp_sym->include = 0;
		hp_sym->strip = 0;

		list_add_tail(&hp_sym->list, &hbfd->symbols);
	}
}

void build_rela_list(struct hp_bfd *hbfd)
{
	struct hp_rela *rela;
	long relcount;
	long relsize;
	struct hp_section *sec;

	list_for_each_entry(sec, &hbfd->sections, list) {
		relsize = bfd_get_reloc_upper_bound(hbfd->raw_bfd, sec->raw_sec);
		if (relsize < 0) {
			fprintf(stderr, "get reloc size failed\n");
			exit(1);
		}

		if (relsize == 0)
			continue;

		relpp = (arelent **)malloc(relsize);
		relcount = bfd_canonicalize_reloc(hbfd->raw_bfd, sec->raw_sec, relpp, symtab);
		if (relcount < 0) {
			fprintf(stderr, "canonicalize reloc failed\n");
			exit(1);
		}

		for (int i = 0; i < relcount; i++) {
			rela = malloc(sizeof(*rela));
			INIT_LIST_NODE(&rela->list);
			rela->raw_rel = relpp[i];

			if (relpp[i]->sym_ptr_ptr && *relpp[i]->sym_ptr_ptr) {
				const char *symname = (*(relpp[i]->sym_ptr_ptr))->name;
				struct hp_symbol *sym = find_symbol_by_name(hbfd, symname);

				if (!sym) {
					fprintf(stderr, "no such symbol found\n");
					exit(1);
				}
				rela->sym = sym;
			}

			list_add_tail(&rela->list, &sec->relas);
		}
	}
}

void check_valid_elf(struct hp_bfd *obfd, struct hp_bfd *pbfd)
{
}

void correlate_sections(struct hp_bfd *obfd, struct hp_bfd *pbfd)
{
	struct hp_section *sec1, *sec2;

	list_for_each_entry(sec1, &obfd->sections, list) {
		list_for_each_entry(sec2, &pbfd->sections, list) {
			if (strcmp(bfd_get_section_name(obfd->raw_bfd, sec1->raw_sec),
					   bfd_get_section_name(pbfd->raw_bfd, sec2->raw_sec)))
				continue;

			sec1->twin = sec2;
			sec2->twin = sec1;
			sec1->status = sec2->status = SAME;
			break;
		}
	}
}

void correlate_symbols(struct hp_bfd *obfd, struct hp_bfd *pbfd)
{
	struct hp_symbol *sym1, *sym2;

	list_for_each_entry(sym1, &obfd->symbols, list) {
		list_for_each_entry(sym2, &pbfd->symbols, list) {
			if (strcmp(bfd_asymbol_name(sym1->raw_sym),
					   bfd_asymbol_name(sym2->raw_sym)))
				continue;

			sym1->twin = sym2;
			sym2->twin = sym1;
			sym1->status = sym2->status = SAME;
			break;
		}
	}
}

void compare_correlated_section(struct hp_section *sec)
{

}

void compare_correlated_symbol(struct hp_symbol *sym)
{

}

void compare_sections(struct hp_bfd *pbfd)
{
	struct hp_section *sec;

	list_for_each_entry(sec, &pbfd->sections, list) {
		if (!sec->twin)
			sec->status = NEW;
		else
			compare_correlated_section(sec);
	}
}

void compare_symbols(struct hp_bfd *pbfd)
{
	struct hp_symbol *sym;

	list_for_each_entry(sym, &pbfd->symbols, list) {
		if (!sym->twin)
			sym->status = NEW;
		else
			compare_correlated_symbol(sym);
	}
}

void correlate_bfds(struct hp_bfd *obfd, struct hp_bfd *pbfd)
{
	correlate_sections(obfd, pbfd);
	correlate_symbols(obfd, pbfd);	
}

void compare_correlate_elements(struct hp_bfd *pbfd)
{
	compare_sections(pbfd);
	compare_symbols(pbfd);
}

void free_bfd(struct hp_bfd *bfd)
{
	bfd_close(bfd->raw_bfd);
	memset(bfd, 0, sizeof(*bfd));
	free(bfd);
}

void drop_bfd(struct hp_bfd *bfd)
{
	struct hp_section *sec;
	struct hp_symbol *sym;

	list_for_each_entry(sec, &bfd->sections, list) {
		memset(sec, 0, sizeof(*sec));
		free(sec);
	}

	list_for_each_entry(sym, &bfd->symbols, list) {
		memset(sym, 0, sizeof(*sym));
		free(sym);
	}

	INIT_LIST_HEAD(&bfd->sections);
	INIT_LIST_HEAD(&bfd->symbols);

	free_bfd(bfd);
}

void include_std_elements(struct hp_bfd *pbfd)
{
	struct hp_section *sec;

	list_for_each_entry(sec, &pbfd->sections, list) {
		char *name = bfd_get_section_name(pbfd->raw_bfd, sec->raw_sec);
		if (!strcmp(name, ".symtab") ||
			!strcmp(name, ".strtab") ||
			!strcmp(name, ".shstrtab"))
			sec->include = 1;
	}
}

void include_symbol(struct hp_symbol *sym)
{
	sym->include = 1;
}

int include_changed_functions(struct hp_bfd *pbfd)
{
	struct hp_symbol *sym;
	int changed = 0;

	list_for_each_entry(sym, &pbfd->symbols, list) {
		if (sym->status == CHANGED) {
			changed++;
			include_symbol(sym);
		}
	}

	return changed;
}

void process_special_sections(struct hp_bfd *pbfd)
{
	
}

void dump_bfd(struct hp_bfd *hbfd)
{
	struct hp_section *sec;
	struct hp_symbol *sym;

	list_for_each_entry(sec, &hbfd->sections, list) {
		char *reloc_hint;
		if (is_reloc_section(sec))
			reloc_hint = "[reloc]";
		else
			reloc_hint = "";

		printf("section: %s %s ", bfd_get_section_name(hbfd->raw_bfd, sec->raw_sec), reloc_hint);
		printf("secsym: %s\n", bfd_asymbol_name(sec->raw_sec->symbol));
	}

	printf("\n");

	list_for_each_entry(sym, &hbfd->symbols, list) {
		printf("symbol: %s\n", bfd_asymbol_name(sym->raw_sym));
	}

	printf("\n");
}

struct hp_bfd *load_bfd(const char *file)
{
	bfd* abfd;

	abfd = bfd_openr(file, NULL);
	if (!abfd) {
		fprintf(stderr, "cannot open %s\n", file);
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

	struct hp_bfd *hbfd = malloc(sizeof(*hbfd));
	hbfd->raw_bfd = abfd;
	INIT_LIST_HEAD(&hbfd->sections);
	INIT_LIST_HEAD(&hbfd->symbols);

	build_section_list(hbfd);
	build_symbol_list(hbfd);
	build_rela_list(hbfd);

	dump_bfd(hbfd);

	return hbfd;
}

void usage(void)
{
	const char *usage = "./create_hotpatch <original_obj> <patched_obj> <running_exec> <out_obj>";

	fprintf(stdout, "%s\n", usage);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct hp_bfd *obfd, *pbfd, *out_bfd;

	if (argc != 5)
		usage();

	bfd_init();

	obfd = load_bfd(argv[1]);
	pbfd = load_bfd(argv[2]);

	check_valid_elf(obfd, pbfd);

	correlate_bfds(obfd, pbfd);

	compare_correlate_elements(pbfd);

	drop_bfd(obfd);

	include_std_elements(pbfd);

	int num_changed = include_changed_functions(pbfd);
	if (!num_changed) {
		fprintf(stderr, "No changed functions\n");
		return 1;
	}

	process_special_sections(pbfd);	
/*
	check_patchability(pbfd);

	migrate_included_elements(pbfd, &out_bfd);

	drop_bfd(pbfd);
*/
	return 0;
}