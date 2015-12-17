#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <bfd.h>
#include <elf.h>

#include "list.h"

enum loglevel {
	DEBUG,
	INFO,
	ERR,
};

#define log_debug(format, ...) log(DEBUG, "DEBUG: "format"\n", ##__VA_ARGS__)
#define log_info(format, ...)  log(INFO, "INFO: "format"\n", ##__VA_ARGS__)
#define err_out(format, ...)                       \
({                                                 \
	log(ERR, "ERROR: "format"\n", ##__VA_ARGS__);  \
	exit(1);                                       \
})

#define log(level, format, ...)        \
({                                     \
	if (loglevel <= (level))           \
		printf(format, ##__VA_ARGS__); \
})

static enum loglevel loglevel = DEBUG;

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
	union {
		struct hp_symbol *secsym;
		struct hp_symbol *bundsym;         // see is_bundleable_symbol()
	};
	asection *raw_sec;
	enum status status;
	int include;
	int ignore;
	struct list_head relas;
};

struct hp_symbol {
	struct list_node list;
	struct hp_symbol *twin;
	struct hp_section *symsec;
	asymbol *raw_sym;
	enum status status;
	union {
		int include;
		int strip;
	};
	int has_fentry;
};

struct hp_rela {
	struct list_node list;
	arelent *raw_rel;
	struct hp_symbol *relsym;
};

struct hp_bfd {
	bfd *raw_bfd;
	struct list_head sections;
	struct list_head symbols;
};

int has_reloc_section(struct hp_section *sec)
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

int is_empty_section(struct hp_section *sec)
{
	return (sec->raw_sec->flags & SEC_HAS_CONTENTS) ? 1 : 0;
}

int is_section_symbol(struct hp_symbol *sym)
{
	return (sym->raw_sym->flags & BSF_SECTION_SYM) ? 1 : 0;
}

int is_function_symbol(struct hp_symbol *sym)
{
	return (sym->raw_sym->flags & BSF_FUNCTION) ? 1 : 0;
}

int is_dataobj_symbol(struct hp_symbol *sym)
{
	return (sym->raw_sym->flags & BSF_OBJECT) ? 1 : 0;
}

int is_file_symbol(struct hp_symbol *sym)
{
	return (sym->raw_sym->flags & BSF_FILE) ? 1 : 0;
}

int is_bundleable_symbol(struct hp_symbol *sym)
{
	const char *secname = bfd_section_name(NULL, sym->symsec->raw_sec);
	const char *symname = bfd_asymbol_name(sym->raw_sym);

	if (is_function_symbol(sym) &&
	    !strncmp(secname, ".text.",6) &&
	    !strcmp(secname + 6, symname))
		return 1;

	if (is_function_symbol(sym) &&
	    !strncmp(secname, ".text.unlikely.",15) &&
	    !strcmp(secname + 15, symname))
		return 1;

	if (is_dataobj_symbol(sym) &&
	   !strncmp(secname, ".data.",6) &&
	   !strcmp(secname + 6, symname))
		return 1;

	if (is_dataobj_symbol(sym) &&
	   !strncmp(secname, ".rodata.",8) &&
	   !strcmp(secname + 8, symname))
		return 1;

	if (is_dataobj_symbol(sym) &&
	   !strncmp(secname, ".bss.",5) &&
	   !strcmp(secname + 5, symname))
		return 1;

	return 0;
}

struct hp_section *find_section_by_name(struct hp_bfd *hbfd, const char *name)
{
	struct hp_section *sec;

	list_for_each_entry(sec, &hbfd->sections, list)
		if (!strcmp(bfd_section_name(hbfd->raw_bfd, sec->raw_sec), name))
			return sec;

	return NULL;
}

struct hp_section *find_section_by_index(struct hp_bfd *hbfd, int index)
{
	struct hp_section *sec;

	list_for_each_entry(sec, &hbfd->sections, list)
		if (sec->raw_sec->index == index)
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

int rela_equal(struct hp_rela *rela1, struct hp_rela *rela2)
{
	if (rela1->raw_rel->howto->type != rela2->raw_rel->howto->type)
		return 0;

	if (rela1->raw_rel->address != rela2->raw_rel->address)
		return 0;

	if (rela1->raw_rel->addend != rela2->raw_rel->addend)
		return 0;

	return !strcmp(bfd_asymbol_name(rela1->relsym->raw_sym),
				   bfd_asymbol_name(rela2->relsym->raw_sym));
}

void dump_rela(struct hp_rela *rel)
{
	log_debug("    rela: offset %lu, addend %d, symbol %s",
						(unsigned long)rel->raw_rel->address,
						(int)rel->raw_rel->addend,
						bfd_asymbol_name(rel->relsym->raw_sym));
}

void dump_section(struct hp_section *sec)
{
	if (has_reloc_section(sec)) {
		struct hp_rela *rel;

		log_debug("section: %s [reloc]", bfd_section_name(hbfd->raw_bfd, sec->raw_sec));

		list_for_each_entry(rel, &sec->relas, list)
			dump_rela(rel);
	} else {
		log_debug("section: %s", bfd_section_name(hbfd->raw_bfd, sec->raw_sec));
	}
}

void dump_symbol(struct hp_symbol *sym)
{
	log_debug("symbol: %s", bfd_asymbol_name(sym->raw_sym));
}

void dump_bfd(struct hp_bfd *hbfd)
{
	struct hp_section *sec;
	struct hp_symbol *sym;

	log_debug("===================== sections =====================");

	list_for_each_entry(sec, &hbfd->sections, list)
		dump_section(sec);

	printf("\n");

	log_debug("===================== symbols =====================");

	list_for_each_entry(sym, &hbfd->symbols, list)
		dump_symbol(sym);

	printf("\n");
}

void dump_changes(struct hp_bfd *hbfd)
{
	struct hp_symbol *sym;

	list_for_each_entry(sym, &hbfd->symbols, list) {
		if (!sym->include || !sym->symsec || !is_function_symbol(sym))
			continue;
		if (sym->status == NEW)
			log_info("new function: %s", bfd_asymbol_name(sym->raw_sym));
		if (sym->status == CHANGED)
			log_info("changed function: %s", bfd_asymbol_name(sym->raw_sym));
	}
}

void build_section_list(struct hp_bfd *hbfd)
{
	struct hp_section *hp_sec;
	asection *asec;

	for (asec = hbfd->raw_bfd->sections; asec != NULL; asec = asec->next) {
		hp_sec = malloc(sizeof(*hp_sec));
		INIT_LIST_NODE(&hp_sec->list);
		hp_sec->twin = NULL;
		hp_sec->secsym = NULL;
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
	struct hp_section *hp_sec;
	long storage, symcount;

	storage = bfd_get_symtab_upper_bound(hbfd->raw_bfd);
	if (storage < 0) {
		err_out("failed to get symtab upper bound");
	}

	if (storage)
		symtab = malloc(storage);

	symcount = bfd_canonicalize_symtab(hbfd->raw_bfd, symtab);
	if (symcount < 0) {
		err_out("no symbols found");
	}

	for (int i = 0; i < symcount; i++) {
		hp_sym = malloc(sizeof(*hp_sym));
		hp_sym->twin = NULL;
		hp_sym->symsec = NULL;
		hp_sym->raw_sym = symtab[i];
		hp_sym->status = SAME;
		hp_sym->include = 0;
		hp_sym->strip = 0;

		int index = hp_sym->raw_sym->section->index;
		if (index > SHN_UNDEF && index < SHN_LORESERVE) {
			hp_sec = find_section_by_index(hbfd, index);
			if (!hp_sec)
				err_out("can't find section for symbol %s",
					bfd_asymbol_name(hp_sym->raw_sym));
			hp_sym->symsec = hp_sec;

			if (is_bundleable_symbol(hp_sym)) {
				hp_sec->bundsym = hp_sym;
			} else if (is_section_symbol(hp_sym)) {
				hp_sec->secsym = hp_sym;
			}
		}

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
		if (!has_reloc_section(sec))
			continue;

		relsize = bfd_get_reloc_upper_bound(hbfd->raw_bfd, sec->raw_sec);
		if (relsize < 0) {
			err_out("get reloc size failed");
		}

		if (relsize == 0)
			continue;

		relpp = (arelent **)malloc(relsize);
		relcount = bfd_canonicalize_reloc(hbfd->raw_bfd, sec->raw_sec, relpp, symtab);
		if (relcount < 0) {
			err_out("canonicalize reloc failed");
		}

		for (int i = 0; i < relcount; i++) {
			rela = malloc(sizeof(*rela));
			INIT_LIST_NODE(&rela->list);
			rela->raw_rel = relpp[i];

			if (relpp[i]->sym_ptr_ptr && *relpp[i]->sym_ptr_ptr) {
				const char *symname = (*(relpp[i]->sym_ptr_ptr))->name;
				struct hp_symbol *sym = find_symbol_by_name(hbfd, symname);

				if (!sym)
					err_out("no such symbol found");
				rela->relsym = sym;
			}

			list_add_tail(&rela->list, &sec->relas);
		}
	}
}

void correlate_sections(struct hp_bfd *obfd, struct hp_bfd *pbfd)
{
	struct hp_section *sec1, *sec2;

	list_for_each_entry(sec1, &obfd->sections, list) {
		list_for_each_entry(sec2, &pbfd->sections, list) {
			if (strcmp(bfd_section_name(obfd->raw_bfd, sec1->raw_sec),
					   bfd_section_name(pbfd->raw_bfd, sec2->raw_sec)))
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
	struct hp_section *sec1 = sec, *sec2 = sec->twin;
	struct hp_rela *rela1, *rela2;

	if (bfd_section_size(NULL, sec1->raw_sec)
		!= bfd_section_size(NULL, sec2->raw_sec)) {
		sec1->status = CHANGED;
		goto out;
	}

	if (!is_empty_section(sec1)) {
		unsigned char *data1, *data2;

		bfd_get_full_section_contents(sec1->raw_sec->owner, sec1->raw_sec, &data1);
		bfd_get_full_section_contents(sec2->raw_sec->owner, sec2->raw_sec, &data2);

		if (memcmp(data1, data2, bfd_section_size(NULL, sec1->raw_sec))) {
			sec->status = CHANGED;
			goto out;
		}
	}

	/* compare reles */
	rela2 = list_first_entry(&sec2->relas, struct hp_rela, list);
	list_for_each_entry(rela1, &sec1->relas, list) {
		if (rela_equal(rela1, rela2)) {
			rela2 = list_entry(rela2->list.next, struct hp_rela, list);
			continue;
		}
		sec1->status = CHANGED;
		goto out;
	}

	sec1->status = SAME;
out:
	if (sec1->status == CHANGED)
		log_info("section %s changed", bfd_section_name(NULL, sec1->raw_sec));
}

void compare_correlated_symbol(struct hp_symbol *sym)
{
	struct hp_symbol *sym1 = sym, *sym2 = sym->twin;

	if (sym1->symsec && sym2->symsec
		&& sym1->symsec->twin != sym2->symsec) {
		if (sym2->symsec->twin && sym2->symsec->twin->ignore)
			sym1->status = CHANGED;
		else
			err_out("symbol changed section: %s",
					bfd_asymbol_name(sym1->raw_sym));
	}

	if (sym1->symsec && (bfd_is_abs_section(sym1->raw_sym->section)
		              || bfd_is_und_section(sym1->raw_sym->section)))
		sym1->status = SAME;

	if (sym1->status == CHANGED)
		log_info("symbol %s changed", bfd_asymbol_name(sym1->raw_sym));
}

void compare_sections(struct hp_bfd *pbfd)
{
	struct hp_section *sec;

	list_for_each_entry(sec, &pbfd->sections, list) {
		if (!sec->twin)
			sec->status = NEW;
		else
			compare_correlated_section(sec);

		/* sync symbol status*/
		if (sec->secsym && sec->secsym->status != CHANGED)
			sec->secsym->status = sec->status;
		if (sec->bundsym && sec->bundsym->status != CHANGED)
			sec->bundsym->status = sec->status;
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
		char *name = bfd_section_name(pbfd->raw_bfd, sec->raw_sec);
		if (!strcmp(name, ".symtab") ||
			!strcmp(name, ".strtab") ||
			!strcmp(name, ".shstrtab")) {
			sec->include = 1;

			log_debug("include section %s",
				bfd_section_name(pbfd->raw_bfd, sec->raw_sec));

			if (sec->secsym) {
				sec->secsym->include = 1;
				log_debug("include symbol %s",
					bfd_asymbol_name(sec->secsym->raw_sym));
			}
		}
	}
}

void include_necessary_symbol(struct hp_symbol *sym)
{
	struct hp_section *sec;
	struct hp_rela *rel;

	sym->include = 1;
	log_debug("include symbol: %s", bfd_asymbol_name(sym->raw_sym));

	if (!sym->symsec || sym->symsec->include
					 || (is_section_symbol(sym) && sym->status == SAME))
		return;

	sec = sym->symsec;
	sec->include = 1;
	log_debug("include section: %s", bfd_section_name(NULL, sec->raw_sec));

	list_for_each_entry(rel, &sec->relas, list)
		include_necessary_symbol(rel->relsym);
}

int include_changed_functions(struct hp_bfd *pbfd)
{
	struct hp_symbol *sym;
	int changed = 0;

	list_for_each_entry(sym, &pbfd->symbols, list) {
		if (sym->status == CHANGED) {
			changed++;
			include_necessary_symbol(sym);
		}

		if (is_file_symbol(sym)) {
			sym->include = 1;
			log_debug("include symbol: %s", bfd_asymbol_name(sym->raw_sym));
		}
	}

	return changed;
}

void include_debug_sections(struct hp_bfd *pbfd)
{
	struct hp_section *sec;

	list_for_each_entry(sec, &pbfd->sections, list) {
		if (is_debug_section(sec)) {
			sec->include = 1;
			log_debug("include debug section: %s",
					  bfd_section_name(pbfd->raw_bfd, sec->raw_sec));

			if (sec->secsym) {
				sec->secsym->include = 1;
				log_debug("include debug symbol: %s",
						  bfd_asymbol_name(sec->secsym->raw_sym));
			}
		}
	}
}

void migrate_included_elements(struct hp_bfd *pbfd, struct hp_bfd **out_bfd)
{
	struct hp_section *sec;
	struct hp_symbol *sym;
	struct hp_bfd *hbfd;

	hbfd = malloc(sizeof(*hbfd));
	hbfd->raw_bfd = NULL;
	INIT_LIST_HEAD(&hbfd->sections);
	INIT_LIST_HEAD(&hbfd->symbols);

	list_for_each_entry(sec, &pbfd->sections, list) {
		if (!sec->include)
			continue;

		log_debug("migrate section: %s",
				  bfd_section_name(hbfd->raw_bfd, sec->raw_sec));

		list_del(&sec->list);
		list_add_tail(&sec->list, &hbfd->sections);

		if (sec->secsym && !sec->secsym->include)
			sec->secsym = NULL;
	}

	list_for_each_entry(sym, &pbfd->symbols, list) {
		if (!sym->include)
			continue;

		log_debug("migrate symbol: %s",
				  bfd_asymbol_name(sym->raw_sym));

		list_del(&sym->list);
		list_add_tail(&sym->list, &hbfd->symbols);
		sym->strip = 0;

		if (sym->symsec && !sym->symsec->include)
			sym->symsec = NULL;
	}

	*out_bfd = hbfd;
}

struct hp_bfd *load_bfd(const char *file)
{
	bfd* abfd;

	abfd = bfd_openr(file, NULL);
	if (!abfd) {
		log_info("cannot open %s", file);
		return NULL;
	}

	if (!bfd_check_format(abfd, bfd_object)) {
		log_info("invalid format");
		return NULL;
	}

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS)) {
		log_info("no symbols found");
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

	err_out("%s", usage);
}

int main(int argc, char *argv[])
{
	struct hp_bfd *obfd, *pbfd, *out_bfd;

	if (argc != 5)
		usage();

	bfd_init();

	obfd = load_bfd(argv[1]);
	pbfd = load_bfd(argv[2]);

	correlate_bfds(obfd, pbfd);

	compare_correlate_elements(pbfd);

	drop_bfd(obfd);

	include_std_elements(pbfd);

	int num_changed = include_changed_functions(pbfd);
	if (!num_changed)
	 	err_out("No changed functions");

	include_debug_sections(pbfd);

	dump_bfd(pbfd);
	dump_changes(pbfd);

	migrate_included_elements(pbfd, &out_bfd);

	drop_bfd(pbfd);

	return 0;
}
