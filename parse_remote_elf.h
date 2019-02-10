#ifndef PARSE_REMOTE_ELF_H
#define PARSE_REMOTE_ELF_H

#include <sys/types.h>
#include <elf.h>

#include "memory_map_parser.h"

/* Structure that holds all the necessary information about a pltgot entry
 * in order to infect it. An array of this is filled when parsing a target
 * in parse_remote_elf().
 * */
typedef struct _pltgot_entry {
	void *slot_address;
	void *jump_address;
	void *module_base; // can be NULL if it cannot be retrieved.
	ssize_t symindex; // can be -1 if not found
	// relindex???
	const char *symname; // can be NULL if cannot be retrieved.
	const char *module; // can be NULL if module_base is NULL or lookup failed.
	int is_resolved;
	int is_infected; // so that it doesn't get infected twice.
} pltgot_entry_t;
// TODO: Write a MACRO that evaluates to whether a pltgotentry is suitable for
// infection or not, that is to say, module_base is not null and more...

typedef struct _TARGET {
	pid_t pid;
	void *base_address;
	memory_map_t maps;
	
	size_t sizeofimage;
	Elf64_Ehdr header; // elf header copied from target.
	Elf64_Phdr *pheader; // program header copied from target.
	Elf64_Dyn  *dyntable; // the DYNAMIC segment copied from target.
	
	void *plt_got_address; // address of plt got in target VA space.
	Elf64_Addr *plt_got; // the plt got copied from target.
	size_t plt_gotsz; // size in bytes of the plt got.
	
	// Dynamic relocation information
	size_t pltrelsz; // size in bytes of plt got relocation table used by dynamic linker.
	size_t numrelocs; // number of entries in the aforementioned reloc table. Redundant.
	union { // table of relocation entries for plt got, copied from target.
		Elf64_Rel *pltreltable;
		Elf64_Rela *pltrelatable;
	} u1;
	// whether plt got relocations are of type Elf64_Rel or Elf64_Rela.
	// this determines how to interpret u1
	Elf64_Xword pltreltype; // can be either DT_REL or DT_RELA
	
	//Dynamic symbols table and string table
	size_t symtabsz; // size in bytes
	Elf64_Sym *symtab;
	size_t strtabsz; // size in bytes
	char *strtab;
	
	/* This array is filled with info about each pltgot entry.
	 * It is used for infecting them. It is filled when parsing.
	 * */
	pltgot_entry_t *pltgot_entries;
} TARGET;

int target_init(TARGET *target, pid_t pid);
int target_parse_remote_elf(TARGET *target);
const char *target_get_symbol_name(TARGET *target, ssize_t symindex);
int is_address_in_target(TARGET *target, void *addr);
void *target_find_base(TARGET *target, void *addr);
void target_free(TARGET *target);

#endif /* PARSE_REMOTE_ELF_H */
