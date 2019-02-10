/* All void pointers ending in "_address" are pointers in the VA space of
 * the target process. They are invalid.
 * */
 
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "parse_remote_elf.h"
#include "memory_map_parser.h"

#include <elf.h>

static const char *_get_module_name_from_base(TARGET *target, void *baseaddr);
static int _target_parse_pltgot(TARGET *target);

void *xmalloc(size_t size) {
	void *res = malloc(size);
	if(!res) error(-1, errno, "malloc()");
	return res;
}

/*
 * Reads size bytes into buffer from the address space
 * of a remote process given by pid. The data read starts at
 * base_address in the va space of the remote process.
 * The process give by pid should be in ptrace-stop already.
 *  */
int ReadProcessMemory(int pid, const void *base_address, 
							void *buffer, size_t size) 
{
	#define _WORD_SIZE (sizeof(long)) // ptrace() returns a word in a long.
	size_t sb, remaining;
	long *raddr, *laddr;
	
	raddr = (long *) base_address;
	laddr = (long *) buffer;

	sb = size / _WORD_SIZE;			
	remaining = size % _WORD_SIZE;

	for(size_t i = 0; i < sb; i++) {
		errno = 0;
		long res = ptrace(PTRACE_PEEKTEXT, pid, (void *) raddr, 0);
		if(errno) return 0;
		
		*laddr = res;
		raddr += 1;
		laddr += 1;
	}

	if(remaining) {
		errno = 0;
		long res = ptrace(PTRACE_PEEKTEXT, pid, (void *) raddr, 0);
		if(errno) return 0;
		
		char *p = (char *) laddr;
		for(int i=0; i<remaining; i++) {
			*p = (char)( (res >> (i*8)) & 0xFF );
			p++;
		}
	}
	
	return 1;		
	#undef _WORD_SIZE
}

const char *target_get_symbol_name(TARGET *target, ssize_t symindex)
{
	if(symindex < 0) return NULL;
	Elf64_Sym *sym = &target->symtab[symindex];
	uint32_t nameoffset = sym->st_name;
	return &target->strtab[nameoffset];
}
/* Given a pointer within the address space of target,
 * returns a boolean telling whether the pointer falls within
 * the image of the main executable or not.
 * */
int is_address_in_target(TARGET *target, void *addr)
{			
	return ( ((size_t)addr) < ((size_t)target->base_address + target->sizeofimage) )
			&& ( ((size_t)addr) >= ((size_t)target->base_address) );
}

static int _target_parse_pltgot(TARGET *target)
{
	if(target->pltgot_entries) free(target->pltgot_entries);
	
	// First 3 entries are reserved. See SysV amd64 ABI supplement.
	size_t numentries = (target->plt_gotsz/sizeof(Elf64_Addr))-3;
	pltgot_entry_t *entries = xmalloc(numentries*sizeof(pltgot_entry_t));
	target->pltgot_entries = entries;
	
	Elf64_Addr *p = target->plt_got+3;
	for(size_t i=0; i<numentries; i++) {
		pltgot_entry_t *entry = &entries[i];
		Elf64_Addr jmpaddr = *p;
		void *slot_address = (void*)(((size_t)target->plt_got_address)+((size_t)p - (size_t)target->plt_got));
		entry->slot_address = slot_address;
		entry->jump_address = (void*)jmpaddr;
		
		ssize_t symindex = -1; // TODO: Use an invalid index as specified in the docs.
		
		// Find the symbol table index for the current pltgot entry.
		for(size_t ri=0; ri < target->numrelocs; ri++) {
			Elf64_Addr r_offset; void *fixaddr;
			uint64_t r_info;
			if(target->pltreltype == DT_REL) {
				r_offset = target->u1.pltreltable[ri].r_offset;
				r_info = target->u1.pltreltable[ri].r_info;
			} else if(target->pltreltype == DT_RELA) {
				r_offset = target->u1.pltrelatable[ri].r_offset;
				r_info = target->u1.pltrelatable[ri].r_info;
			}

			fixaddr = (void *)r_offset;
			if(target->header.e_type == ET_DYN) // the binary is pie so va is relative.
				fixaddr = (void*)((size_t)fixaddr+(size_t)target->base_address);

			if(fixaddr == slot_address) symindex = ELF64_R_SYM(r_info);
		}
		entry->symindex = symindex;
		entry->symname = target_get_symbol_name(target, symindex);
		entry->module_base = target_find_base(target, (void*)jmpaddr);
		entry->module = _get_module_name_from_base(target, entry->module_base);
		entry->is_resolved = !is_address_in_target(target, entry->jump_address);
	
		p++;
	}
	
	return 1;
}

int target_init(TARGET *target, pid_t pid) {
	// so that we can call free() after an error.
	// Unallocated buffers will be NULL so free is no-op.
	memset((void*)target, 0x00, sizeof(TARGET));
	
	target->pid = pid;
	if(!memory_map_parse(&target->maps, target->pid)) {
		fprintf(stderr, "[-] Cannot parse memory map of target.\n");
		return 0;
	}
	target->base_address = target->maps.regions[0].start_address;
	
	long res = ptrace(PTRACE_ATTACH, pid, 0, 0);
	if(res == -1) return 0;
	wait(NULL);
	
	return 1;
}

void target_free(TARGET *target) {
	free(target->pheader); target->pheader = NULL;
	free(target->dyntable); target->dyntable = NULL;
	free(target->plt_got); target->plt_got = NULL;
	free(target->u1.pltrelatable); target->u1.pltrelatable = NULL;
	free(target->symtab); target->symtab = NULL;
	free(target->strtab); target->strtab = NULL;
	free(target->pltgot_entries); target->pltgot_entries = NULL;
	
	memory_map_free(&target->maps);
	
	ptrace(PTRACE_DETACH, target->pid, 0, 0);
}

int target_parse_remote_elf(TARGET *target) {
	void *base_address = target->base_address;
	pid_t pid = target->pid;
	
	fprintf(stderr, "[+] Base address of pid %lu is %p\n",
			(unsigned long) pid, base_address); 
	/* Copy the ELF header from the remote process */
	Elf64_Ehdr *header = &target->header;
	if(!ReadProcessMemory(pid, base_address, (void*)header, 
						  sizeof(Elf64_Ehdr))) 
		goto _error;
		
	if( ((char*)header)[4] != 0x02 ) {
		fprintf(stderr,"[-] This prgram only works on 64bit proceses!\n");
		goto _error;
	}

	// DEBUG:
	//write(1, (const void*)header, sizeof(Elf64_Ehdr));
	
	/* Copy program header from remote process */
	void *pheader_address = (void *)( ((char *)base_address) 
										       + header->e_phoff);
	Elf64_Phdr *pheader;
	pheader = (Elf64_Phdr *)xmalloc(header->e_phnum*sizeof(Elf64_Phdr));
	target->pheader = pheader;
	if(!ReadProcessMemory(pid, pheader_address, (void*)pheader,
						  sizeof(Elf64_Phdr)*header->e_phnum))
		goto _error;
	
	// DEBUG:
	//write(1, (const void*)pheader, sizeof(Elf64_Phdr)*header.e_phnum);
	
	/* Traverse program header to look for dynamic segment and to calculate
	 * size of image */
	Elf64_Phdr *ph_dynamic = NULL;
	Elf64_Phdr *firstload, *lastload; 
	firstload = lastload = NULL;
	for(int i=0; i<header->e_phnum; i++) {
		Elf64_Phdr *ph = &pheader[i];
		if(ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC) {
			if(firstload == NULL) firstload = ph;
			lastload = ph;
			if(ph->p_type == PT_DYNAMIC) ph_dynamic = ph;
		}
	}
	if(!firstload || !lastload) goto _error;
	if(!ph_dynamic) {
		fprintf(stderr, "[-] Could not find DYNAMIC information.");
		goto _error;		
	}
	
	target->sizeofimage = (size_t)( ((size_t)lastload->p_vaddr + lastload->p_memsz)
							- (size_t)firstload->p_vaddr );
	
	void *dynamic_address; // Address of DYNAMIC Section in target va.
	dynamic_address = (void *) ph_dynamic->p_vaddr;
	uint64_t dynamic_size = ph_dynamic->p_memsz;
	if(header->e_type == ET_DYN) { 
		// target is PIE so segment addresses are base-relative.
		dynamic_address = (void*)(((char *)dynamic_address)+
						  ((size_t)base_address));
		fprintf(stderr, "[+] Target process is PIE\n");
	}
	
	fprintf(stderr, "[+] DYNAMIC section at %p (size %llu bytes)\n", 
			dynamic_address, (unsigned long long) dynamic_size);

	/* Copy dynamic section from target */
	Elf64_Dyn *dyntable = xmalloc(dynamic_size);
	target->dyntable = dyntable;
	if(!ReadProcessMemory(pid, dynamic_address, dyntable, dynamic_size))
		goto _error;

	/* Find dynamic information from DYNAMIC section and copy it.
	 *  ex. pointers to dynamic symbol table, dynamic relocations for pltgot...
	 * */
	size_t pltrelsz = 0;
	void *pltreltable_address = NULL;
	void *plt_got_address = NULL;
	Elf64_Xword pltreltype; int foundRelTable, foundRelSize, foundRelType;
	foundRelTable = foundRelSize = foundRelType = 0;

	void *symtab_address = NULL;
	void *symhash_address = NULL;
	void *strtab_address = NULL;
	size_t strtabsz = 0; int foundStrtabsz = 0;
	
	// Note: Even if target is PIE, VAs in DYNAMIC segment are already absolute.
	// Probably fixed by dynamic loader(?)
	for(Elf64_Dyn *dentry = dyntable;  dentry->d_tag != DT_NULL; dentry++) {
		switch(dentry->d_tag) {
			case DT_PLTGOT: // address of the PLT GOT
				plt_got_address = (void *) dentry->d_un.d_ptr;
			break;
			case DT_JMPREL: // address of relocation table
				foundRelTable = 1;
				pltreltable_address = (void*) dentry->d_un.d_ptr;
			break;
			case DT_PLTREL: // type of relocation
				foundRelType = 1;
				pltreltype = dentry->d_un.d_val;
			break;
			case DT_PLTRELSZ: // size in bytes or relocation table for plt got
				foundRelSize = 1;
				pltrelsz = dentry->d_un.d_val;				
			break;
			case DT_SYMTAB: // address of dynamic symbol table
				symtab_address = (void*) dentry->d_un.d_ptr;
			break;
			case DT_HASH: // address of symbol hash table
				symhash_address = (void*) dentry->d_un.d_ptr;
			break;
			case DT_STRTAB: // address of string table
				strtab_address = (void*) dentry->d_un.d_ptr;
			break;
			case DT_STRSZ: // size in bytes of string table
				foundStrtabsz = 1;
				strtabsz = (size_t) dentry->d_un.d_val;
			break;
			
		}
	}
	if(!plt_got_address) {
		fprintf(stderr, "[-] Could not find PLT GOT of target.");
		goto _error;
	}
	target->plt_got_address = plt_got_address;
	
	if(!foundRelTable || !foundRelType || !foundRelSize) {
		fprintf(stderr, "[-] Could not find dynamic relocation information of target.");
		goto _error;
	}
	
	if(!symtab_address || !strtab_address || !foundStrtabsz) 
	{
		fprintf(stderr, "[-] Could not find dynamic symbol table or string table\n");
		goto _error;
	}
	
	
	// Copy plt got relocation table from target.
	char *pltreltable = (char *) xmalloc(pltrelsz);
	if(!ReadProcessMemory(pid, pltreltable_address, pltreltable, pltrelsz))
		goto _error;
	
	// Copy string table from target
	target->strtab = xmalloc(strtabsz);
	if(!ReadProcessMemory(pid, strtab_address, target->strtab, strtabsz))
		goto _error;
	
	target->pltreltype = pltreltype;
	target->pltrelsz = pltrelsz;
	if(pltreltype == DT_REL) target->u1.pltreltable = (Elf64_Rel*)pltreltable;
	else if(pltreltype == DT_RELA) target->u1.pltrelatable = (Elf64_Rela*)pltreltable;
	else fprintf(stderr, "[-] PLT relocation type corruption detected!\n");
	

	fprintf(stderr, "[+] Dynamic relocation table for PLT GOT at %p (%llu bytes) ", 
		pltreltable_address, (unsigned long long) pltrelsz);
	fprintf(stderr, pltreltype == DT_REL?  "DT_REL\n" : "DT_RELA\n");
	
	fprintf(stderr, "[+] Dynamic symbol table at %p\n", 
		symtab_address);
	fprintf(stderr, "[+] Dynamic string table at %p (size %llu bytes)\n", 
		strtab_address, (unsigned long long) strtabsz);
	
	//DEBUG
	//write(1, (const void*)target->strtab, strtabsz);
	// after running it through strings(1) it gave expected results.
	

	 // Copy pltgot and dynamic symbol table from target 
	 
	 // We calculate the number of pltgot entries from the number
	 // off relocation entries.
	 
	size_t numrelocs = target->pltrelsz;
	if(target->pltreltype == DT_REL) numrelocs /= sizeof(Elf64_Rel);
	else if(target->pltreltype == DT_RELA) numrelocs /= sizeof(Elf64_Rela);
	else goto _error;
	target->numrelocs = numrelocs;

	/* There are 3 reserved entries at the begining according to amd64 ABI supplement. 
	 * */
	target->plt_gotsz = (numrelocs+3)*sizeof(Elf64_Addr);
	
	/* 
	 * Calculate the size of the dynamic symbol table.
	 * -------------------------------------------------
	 * To do so we use the symbol hash table. ELF specs say:
	 * "The number of symbol table entries should equal nchain (in hash table)"
	 * If there is no hash table, we calculate the size as the distance
	 * between the symbol tamble and the string table, since in practice
	 * they are contiguous. This is undocumented.
	 * */
	 if(symhash_address) {
		 Elf64_Word data[2];
		 if(!ReadProcessMemory(pid, symhash_address, data, sizeof(data)))
			goto _error;
		 target->symtabsz = (size_t) data[1];
		 fprintf(stderr, "[DEBUG] Found hash table, nchain=nsyms=%ld\n", target->symtabsz);
	 } else { // It is usually not present....
		if((size_t)strtab_address <= (size_t)symtab_address) {
			fprintf(stderr, "[-] Cannot calculate size of dynamic symbol table.\n");
			goto _error;
		}
		target->symtabsz = (size_t)strtab_address - (size_t)symtab_address;
	 }
	
	fprintf(stderr, "[+] Estimated size of the PLT GOT: %llu bytes (%lu entries)\n",
		(unsigned long long) target->plt_gotsz, (unsigned long)(numrelocs+3));
	fprintf(stderr, "[+] Estimated size of dynamic symbol table: %llu bytes (%lu entries)\n",
		(unsigned long long) target->symtabsz, (unsigned long)(target->symtabsz/sizeof(Elf64_Sym)));
	
	// Perform the memory transfers.
	target->plt_got = xmalloc(target->plt_gotsz);
	target->symtab = xmalloc(target->symtabsz);
	if(!ReadProcessMemory(pid, plt_got_address, target->plt_got, target->plt_gotsz))
		goto _error;
	if(!ReadProcessMemory(pid, symtab_address, target->symtab, target->symtabsz))
		goto _error;
		
	/* Fill the array target.pltgot_entries with the necessary info about
	 * each pltgot entry needed to infect it.
	 * */
	_target_parse_pltgot(target);
	
	// DEBUG
	//write(1, (const void*)target->plt_got, target->plt_gotsz);
	//write(1, (const void*)target->symtab, target->symtabsz);
	
	//-------------------------------------------------------------------------
	//-------------------------------------------------------------------------
	//-------------------------------------------------------------------------
	
	
	// THE END
	return 1;
_error:
	target_free(target);
	return 0;
}

/* Given a pointer addr somewhere within target va space,
 * return the base address of the module where that pointer
 * lies. 
 * For instance, if addr is the address of a libc function,
 * it returns the base address of libc.
 * Returns NULL on failure.
 * */
void *target_find_base(TARGET *target, void *addr)
{
	size_t val = (size_t) addr;
	memory_region_t *belong_region = NULL;
	for(uint32_t i=0; i<target->maps.num_regions; i++) {
		memory_region_t *r = &target->maps.regions[i];
		if(val < (size_t)r->end_address && val >= (size_t)r->start_address)
			belong_region = r;
	}
	if(!belong_region) return NULL;
	
	for(uint32_t i=0; i<target->maps.num_regions; i++) {
		memory_region_t *r = &target->maps.regions[i];
		if(strcmp(r->dev, belong_region->dev) == 0
			&& r->inode == belong_region->inode)
			return r->start_address;
	}
	return NULL;
}

/* Givwen the base address of a module in target va space,
 * it returns a string with the name of said module.
 * returns NULL when the module is a special region in the memory map:
 * [heap], [stack]... instead of being mapped from a file.
 * */
static const char *_get_module_name_from_base(TARGET *target, void *baseaddr)
{
	memory_map_t *maps = &target->maps;
	for(uint32_t i = 0; i<maps->num_regions; i++) {
		if(maps->regions[i].start_address == baseaddr)
			return maps->regions[i].module; // will be null if special region.
	}
	return NULL;
}
