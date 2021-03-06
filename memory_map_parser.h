#ifndef MEMORY_MAP_PARSER_H
#define MEMORY_MAP_PARSER_H

#include <stdint.h>
#include <sys/types.h>
#include <elf.h>

/* All void pointers ending in "_address" are pointers in the VA space of
 * the target process. They are invalid.
 * */

typedef struct _memory_region {
	void *start_address;
	void *end_address;
	char perms[5]; // ex. "r-xp", null-terminated
	off_t offset;
	char dev[12]; // major:minor ex: "08:02", null terminated.
	int inode;
	char *path; /* Will be NULL if not present */
	char *module; /* Will be NULL if not present */
	
	void *shellcode_address; // address of the injected shellcode within a region.
	Elf64_Ehdr *elfheader; 	// ELF and program header copied from target.
	Elf64_Phdr *pheader;   	// only valid if this region the first region of an object/executable.
							// They are lazy loaded by inject_shellcode in infect.c
} memory_region_t;

typedef struct _memory_map {
	uint32_t num_regions;
	memory_region_t *regions;
} memory_map_t;

int memory_map_parse(memory_map_t *map, pid_t pid);
void memory_map_free(memory_map_t *map);

#endif /* MEMORY_MAP_PARSER_H */
