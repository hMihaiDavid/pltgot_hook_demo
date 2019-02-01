#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>

#include "memory_map_parser.h"
#include "parse_remote_elf.h"


void usage(char *cmd) {
	printf("Usage: %s <TARGET_PID>\n", cmd);		
}

static void dump_imports(TARGET *target)
{
	pltgot_entry_t *entries = target->pltgot_entries;
	size_t numentries = (target->plt_gotsz/sizeof(Elf64_Addr))-3;
	
	for(size_t i = 0; i < numentries; i++) {
		pltgot_entry_t *entry = &entries[i];
		
		if(entry->symindex < 0) {
			fprintf(stderr, "[%lu] %p:\t%p\t(sym. #?)\tCANNOT FIND SIMBOL\n", i, entry->slot_address, entry->jump_address);
		}
		else {
			const char *module = entry->is_resolved ? entry->module : "(unresolved)";
			fprintf(stderr, "[%lu] %p:\t%p\t(sym. #%ld)\t%s@%s\n", i, entry->slot_address, entry->jump_address,
				entry->symindex, entry->symname, module);
		}
	}
	
}

int main(int argc, char **argv)
{
	pid_t pid;
	long res;
	TARGET target;

	if(argc < 2) {
		usage(argv[0]);
		return 1;		
	}
	
	pid = (pid_t) atoll(argv[1]);
	
	if(!target_init(&target, pid))
		error(2, errno, "target_init");
	
	if(!target_parse_remote_elf(&target))
		error(3, errno, "target_parse_remote_elf");
	
	fprintf(stderr, "\n\n[+] ---- DUMP OF PLT GOT OF TARGET ----\n");
	dump_imports(&target);
	
	target_free(&target);
	return 0;
}
