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

#include <elf.h>

/* All void pointers ending in address are pointers in the VA space of
 * the target process. They are invalid and their data must be copied first. 
 * */
 
 
 
typedef struct _TARGET {
	pid_t pid;
	void *base_address;
	Elf64_Ehdr header; // elf header copied from target.
	Elf64_Phdr *pheader; // program header copied from target.
	Elf64_Dyn  *dyntable; // the DYNAMIC segment copied from target.
	
	void *plt_got_address; // address of plt got in target VA space.
	Elf64_Addr *plt_got; // the plt got copied from target.	
	
	// Dynamic relocation information
	size_t pltrelsz; // size in bytes of plt got relocation table used by dynamic linker.
	union { // table of relocation entries for plt got, copied from target.
		Elf64_Rel *pltreltable;
		Elf64_Rela *pltrelatable;
	} u1;
	// whether plt got relocations are of type Elf64_Rel or Elf64_Rela
	// this determines how to interpret u1
	Elf64_Xword pltreltype; // can be either DT_REL or DT_RELA
	
	//Dynamic symbols table and string table
	size_t symtabsz; // size in bytes
	Elf64_Sym *symtab;
	size_t strtabsz; // size in bytes
	char *strtab;

} TARGET;

void *_get_base_address(pid_t pid);
int target_init(TARGET *target, pid_t pid);
int target_parse_remote_elf(TARGET *target);
void target_free(TARGET *target);

void *xmalloc(size_t size) {
	void *res = malloc(size);
	if(!res) error(-1, errno, "malloc()");
	return res;
}

void usage(char *cmd) {
	printf("Usage: %s <TARGET_PID>\n", cmd);		
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

int main(int argc, char *argv[]) {
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
	
	target_free(&target);
	return 0;
}

int target_init(TARGET *target, pid_t pid) {
	// so that we can call free() after an error.
	// Unallocated buffers will be NULL so free is no-op.
	memset((void*)target, 0x00, sizeof(TARGET));
	
	target->pid = pid;
	void *base_address = _get_base_address(pid);
	if(base_address == NULL) {
		fprintf(stderr, "[-] Cannot obtain base address.");
		return 0;
	}
	target->base_address = base_address;
	
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
	
	ptrace(PTRACE_DETACH, target->pid, 0, 0);
}

int target_parse_remote_elf(TARGET *target) {
	void *base_address = target->base_address;
	pid_t pid = target->pid;
	
	fprintf(stderr, "[+] base address of pid %lu is %p\n",
			(unsigned long) pid, base_address); 

	/* Copy the ELF header from the remote process */
	Elf64_Ehdr *header = &target->header;
	if(!ReadProcessMemory(pid, base_address, (void*)header, 
						  sizeof(Elf64_Ehdr))) 
		goto _error;

	// DEBUG:
	//write(1, (const void*)&header, sizeof(header));

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
	
	/* Traverse program header to look for the DYNAMIC section */
	Elf64_Phdr *ph_dynamic = NULL;
	for(int i=0; i<header->e_phnum; i++) {
		Elf64_Phdr *ph = &pheader[i];
		
		if(ph->p_type == PT_DYNAMIC) {
			ph_dynamic = ph;
			break;
		}
	}
	if(!ph_dynamic) {
		fprintf(stderr, "[-] Could not find DYNAMIC information.");
		goto _error;		
	}

	void *dynamic_address; // Address of DYNAMIC Section in target va.
	dynamic_address = (void *) ph_dynamic->p_vaddr;
	uint64_t dynamic_size = ph_dynamic->p_memsz;
	if(header->e_type == ET_DYN) { 
		// target is PIE so segment addresses are base-relative.
		dynamic_address = (void*)(((char *)dynamic_address)+
						  ((size_t)base_address));
		// TODO: Write a MACRO or something to add byte offsets to 
		// pointers ellegantly.
	}
	
	fprintf(stderr, "[+] DYNAMIC section at %p (size %llu bytes)\n", 
			dynamic_address, (unsigned long long) dynamic_size);

	/* Copy dynamic section from target */
	Elf64_Dyn *dyntable = xmalloc(dynamic_size);
	target->dyntable = dyntable;
	if(!ReadProcessMemory(pid, dynamic_address, dyntable, dynamic_size))
		goto _error;

	/* Find dynamic information from DYNAMIC section and copy it.
	 *  ex. dynamic symbol table, dynamic relocations for pltgot...
	 * */
	size_t pltrelsz = 0;
	void *pltreltable_address = NULL;
	void *plt_got_address = NULL;
	Elf64_Xword pltreltype; int foundRelTable, foundRelSize, foundRelType;
	foundRelTable = foundRelSize = foundRelType = 0;

	void *symtab_address = NULL;
	void *strtab_address = NULL;
	size_t strtabsz = 0; int foundStrtabsz = 0;
	
	for(Elf64_Dyn *dentry = dyntable;  dentry->d_tag != DT_NULL; dentry++) {
		switch(dentry->d_tag) {
			case DT_PLTGOT: // address of the PLT GOT
				plt_got_address = (void *) dentry->d_un.d_ptr;
			break;
			// ojalá hubiera un DT_PLTGOTSZ...
			case DT_JMPREL: // address of relocation table
				// Even if target is PIE, the va here is already absolute.
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
			// ojalá hubiera un DT_SYMSZ....
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
		fprintf(stderr, "[-] Could not find dynamic symbol table or string table in memory\n");
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
	
	/* TODO: <-------------------------------------------------
	 * Now we have to find the size of the plt got and the size of the
	 * dynamic symbol table in order to copy them.
	 * Maybe assuming they have a last NULL entry will work??
	 * */
	
	//-------------------------------------------------------------------------
	//-------------------------------------------------------------------------
	//-------------------------------------------------------------------------
	
	// DEBUG: IGNORE THIS ---------------------------------------------------
	// print relocation info to check with readelf of a binary on disk-------
	// info was correct.
	/*Elf64_Rela *rels = target->u1.pltrelatable;
	size_t nrels = target->pltrelsz / sizeof(Elf64_Rela);
	
	fprintf(stderr,"\n\n---- SOME RELOCATION TARGET VAs ---- (nrels=%llu) \n\n",
			(unsigned long long)nrels);
	for(size_t i=0; i<nrels; i++) {
		void *fixva = (void*)(((char *)rels[i].r_offset)+
						  ((size_t)base_address));
						  
		fprintf(stderr, "\t[I] offset: %p, va: %p, sym: %llu, type: %lu\n", 
			 (void*) rels[i].r_offset, fixva, 
			 (unsigned long long)ELF64_R_SYM(rels[i].r_info),
			 (unsigned long)ELF64_R_TYPE(rels[i].r_info));
	}*/
	//-------------------------------------------------------------------------

	//DEBUG
	//write(1, (const void*)target->strtab, strtabsz);
	// after running it through strings(1) it gave expected results.
	
	return 1;
_error:
	target_free(target);
	return 0;
}

/* Given the pid of a process it returns the base address of the main executable of the process.
 * */
void *_get_base_address(pid_t pid) {
	char buf[17], *path, *baseaddr_str, *p;
	void *base_address;
	int fd, nread;

	if(asprintf(&path, "/proc/%lu/maps", 
			(unsigned long) pid
	) == -1)
			return NULL;

	if((fd = open(path, O_RDONLY)) == -1) return NULL;
	free(path);
	nread = read(fd, buf, 17);
	if(nread < 17) return NULL;
	buf[16] = '\0';
	baseaddr_str = buf;
	
	p = buf;
	while(*p != '\0' && *p != '-') p++;
	if(*p == '\0') return NULL;
	*p = '\0';

	// Now baseaddr_str is a null-terminated string like "55f3ecfb3000"
	// being the base address. We need to convert this into a pointer.

	if(sscanf(baseaddr_str, "%p", &base_address) < 1) return NULL;
	
	return base_address;
}
