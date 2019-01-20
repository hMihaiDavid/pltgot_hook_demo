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
	Elf64_Ehdr header;
	Elf64_Phdr *pheader;
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
	size_t symtabsz;
	Elf64_Sym *symtab;
	size_t strtabsz;
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
		if(errno) return -1;
		
		*laddr = res;
		raddr += 1;
		laddr += 1;
	}

	if(remaining) {
		errno = 0;
		long res = ptrace(PTRACE_PEEKTEXT, pid, (void *) raddr, 0);
		if(errno) return -1;
		
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
	
	
	if(target_init(&target, pid) == -1)
		error(2, errno, "target_init: ptrace(PTRACE_ATTACH)");
	
	target_parse_remote_elf(&target);
	
	fprintf(stderr, "[+] PLT GOT at address %p\n", target.plt_got_address);
	
	target_free(&target);	
	
	return 0;
}

int target_init(TARGET *target, pid_t pid) {
	/* By doing this, if the parsing of the remote ELF fails
	 * we will not have dangling pointers that will cause corruption in target_free().
	 * Non-allocated pointers will be NULL and free(NULL) is a no-op.
	 * */
	memset((void*)target, 0x00, sizeof(TARGET));
	target->pid = pid;
	
	long res = ptrace(PTRACE_ATTACH, pid, 0, 0);
	if(res == -1) return -1;
	wait(NULL);
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

// TODO refactor erro handling.
int target_parse_remote_elf(TARGET *target) {
	void *base_address;
	pid_t pid = target->pid;
	
	base_address = _get_base_address(pid);
	if(base_address == NULL) {
		fprintf(stderr, "[-] Cannot obtain base address.");
		return -1;		
	}
	target->base_address = base_address;
	
	fprintf(stderr, "[+] base address of pid %lu is %p\n",
			(unsigned long) pid, base_address); 

	/* Copy the ELF header from the remote process */
	Elf64_Ehdr *header = &target->header;
	if(!ReadProcessMemory(pid, base_address, (void*)header, 
						  sizeof(Elf64_Ehdr))) 
	{
			error(3, errno, 
				  "ReadProcessMemory(): ptrace(PTRACE_PEEKTEXT)");
	}

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
	{
			error(4, errno, 
				  "ReadProcessMemory(): ptrace(PTRACE_PEEKTEXT)");	
	}
	
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
		return -1;		
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
	
	fprintf(stderr, "[+] DYNAMIC section VA %p (size %llu bytes)\n", 
			dynamic_address, (unsigned long long) dynamic_size);

	/* Copy dynamic section from target and look for the PLT GOT */
	Elf64_Dyn *dyntable = xmalloc(dynamic_size);
	target->dyntable = dyntable;
	if(!ReadProcessMemory(pid, dynamic_address, dyntable, dynamic_size))
	{
		error(5, errno, 
			  "ReadProcessMemory(): ptrace(PTRACE_PEEKTEXT)");	
	}

	void *plt_got_address = NULL;
	for(Elf64_Dyn *dentry = dyntable;  dentry->d_tag != DT_NULL; dentry++) {
		if(dentry->d_tag == DT_PLTGOT) {
			plt_got_address = (void *) dentry->d_un.d_ptr;
		}
	}
	if(!plt_got_address) {
		return -1;
	}
	target->plt_got_address = plt_got_address;
	/* Copy plt table */
	reserve mem
	if(!ReadProcessMemory(pid, plt_got_address, target->plt_got, ))
	
	/* Find and copy the dynamic relocation information. */
	
	size_t pltrelsz = 0;
	void *pltreltable_address = NULL;
	Elf64_Xword pltreltype; int foundTable, foundSize, foundType;
	foundTable = foundSize = foundType = 0;
	
	for(Elf64_Dyn *dentry = dyntable;  dentry->d_tag != DT_NULL; dentry++) {
		switch(dentry->d_tag) {
			case DT_JMPREL: // vaddress of relocation table
				// Even if target is PIE, the va here is already absolute.
				foundTable = 1;
				pltreltable_address = (void*) dentry->d_un.d_ptr;
			break;
			case DT_PLTREL: // type of relocation
				foundType = 1;
				pltreltype = dentry->d_un.d_val;
			break;
			case DT_PLTRELSZ: // size in bytes or relocation table
				foundSize = 1;
				pltrelsz = dentry->d_un.d_val;				
			break;
			
		}
	}
	if(!foundTable || !foundType || !foundSize) {
		fprintf(stderr, "[-] Could not find dynamic relocation information in memory.");
		return -1;
	}
	
	char *pltreltable = (char *) xmalloc(pltrelsz);
	if(!ReadProcessMemory(pid, pltreltable_address, pltreltable, pltrelsz)) {
		error(6, errno, 
			  "ReadProcessMemory(): ptrace(PTRACE_PEEKTEXT)");	
	}
	
	target->pltreltype = pltreltype;
	target->pltrelsz = pltrelsz;
	if(pltreltype == DT_REL) target->u1.pltreltable = (Elf64_Rel*)pltreltable;
	else if(pltreltype == DT_RELA) target->u1.pltrelatable = (Elf64_Rela*)pltreltable;
	else fprintf(stderr, "[-] PLT relocation type corruption detected!\n");
	
	fprintf(stderr, "[+] Dynamic relocation info at %p (%llu bytes) ", 
		pltreltable_address, (unsigned long long) pltrelsz);
	fprintf(stderr, pltreltype == DT_REL?  "DT_REL\n" : "DT_RELA\n");
	
	// DEBUG:
	//write(1, (const void*)pltreltable, pltrelsz);

	// just some tests here ---------------------------------------------------
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
	
	/* Copy dynamic string table and symbol table */
	// TODO: Merge all searchs on the DYNAMIC segment in the same for!!
	
	void *symtab_address = NULL;
	size_t symtabsz = 0; int foundSymtabsz = 0;
	void *strtab_address = NULL;
	size_t strtabsz = 0; int foundStrtabsz = 0;
	
	for(Elf64_Dyn *dentry = dyntable;  dentry->d_tag != DT_NULL; dentry++) {
		switch(dentry->d_tag) {
			case DT_SYMTAB:
				symtab_address = (void*) dentry->d_un.d_ptr;
			break;
			/*case XXXXXXX: // NECESITO AYUDA PARA SABER EL TAMAÑO O NUM.SIMBOLOS
				foundSymtabsz = 1;
				symtabsz = (size_t) dentry->d_un.d_val;
			break;
			*/case DT_STRTAB:
				strtab_address = (void*) dentry->d_un.d_ptr;
			break;
			case DT_STRSZ:
				foundStrtabsz = 1;
				strtabsz = (size_t) dentry->d_un.d_val;
			break;
		}
	}
	
	if(!symtab_address || !strtab_address || 
		//!foundSymtabsz 
		 !foundStrtabsz) 
	{
			fprintf(stderr, "[-] Could not find dynamic symbol table or string table in memory\n");
			return -1;
	}
	
	fprintf(stderr, "[+] Dynamic symbol table at %p (size %llu bytes)\n", 
		symtab_address, (unsigned long long) symtabsz);
	fprintf(stderr, "[+] Dynamic string table at %p (size %llu bytes)\n", 
		strtab_address, (unsigned long long) strtabsz);
	fprintf(stderr, "CACA -- %llu\n", (unsigned long long) sizeof(Elf64_Sym) );
	
	target->strtab = xmalloc(strtabsz);
	if(!ReadProcessMemory(pid, strtab_address, target->strtab, strtabsz)) {
		error(6, errno, 
			  "ReadProcessMemory(): ptrace(PTRACE_PEEKTEXT)");	
	}
	//DEBUG
	//write(1, (const void*)target->strtab, strtabsz);
	
	// TODO copy symbol table, buut first find out its size LOL
	
	return 1;
}

/* Given the pid of a process it returns the base address of the executable of the process in its VA space
 * */
void *_get_base_address(pid_t pid) {
	char buf[17], *path, *baseaddr_str, *p;
	void *base_address;
	int fd, nread;

	if(asprintf(&path, "/proc/%lu/maps", 
			(unsigned long) pid
	) == -1)
			return NULL;

	fd = open(path, O_RDONLY);
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

	
	/* TODO: MAKE THIS CROSS-PLATFORM REGARDLESS OF COMPILATION TARGET */
	if(sscanf(baseaddr_str, "%p", &base_address) < 1) return NULL;
	
	return base_address;
}
