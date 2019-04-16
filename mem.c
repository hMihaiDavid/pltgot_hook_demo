#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <sys/ptrace.h>
#include "mem.h"

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
