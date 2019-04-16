#ifndef MEM_H
#define MEM_H

#include <stdlib.h>

void *xmalloc(size_t size);
int ReadProcessMemory(int pid, const void *base_address, 
							void *buffer, size_t size);
int WriteProcessMemory(int pid, void *base_address, 
							const void *buffer, size_t size);

#endif /* MEM_H */
