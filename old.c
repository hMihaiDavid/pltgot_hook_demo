/*
 * Associative array that maps the base address of an object (libc...) to
 * the address of the shellcode injected into it or NULL if not infected yet.
 * Each TARGET has an instance of this map in target->shellcode_map.
 * */
static void *lookup_shellcode_address(TARGET *target, void *base_address);
static void set_shellcode_address(TARGET *target, void *base_address, void *shellcode_address);
hash_t *init_shellcode_map(TARGET *target, size_t size);
void free_shellcode_map(TARGET *target);
// It is implemented at the end of this file as a simple hash set of fixed size.


typedef struct _hash {
	size_t size;
	void **keys;
	void **values;
} hash_t;





// Implementation of the associative array stated at the begining of the file.
// ---------------------------------------------------------------------------
/* 
 * typedef struct _hash {
	size_t size;
	void **keys;
	void **values;
} hash_t;  shellcode_map
 * */
hash_t *init_shellcode_map(TARGET *target, size_t size) {
	target->shellcode_map.size   = size;
	target->shellcode_map.keys 	 = xmalloc(size*sizeof(void*));
	target->shellcode_map.values = xmalloc(size*sizeof(void*));
	
	return &target->shellcode_map;
}
void free_shellcode_map(TARGET *target) {
	free(target->shellcode_map.keys);
	target->shellcode_map.keys = NULL;
	free(target->shellcode_map.values);
	target->shellcode_map.values = NULL;
	target->shellcode_map.size = 0;
}

static void *lookup_shellcode_address(TARGET *target, void *base_address);
static void set_shellcode_address(TARGET *target, void *base_address, void *shellcode_address);
