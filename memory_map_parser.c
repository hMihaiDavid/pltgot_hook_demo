#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#include "memory_map_parser.h"

int _parse_line(const char *line, memory_region_t *region)
{	
	int res, n = 0;
	unsigned long start_address, end_address;
	unsigned int off;
	
	res = sscanf(line, "%lx-%lx %4c %x %11s %d %n", &start_address, 
	&end_address, region->perms, &off, region->dev, &region->inode, &n);
	if(res < 4)  {
		region->path = NULL;
		return 0;
	}
	
	const char *path = line+n;
	size_t path_len = strlen(path);
	region->path = malloc(path_len+1);
	if(!region->path) return 0;
	strcpy(region->path, path);
	region->perms[4] = '\0';
	
	region->start_address = (void*) start_address;
	region->end_address = (void*) end_address;
	region->offset = (off_t) off;
	
	/*fprintf(stderr, "---%p;%p;%s;%d;%s;%d;%s\n", region->start_address, region->end_address,region->perms,
			(int)region->offset, region->dev, region->inode, region->path);
	*/
	return 1;
}

void memory_map_free(memory_map_t *map)
{
	for(size_t i=0; i<map->num_regions; i++) {
		free(map->regions[i].path);
	}
	free(map->regions); map->regions = NULL;
	map->num_regions = 0;
}

int memory_map_parse(memory_map_t *map, pid_t pid)
{
#define NSLOTS 23 // tested with NSLOTS=1
	uint32_t num_regions = 0;
	uint32_t remaining_slots = 0;
	FILE *f = NULL;
	char *path = NULL, *line = NULL;
	size_t n = 0;
	ssize_t nread = 0;
	memory_region_t *regions = NULL;
	
	memset((void*)map, 0x00, sizeof(memory_map_t));
	
	if(asprintf(&path, "/proc/%lu/maps", 
			(unsigned long) pid
	) == -1)
			goto _error;

	if( !(f = fopen(path, "r")) ) goto _error;
	free(path);
	
	size_t size = NSLOTS*sizeof(memory_region_t);
	regions = (memory_region_t*) malloc(size);
	if(!regions) goto _error;
	remaining_slots = NSLOTS;
	num_regions = 0;
	
	n = 128; line = malloc(n); if(!line) goto _error;
	while( (nread = getline(&line, &n, f)) != -1 ) {
		if(!_parse_line(line, &regions[num_regions]))
			goto _error;
			
		num_regions++; remaining_slots--;
		if(remaining_slots == 0) { // dynamically grow the array...
			size += NSLOTS*sizeof(memory_region_t);
			void *p = realloc(regions, size);
			if(!p) goto _error; regions = (memory_region_t*)p;
			remaining_slots = NSLOTS;
			//fprintf(stderr,"[DEBUG] _target_parse_mem_map: Resizing\n");
		}
		
	}
	if(errno || num_regions == 0) goto _error;
	
	free(line);
	map->regions = regions;
	map->num_regions = num_regions;
	
	fclose(f);
	return 1;
_error:
	if(f) fclose(f);
	free(path);
	free(line);
	memory_map_free(map);
	return 0;
#undef NSLOTS
}
