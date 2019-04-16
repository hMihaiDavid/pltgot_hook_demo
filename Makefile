all:
	gcc -o foo parse_remote_elf.c memory_map_parser.c dump_pltgot.c infect.c main.c mem.c -ggdb
test:
	gcc -no-pie -o test test.c
	gcc -o test_pie test.c
clean:
	rm foo test test_pie
