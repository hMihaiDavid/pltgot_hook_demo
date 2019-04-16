#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <error.h>
#include <errno.h>

void dump_pltgot(pid_t pid);
void infect(pid_t pid, int entry_num, char *shellcode_path);

void usage(char *cmd) {
	printf(	"Usage: %s <PID>\t\t\tDump PLT GOT (imports)\n"
			"       %s <PID> <entry_num> /path/sc.bin\tInfect PLTGOT entry\n"
			"\nExamples:\n"
			"       sudo %s 9940 8 ./shellcode.bin\n"
			"         ^\n"
			"         |--- Infects entry number 8 in the PLTGOT of process PID 9940\n"
			"              Dump the PLTGOT first to see the entries indexes.\n\n"
			"\n"
			" You can infect the target several times as long as you infect\n"
			" functions on different shared objects. If you try to infect, let's say,\n"
			" printf and exit (both on libc), you will corrupt the shellcode's return address!\n"
			"\n There can only be one instance of a shellcode per shared object.\n"
	,cmd, cmd, cmd);
}

size_t *parse_argv_list(int argc, char **argv, size_t *list_size);
static char *parse_shellcode(int argc, char **argv);

int main(int argc, char **argv)
{

	if(argc < 2) {
		usage(argv[0]);		
	} else if(argc == 2) {
		pid_t pid = (pid_t)atoll(argv[1]);
		if(pid == 0) {
			fprintf(stderr, "Invalid PID. Run %s without arguments for help.\n", argv[0]);
			return 2;
		}
		dump_pltgot(pid);
	} else if(argc == 3) {
		fprintf(stderr, "Missing shellcode. Run %s with no arguents for help.\n", argv[0]);
		return 1;
	} else {
		
		pid_t pid = (pid_t)atoll(argv[1]);
		if(pid == 0) {
			fprintf(stderr, "Invalid PID. Run %s without arguments for help.\n", argv[0]);
			return 2;
		}
		char *shellcode_path = parse_shellcode(argc, argv);
		int entry_num = atoi(argv[2]);

		if(!shellcode_path) {
			fprintf(stderr, "Invalid input. Run %s without arguments for help\n", argv[0]);
			return 3;
		}

		infect(pid, entry_num, shellcode_path);
	}
	
	return 0;
}

static char *parse_shellcode(int argc, char **argv) {
	char **p = &argv[2];
	while(*p) {
		if(!isdigit(**p)) return *p;
		p++;
	}
	return NULL;
}
