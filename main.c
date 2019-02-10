#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <error.h>
#include <errno.h>

void dump_pltgot(pid_t pid);
void infect(pid_t pid, size_t list[], size_t list_size, char *shellcode_path);

void usage(char *cmd) {
	printf(	"Usage: %s <PID>\t\t\tDump PLT GOT (imports)\n"
			"       %s <PID> [LIST] /path/sc.bin\tInfect PLTGOT entries\n"
			"\nExamples:\n"
			"       sudo %s 9940 8 2-4 7 ./shellcode.bin\n"
			"         ^\n"
			"         |--- Infects entries 2 to 4 (both included), 7 and 8\n"
			"               Dump the PLTGOT first to see the entries indexes.\n\n"
			"       sudo %s 9970 1 -\t\tReads shellcode from STDIN\n"
	,cmd, cmd, cmd, cmd);
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
		size_t list_size;
		size_t *list = parse_argv_list(argc, argv, &list_size);
		char *shellcode_path = parse_shellcode(argc, argv);
		
		if(!list || !shellcode_path) {
			fprintf(stderr, "Invalid input. Run %s without arguments for help\n", argv[0]);
			return 3;
		}
		infect(pid, list, list_size, shellcode_path);
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

/* parse_argv_list */
/* Singly-linked list of size_t */
typedef struct _node {
	size_t data;
	struct _node *next;
} node_t;
typedef struct _list {
	node_t *head;
	size_t size;
} list_t;
static list_t *list_init(list_t *list);
static void *list_add(list_t *list, size_t n);
static void list_free(list_t *list);

static void *xmalloc(size_t size) {
	void *res = malloc(size);
	if(!res) error(-1, errno, "malloc()");
	return res;
}

size_t *parse_argv_list(int argc, char **argv, size_t *list_size) {
	list_t l;
	list_init(&l);
	
	char **p = &argv[2];
	while(*p) {
		if(!isdigit(**p)) break; //end of list
		char *h;
		if(h = strstr(*p, "-")) {
			// range of 2 values, h points to "-" separator. 
			*h = '\0';
			size_t a = (size_t) atol(*p);
			size_t b = (size_t) atol(h+1);
			if((a == 0 && **p != '0') || (b == 0 && *(h+1) != '0')) {
				// non numeric string
				list_free(&l); return NULL;
			}
			if(b < a) { size_t aux = a; a = b; b = aux; }
			for(size_t i=a; i<=b; i++) list_add(&l, i);
		} else {
			size_t n = (size_t) atol(*p);
			if(n == 0 && **p != '0') {
				// non numeric string
				list_free(&l); return NULL;
			}
			list_add(&l, n);
		}
		
		p++;
	}
	
	/* convert list into an array */
	if(list_size) *list_size = l.size;
	if(l.size == 0) {list_free(&l); return NULL; }
	
	size_t *res = xmalloc(l.size * sizeof(size_t));
	size_t i = l.size-1;
	node_t *node = l.head;
	while(node) {
		res[i] = node->data;
		i--;
		node = node->next;	
	}
	list_free(&l);
	return res;
}
/* Singly-linked list of size_t (simple stack implementation) */
static list_t *list_init(list_t *list) {
	memset((void*)list, 0x00, sizeof(list_t));
	return list;
}

static void *list_add(list_t *list, size_t n) {
	node_t *new_node = (node_t*)xmalloc(sizeof(node_t));
	new_node->next = list->head;
	new_node->data = n;	
	list->head = new_node;
	list->size++;
}

static void list_free(list_t *list) {
	node_t *node = list->head;
	while(node) {
		node = node->next;
		free(node);
	}
	list->head = NULL;
}

