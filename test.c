#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv) {
	
	puts("Hello\n");
	printf("My pid is %lu\n", getpid());
	pause();
	system("echo Hello from system.");
	return 0;		
}
