#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv) {
	
	puts("Hello\n");
	printf("My pid is %lu\n", getpid());
	
	while(1) {
		puts("Yet another printf\n");
		sleep(5);
	}
	system("echo Hello from system.");
	return 0;		
}
