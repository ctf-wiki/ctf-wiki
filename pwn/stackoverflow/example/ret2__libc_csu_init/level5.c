#undef _FORTIFY_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function() {
	char buf[128];
	read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
	write(STDOUT_FILENO, "Hello, World\n", 13);
	vulnerable_function();
}

