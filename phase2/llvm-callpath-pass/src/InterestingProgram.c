#include <stdio.h>

void InterestingProcedure() {
    printf("\t This is an interesting procedure\n");
}

void print(char *message) {
	InterestingProcedure();
    printf("%s\n", message);
}

int main() {
    printf("Hello, world!\n");
	print("Nachricht");
    int i; 
    for (i = 0; i < 10; i++)
        InterestingProcedure();

    return 0;
}

