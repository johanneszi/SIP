#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void a();
void b();
void c();
void d();
void e();

void InterestingProcedure() {
    printf("\t This is an interesting procedure\n");
}

void print(char* message) {
    InterestingProcedure();
    printf("%s\n", message);
}

void a() {
    b();
}

void b() {
    c();
}

void c() {
    d();
}

void d() {
    e();
}

void e() {
    print("\t Not an interesting procedure");
}

int main(int argc, char** argv) {
    char inp[8];
    InterestingProcedure();
    a();
    gets(inp);
    return 0;
}
