#include "stdio.h"

typedef struct test {
    int a;
    short b;
    unsigned char c;
    char d;
} test;

test global_var = { 1, 2, 3, -1 };

int main()
{

    global_var.d *= 10; 

    printf("global_var is: %d\n", global_var.d);

    return 0;
}
