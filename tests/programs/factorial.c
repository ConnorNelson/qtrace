#include <stdlib.h>
#include <stdio.h>


int factorial(int n)
{
    if (n == 0)
        return 1;
    return n * factorial(n - 1);
}


int main(int argc, char **argv)
{
    int n = atoi(argv[1]);
    printf("factorial(%d) = %d\n", n, factorial(n));
}
