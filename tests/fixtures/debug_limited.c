#include <stdlib.h>

volatile int counter = 4;

__attribute__((noinline)) int get_counter(void) { return counter * 3 + 1; }
__attribute__((noinline)) char *pick(void) { return getenv("HOME"); }
__attribute__((noinline)) int ignore_args(int a, int b) {
    (void)a;
    (void)b;
    return counter + 7;
}
