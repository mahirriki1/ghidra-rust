/* Original no-return fixture. Each `die_*` function ends in a call that never
 * returns, so the next function follows the call directly: following the
 * fallthrough would run into it. `after_abort` is reached only through a
 * function pointer, so stripped builds can recover it only from its own code. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile int sink;

__attribute__((noipa)) void die_exit(int code) {
    sink = code;
    exit(code);
}

__attribute__((noipa)) void die_abort(void) {
    sink = 1;
    abort();
}

__attribute__((noipa)) int after_abort(int value) {
    sink = value;
    return puts("after") + value;
}

__attribute__((noipa)) int checked(int value) {
    if (value > 100) {
        die_exit(2);
    }
    return value * 3;
}

__attribute__((noipa)) int guarded(const char *text) {
    char buffer[32];
    strcpy(buffer, text);
    return (int)strlen(buffer) + buffer[0];
}

int (*volatile hook)(int) = after_abort;

int main(int argc, char **argv) {
    if (argc > 5) {
        die_abort();
    }
    return checked(argc) + hook(argc) + guarded(argv[0]);
}
