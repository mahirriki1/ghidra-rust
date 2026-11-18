/* Original fixture for local GDB sessions. */
#include <unistd.h>
#include <stdio.h>

volatile unsigned int debugger_counter;

__attribute__((noinline)) void debug_point(int pid) {
    debugger_counter += pid != 0;
}

int main(void) {
    debug_point(getpid());
#ifdef DEBUGGER_REEXEC
    execl("/usr/bin/true", "true", (char *)NULL);
#else
    puts("*stopped,reason=target-output");
    sleep(1);
    debug_point(getpid());
#endif
    return 19;
}
