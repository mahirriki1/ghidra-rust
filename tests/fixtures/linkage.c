/* Original ELF declaration fixture. The test builds but never executes it. */
#include <stdio.h>
extern int optional_hook(void) __attribute__((weak));
int exported_word = 7;
int linkage_export(void) __asm__("_ZN4demo3fooEv");
int linkage_export(void) {
    puts("linkage fixture");
    return optional_hook ? optional_hook() : exported_word;
}
