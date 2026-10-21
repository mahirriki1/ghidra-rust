/* Original switch fixture. `case_only` is reached solely from one case of a
 * dense switch, which optimizing compilers emit as a jump table; `computed`
 * tail-jumps through an unknown function pointer. */
volatile int sink;

__attribute__((noipa)) int case_only(int value) {
    sink = value;
    return value * 3 + 1;
}

__attribute__((noipa)) int other(int value) {
    sink = -value;
    return value - 7;
}

__attribute__((noipa)) int dense(int value) {
    switch (value) {
    case 0: return case_only(value) + 5;
    case 1: sink = 1; return 9;
    case 2: return other(value) * 2;
    case 3: return 17;
    case 4: return sink * 3;
    case 5: return 23;
    case 6: return 29;
    default: return -1;
    }
}

__attribute__((noipa)) int computed(int (*function)(int), int value) {
    return function(value);
}

int main(int argc, char **argv) {
    (void)argv;
    return dense(argc) + computed(other, argc);
}
