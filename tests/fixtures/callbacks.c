/* Original pattern fixture. The callbacks are reached only through a table of
 * function pointers, so no direct call names them; `scaled` is called only
 * from a callback. Stripped builds must recover them from code alone. */
volatile int sink;

__attribute__((noipa)) int scaled(int value, int factor) {
    sink = value;
    return value * factor + 3;
}

__attribute__((noipa)) int keep_across_call(int value) {
    int kept = value * 7;
    int result = scaled(value, 5);
    return result + kept;
}

__attribute__((noipa)) int with_locals(int value) {
    int values[16];
    for (int index = 0; index < 16; index++) {
        values[index] = value + index * sink;
    }
    return values[value & 15] + values[3];
}

__attribute__((noipa)) int two_calls(int value) {
    int first = scaled(value, 2);
    int second = scaled(first, 3);
    return first - second;
}

__attribute__((noipa)) int leaf(int value) {
    return value ^ 0x55;
}

int (*const callbacks[])(int) = {keep_across_call, with_locals, two_calls, leaf};

int main(int argc, char **argv) {
    (void)argv;
    int total = 0;
    for (unsigned index = 0; index < sizeof callbacks / sizeof *callbacks; index++) {
        total += callbacks[index](argc + (int)index);
    }
    return total & 0x7f;
}
