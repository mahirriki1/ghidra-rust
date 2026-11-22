#include <stdio.h>
#include <stdlib.h>

struct reading {
    long data[4];
    int bias;
};

int record_reading(struct reading *reading, int index);

int main(int argc, char **argv) {
    struct reading reading = {{0}, atoi(argv[0])};
    record_reading(&reading, argc);
    record_reading(&reading, argc + 9);
    puts("recorded");
    return 0;
}
