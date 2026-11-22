struct reading {
    long data[4];
    int bias;
};

volatile long recorded;

__attribute__((noinline)) int record_reading(struct reading *reading, int index) {
    recorded = reading->data[index & 3] + index;
    return reading->bias * 13 + index * 5;
}
