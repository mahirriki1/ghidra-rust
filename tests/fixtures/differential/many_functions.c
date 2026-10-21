/* Original differential-benchmark source: 300 distinct functions reachable only
 * through a retained pointer table. Stripped builds therefore test function
 * recovery without direct calls or symbols. This is analyzed, never executed. */

#define BENCH_NOINLINE __attribute__((noinline))

/* The leading 1 keeps every constant decimal (e.g. 1089, not octal 089). */
#define BENCH_MANY(n)                                                         \
    BENCH_NOINLINE unsigned bench_many_##n(unsigned x) {                      \
        return (x * (1##n##u + 3u)) ^ (x >> (1##n##u % 7u)) ^ 1##n##u;        \
    }
#define BENCH_MANY10(d)                                                       \
    BENCH_MANY(d##0) BENCH_MANY(d##1) BENCH_MANY(d##2) BENCH_MANY(d##3)       \
    BENCH_MANY(d##4) BENCH_MANY(d##5) BENCH_MANY(d##6) BENCH_MANY(d##7)       \
    BENCH_MANY(d##8) BENCH_MANY(d##9)
#define BENCH_MANY100(h)                                                      \
    BENCH_MANY10(h##0) BENCH_MANY10(h##1) BENCH_MANY10(h##2)                  \
    BENCH_MANY10(h##3) BENCH_MANY10(h##4) BENCH_MANY10(h##5)                  \
    BENCH_MANY10(h##6) BENCH_MANY10(h##7) BENCH_MANY10(h##8)                  \
    BENCH_MANY10(h##9)

BENCH_MANY100(0)
BENCH_MANY100(1)
BENCH_MANY100(2)

#define BENCH_ENTRY(n) bench_many_##n,
#define BENCH_ENTRY10(d)                                                      \
    BENCH_ENTRY(d##0) BENCH_ENTRY(d##1) BENCH_ENTRY(d##2) BENCH_ENTRY(d##3)   \
    BENCH_ENTRY(d##4) BENCH_ENTRY(d##5) BENCH_ENTRY(d##6) BENCH_ENTRY(d##7)   \
    BENCH_ENTRY(d##8) BENCH_ENTRY(d##9)
#define BENCH_ENTRY100(h)                                                     \
    BENCH_ENTRY10(h##0) BENCH_ENTRY10(h##1) BENCH_ENTRY10(h##2)               \
    BENCH_ENTRY10(h##3) BENCH_ENTRY10(h##4) BENCH_ENTRY10(h##5)               \
    BENCH_ENTRY10(h##6) BENCH_ENTRY10(h##7) BENCH_ENTRY10(h##8)               \
    BENCH_ENTRY10(h##9)

unsigned (*const bench_many_table[300])(unsigned) = {
    BENCH_ENTRY100(0) BENCH_ENTRY100(1) BENCH_ENTRY100(2)
};

BENCH_NOINLINE unsigned bench_many_dispatch(unsigned index, unsigned x) {
    return bench_many_table[index % 300u](x);
}
