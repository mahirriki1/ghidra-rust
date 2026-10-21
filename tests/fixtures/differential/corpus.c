/* Original differential-benchmark source exercising common analysis cases:
 * jump tables, indirect and tail calls, no-return calls, recursion, static
 * helpers, globals and strings. Built only for analysis; never executed. */
#include <stdlib.h>
#include <string.h>

#define BENCH_NOINLINE __attribute__((noinline))

unsigned bench_many_dispatch(unsigned index, unsigned x);

volatile unsigned bench_global_counter;
unsigned bench_global_array[16];
const char *volatile bench_last_message;

BENCH_NOINLINE unsigned bench_global_read(void) { return bench_global_counter; }

BENCH_NOINLINE void bench_global_write(unsigned value) {
    bench_global_counter = value;
}

BENCH_NOINLINE unsigned bench_array_update(unsigned index, unsigned value) {
    bench_global_array[index & 15u] += value;
    return bench_global_array[(index + 1u) & 15u];
}

BENCH_NOINLINE unsigned bench_dense_switch(unsigned selector, unsigned x) {
    switch (selector) {
    case 0: return x + 11u;
    case 1: return x * 3u;
    case 2: return x ^ 0x5a5au;
    case 3: return bench_global_read() + x;
    case 4: return x << 3;
    case 5: return x - 7u;
    case 6: return bench_array_update(x, 6u);
    case 7: return x | 0x80u;
    case 8: return (x >> 2) + 9u;
    default: return 0;
    }
}

BENCH_NOINLINE unsigned bench_sparse_switch(unsigned selector) {
    switch (selector) {
    case 3: return 30u;
    case 100: return 1000u;
    case 2048: return 7u;
    case 65537: return 12u;
    default: return 1u;
    }
}

typedef unsigned (*bench_operation)(unsigned);

static BENCH_NOINLINE unsigned bench_static_mix(unsigned x) {
    return (x * 2654435761u) ^ (x >> 13);
}

static BENCH_NOINLINE unsigned bench_static_negate(unsigned x) { return ~x; }

volatile bench_operation bench_selected_operation = bench_static_mix;

BENCH_NOINLINE unsigned bench_indirect_call(unsigned x) {
    if (x & 1u) {
        bench_selected_operation = bench_static_negate;
    }
    return bench_selected_operation(x);
}

static BENCH_NOINLINE unsigned bench_static_dispatch(unsigned x) {
    return bench_static_mix(x) + bench_static_negate(x);
}

BENCH_NOINLINE unsigned bench_tail_leaf(unsigned x, unsigned y) {
    return (x ^ y) * 31u + bench_global_read();
}

BENCH_NOINLINE unsigned bench_tail_wrapper(unsigned x) {
    return bench_tail_leaf(x + 1u, x);
}

BENCH_NOINLINE _Noreturn void bench_custom_die(const char *message) {
    bench_last_message = message;
    abort();
}

BENCH_NOINLINE _Noreturn void bench_exit(int code) { exit(code); }

BENCH_NOINLINE _Noreturn void bench_abort(void) { abort(); }

BENCH_NOINLINE unsigned bench_after_noreturn(unsigned x) {
    if (x == 0xdeadu) {
        bench_custom_die("bench: invalid sentinel");
    }
    if (x == 0xbeefu) {
        bench_exit(3);
    }
    return x * 5u + 1u;
}

BENCH_NOINLINE unsigned bench_recursive(unsigned n) {
    if (n < 2u) {
        return n;
    }
    return bench_recursive(n - 1u) + bench_recursive(n - 2u) + 1u;
}

BENCH_NOINLINE int bench_odd(unsigned n);

BENCH_NOINLINE int bench_even(unsigned n) {
    if (n == 0u) {
        return 1;
    }
    int result = bench_odd(n - 1u);
    bench_global_counter += 1u;
    return result;
}

BENCH_NOINLINE int bench_odd(unsigned n) {
    if (n == 0u) {
        return 0;
    }
    int result = bench_even(n - 1u);
    bench_global_counter += 2u;
    return result;
}

BENCH_NOINLINE const char *bench_string_select(unsigned x) {
    if (x % 3u == 0u) {
        return "bench: first differential string";
    }
    if (x % 3u == 1u) {
        return "bench: second differential string";
    }
    return "bench: third differential string";
}

int main(int argc, char **argv) {
    unsigned x = (unsigned)argc;
    if (argc > 5) {
        bench_abort();
    }
    x += bench_dense_switch(x % 10u, x);
    x += bench_sparse_switch(x);
    x += bench_indirect_call(x);
    x += bench_static_dispatch(x);
    x += bench_tail_wrapper(x);
    x += bench_after_noreturn(x);
    x += bench_recursive(x & 7u);
    x += (unsigned)bench_even(x & 15u);
    x += (unsigned)strlen(bench_string_select(x));
    x += bench_many_dispatch(x, (unsigned)strlen(argv[0]));
    bench_global_write(x);
    return (int)(bench_global_read() & 0x7fu);
}
