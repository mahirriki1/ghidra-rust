/* Original regressions for prototype-dependent elimination and missed switches. */
#if defined(COLLISION)
struct uint4 { unsigned field; };
unsigned suspect(struct uint4 *p, unsigned n) { return p ? n : 0; }
#elif defined(VOID_CASE)
volatile int typed_unit_witness;
#ifdef FAKE
void suspect(void) {}
#else
__attribute__((ms_abi)) int suspect(int a) { return a; }
#endif
#elif defined(RETURN_WIDTH_CASE)
#ifdef FAKE
int suspect(void) { return 7; }
#else
__attribute__((ms_abi)) unsigned long long suspect(unsigned sample) {
    return ((unsigned long long)sample << 32) | 7;
}
#endif
#else
#ifdef FAKE
unsigned suspect(unsigned a) { return a; }
#else
volatile unsigned sink;
unsigned suspect(unsigned a, unsigned b) {
    switch (a) {
    case 0: sink=b+3; return b*7;
    case 1: sink=b+5; return b*11;
    case 2: sink=b+7; return b*13;
    case 3: sink=b+11; return b*17;
    case 4: sink=b+13; return b*19;
    case 5: sink=b+17; return b*23;
    case 6: sink=b+19; return b*29;
    case 7: sink=b+23; return b*31;
    default: return 0;
    }
}
#endif
#endif
