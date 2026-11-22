/* Original calling-convention regression fixture. No runtime headers needed. */
#if defined(__i386__)
#define STDCALL __attribute__((stdcall))
#define FASTCALL __attribute__((fastcall))
#define REGPARM __attribute__((regparm(3)))
#define MSABI
#else
#define STDCALL
#define FASTCALL
#define REGPARM
#define MSABI __attribute__((ms_abi))
#endif
#define KEEP __attribute__((noinline, used))
KEEP int default_callee(int a, int b) { return a - b * 5; }
KEEP STDCALL int std_callee(int a, int b) { return a - b * 5; }
KEEP FASTCALL int fast_callee(int a, int b) { return a - b * 5; }
KEEP REGPARM int reg_callee(int a, int b, int c) { return a - b * c; }
KEEP MSABI int ms_callee(int a, int b) { return a - b * 5; }
KEEP int fixture_entry(int count) {
    return default_callee(count, 1) + std_callee(count, 2) +
        fast_callee(count, 3) + reg_callee(count, 4, 5) + ms_callee(count, 2);
}
#if defined(__x86_64__)
KEEP __attribute__((sysv_abi)) int sysv_callee(int a, int b) { return a - b * 5; }
#endif
