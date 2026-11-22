/* Original freestanding fixture, independent of host headers and runtimes. */
#ifdef FIXTURE_STDCALL
__attribute__((stdcall))
#endif
__attribute__((noinline)) int fixture_entry(int count) { return count + 7; }
