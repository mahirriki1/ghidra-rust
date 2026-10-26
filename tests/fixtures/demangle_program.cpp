// Original linked symbol-name fixture. Analyzed by tests, never executed.
// G++ links it as an ELF executable; MSVC builds a DLL exporting these
// functions under their MSVC-decorated names.
#if defined(_MSC_VER)
#define FIXTURE __declspec(dllexport) __declspec(noinline)
#else
#define FIXTURE __attribute__((noinline))
#endif

namespace demangle_fixture {
FIXTURE int overloaded(int value) { return value + 1; }
FIXTURE double overloaded(double value) { return value + 1.0; }

template <typename T> FIXTURE T identity(T value) { return value; }
template FIXTURE int identity<int>(int);

// Its compact display name ends in "exit"; it returns normally.
FIXTURE int exit(int code) { return code + 2; }
} // namespace demangle_fixture

FIXTURE int main(int argc, char **) {
    int total = demangle_fixture::overloaded(argc);
    total += static_cast<int>(demangle_fixture::overloaded(1.5));
    total += demangle_fixture::identity<int>(argc);
    return demangle_fixture::exit(total);
}
