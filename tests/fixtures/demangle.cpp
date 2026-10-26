// Original symbol-name fixture. Compiled to an object file, never executed.
namespace demangle_fixture {
int overloaded(int value) { return value + 1; }
double overloaded(double value) { return value + 1.0; }

template <typename T> T identity(T value) { return value; }
template int identity<int>(int);
} // namespace demangle_fixture
