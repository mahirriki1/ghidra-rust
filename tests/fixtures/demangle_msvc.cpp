// Original MSVC symbol fixture; compiled to an object and never executed.
namespace demangle_fixture {
namespace inner {
template <typename T> __declspec(noinline) T identity(T value) { return value; }
}
__declspec(noinline) int overloaded(int value) { return value + 1; }
__declspec(noinline) double overloaded(double value) { return value + 2.0; }
namespace {
__declspec(noinline) int hidden(int value) { return value + 3; }
}
struct __declspec(dllexport) Widget {
    Widget();
    virtual ~Widget();
    __declspec(noinline) int operator+(int value) const;
};
Widget::Widget() {}
Widget::~Widget() {}
int Widget::operator+(int value) const { return inner::identity(hidden(value)); }
Widget original_widget;
}
