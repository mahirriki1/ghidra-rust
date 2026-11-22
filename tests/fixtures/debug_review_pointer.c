/* Original fixture: this translation unit names a structure ReviewType; see
   debug_review_scalar.c. */
struct ReviewType {
    int n;
};

__attribute__((noinline)) int review_pointer(struct ReviewType *value)
{
    return value->n + 7;
}
