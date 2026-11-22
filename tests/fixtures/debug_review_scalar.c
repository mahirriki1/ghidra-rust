/* Original fixture: this translation unit names a scalar typedef ReviewType.
   It is linked with debug_review_pointer.c, whose unit uses the same name
   for a structure, so each render needs its own fresh type factory. */
typedef unsigned int ReviewType;

__attribute__((noinline)) ReviewType review_scalar(ReviewType value)
{
    return value * 3u + 1u;
}
