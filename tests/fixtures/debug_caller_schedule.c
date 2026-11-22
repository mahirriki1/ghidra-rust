/* Callee translation unit, compiled with debug info. */
extern void *make_timer(unsigned);
extern void bind_timer(void *, void (*)(void),void *,void *);
extern void attach_timer(void *,void *);
#ifdef _WIN32
__declspec(noinline)
#else
__attribute__((noinline,visibility("hidden")))
#endif
void *sample_schedule(void *queue,unsigned delay,void(*callback)(void),void *context, void *cleanup) {
    void *timer=make_timer(delay);
    bind_timer(timer,callback,context,cleanup);
    attach_timer(queue,timer);
    return timer;
}
