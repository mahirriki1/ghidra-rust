/* Freestanding Win64 support for the managed caller fixture. Keep the
 * collecting call indirect and observe the fourth argument in the stub. */
unsigned long queue_bias;
static void *volatile collected_cookie;
void *volatile observed_cookie;
static void *volatile timer_state;

static void *collect(void *base, void *cancel, void *notify, void *cookie) {
    (void)cancel;
    (void)notify;
    collected_cookie = cookie;
    return base;
}
void *(*volatile collect_task)(void *, void *, void *, void *) = collect;

int should_discard(void *ticket) { return ticket == 0; }
void dispose_ticket(void *ticket) { collected_cookie = ticket; }
void prepare_queue(void *queue) { timer_state = queue; }
void mark_result(void *timer, const char *description) {
    timer_state = timer;
    collected_cookie = (void *)description;
}
void invalid_state(const char *queue, const char *operation, unsigned line,
                   const char *stage, const char *field) {
    (void)queue;
    (void)operation;
    (void)line;
    (void)stage;
    collected_cookie = (void *)field;
}
void run_queued(void) { timer_state = 0; }
void *make_timer(unsigned delay) {
    (void)delay;
    return (void *)&timer_state;
}
void bind_timer(void *timer, void (*callback)(void), void *context, void *cleanup) {
    (void)timer;
    (void)callback;
    (void)cleanup;
    collected_cookie = context;
}
void attach_timer(void *queue, void *timer) {
    timer_state = queue;
    collected_cookie = timer;
}
