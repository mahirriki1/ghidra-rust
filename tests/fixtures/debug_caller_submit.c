/* Caller translation unit, compiled without debug info. Its forwarded fifth
 * argument reaches an unrelated indirect call before the direct call to a
 * callee whose prototype comes from the other unit's DWARF. */
typedef unsigned long W;
struct Queue { W status; void *ticket; };
extern W queue_bias;
#ifdef _WIN32
extern void *(*volatile collect_task)(void *,void *,void *,void *);
extern void *volatile observed_cookie;
#else
extern void *collect_task(void *,void *,void *,void *);
#endif
extern int should_discard(void *);
extern void dispose_ticket(void *);
extern void prepare_queue(void *);
extern void mark_result(void *, const char *);
extern void invalid_state(const char *, const char *, unsigned, const char *, const char *);
extern void run_queued(void);
#ifndef _WIN32
__attribute__((visibility("hidden")))
#endif
extern void *sample_schedule(void *,unsigned,void(*)(void),void *,void *);
void sample_entry(void *base, int priority, void *cancel, void *notify, void *cookie) {
    struct Queue *q=(struct Queue*)((char*)base+queue_bias);
    if (q->status) { invalid_state("q","submit",73,"start","status"); return; }
    if (q->ticket) { invalid_state("q","submit",74,"start","ticket"); return; }
    void *t=collect_task(base,cancel,notify,cookie);
#ifdef _WIN32
    /* The fifth Win64 formal has an independent use as well as forwarding. */
    observed_cookie=cookie;
#endif
    if (should_discard(t)) { if(t) dispose_ticket(t); return; }
    q->ticket=t;
    q->status=1;
    prepare_queue(base);
    mark_result(sample_schedule(base,0,run_queued,0,0),"queued");
}
void * volatile last_ticket;
void *sample_entry_positive(void *queue) {
    void *t = sample_schedule(queue, 9, run_queued, 0, 0);
    last_ticket = t;
    return t;
}
