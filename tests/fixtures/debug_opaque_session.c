/* Original regression source: named structure pointers in a DWARF prototype. */
typedef struct blob {
    int length;
    int type;
    unsigned char *data;
    long flags;
} BLOB;

typedef struct record {
    unsigned int version;
    int protocol;
    BLOB *fields[12];
    long lifetime;
    BLOB *protocols;
} RECORD;

typedef struct session {
    int protocol;
    unsigned long key_length;
    unsigned char key[256];
    long counters[11];
    unsigned char *ticket;
    unsigned long ticket_length;
    unsigned char *protocols;
    unsigned long protocols_length;
} SESSION;

extern RECORD *parse_record(RECORD **out, const unsigned char **cursor, long length);
extern SESSION *session_new(void);
extern void *duplicate(const void *data, unsigned long length);
extern void report(int library, int function, int reason, const char *file, int line);

SESSION *decode_session(SESSION **existing, const unsigned char **cursor, long length)
{
    const unsigned char *position = *cursor;
    RECORD *record = parse_record(0, &position, length);
    SESSION *session = 0;
    if (!existing || !*existing) {
        session = session_new();
        if (session == 0)
            return 0;
    } else {
        session = *existing;
    }
    if (record->version != 1) {
        report(20, 103, 254, "session.c", 1);
        return 0;
    }
    session->protocol = record->protocol;
    if (record->protocols) {
        session->protocols = duplicate(record->protocols->data, record->protocols->length);
        if (session->protocols == 0)
            return 0;
        session->protocols_length = record->protocols->length;
    } else {
        session->protocols = 0;
        session->protocols_length = 0;
    }
    *cursor = position;
    return session;
}
