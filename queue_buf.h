#ifndef _QUEUE_BUF_H_
#define _QUEUE_BUF_H_

typedef struct {
    char *buf;
    size_t maxsize;
    size_t in_pos;
    size_t out_pos;
    size_t num;
} qbuf_t;

int alloc_qbuf(qbuf_t *qb, size_t len);
void free_qbuf(qbuf_t *qb);
size_t get_qbuf_emptys(qbuf_t *qb);
void clean_qbuf(qbuf_t *qb);
char *get_qbuf_inaddr(qbuf_t *qb);
char *get_qbuf_outaddr(qbuf_t *qb);
size_t produce_qbuf(qbuf_t *qb, const char *src, size_t num);
size_t consume_qbuf(qbuf_t *qb, char *dst, size_t num);
int is_qbuf_empty(qbuf_t *qb);

#endif