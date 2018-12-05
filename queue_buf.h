#ifndef _QUEUE_BUF_H_
#define _QUEUE_BUF_H_

typedef struct {
    char *buf;
    size_t maxsize;
    size_t in_pos;
    size_t out_pos;
    size_t num;
} qbuf_t;

int init_qbuf(qbuf_t *qb, size_t len);
size_t get_qbuf_emptys(qbuf_t *qb);
size_t write_qbuf(qbuf_t *qb, const char *src, size_t num);
size_t read_qbuf(qbuf_t *qb, char *dst, size_t num);
int is_qbuf_empty(qbuf_t *qb);
void free_qbuf(qbuf_t *qb);
#endif