#include <stdlib.h>
#include <string.h>
#include "queue_buf.h"

static void _fix_qbuf(qbuf_t *qb);

int alloc_qbuf(qbuf_t *qb, size_t len)
{
    char *b;
    
    // len can NOT be 0
    b = malloc(len);
    if (!b) {
        return -1;
    }

    qb->buf = b;
    qb->maxsize = len;
    qb->in_pos = 0;
    qb->out_pos = 0;
    qb->num = 0;
    return 0;
}

size_t get_qbuf_emptys(qbuf_t *qb)
{
    return qb->maxsize - qb->num;
}

void clean_qbuf(qbuf_t *qb)
{
    qb->in_pos = qb->out_pos = 0;
    qb->num = 0;
}
/*
 * Return n numbers of copied char. n will be less than num if the buffer
 * don't have enough space.
 * 
 * qbuf can't be a ring buffer because there would be many interfaces.
 */
size_t produce_qbuf(qbuf_t *qb, const char *src, size_t num)
{
    size_t emptys = get_qbuf_emptys(qb);
    size_t minlen = num < emptys ? num : emptys;

    _fix_qbuf(qb);
    memcpy(qb->buf + qb->in_pos, src, minlen);
    qb->num += minlen;
    qb->in_pos += minlen;
    return minlen; 
}
size_t consume_qbuf(qbuf_t *qb, char *dst, size_t num)
{
    size_t e = get_qbuf_emptys(qb);
    size_t m = num < e ? num : e;

    memcpy(qb->buf + qb->out_pos, dst, m);
    qb->out_pos -= m;
    qb->num -= m;
    _fix_qbuf(qb);
    return m;
}

int is_qbuf_empty(qbuf_t *qb)
{
    return qb->num == qb->maxsize;
}


void free_qbuf(qbuf_t *qb)
{
    free(qb->buf);
    qb->maxsize = 0;
    clean_qbuf(qb);
}

static void _fix_qbuf(qbuf_t *qb)
{
    if (qb->out_pos > 0) {
        for (int i = 0; i < qb->num; i++) {
            qb->buf[i] = qb->buf[qb->out_pos + i];
        }
    }

    qb->in_pos -= qb->out_pos;
    qb->out_pos = 0;
}
char *get_qbuf_inaddr(qbuf_t *qb)
{
    _fix_qbuf(qb);
    return qb->buf + qb->in_pos;
}
char *get_qbuf_outaddr(qbuf_t *qb)
{
    _fix_qbuf(qb);
    return qb->buf;
}