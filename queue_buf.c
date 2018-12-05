#include <stdlib.h>
#include <string.h>
#include "queue_buf.h"

int init_qbuf(qbuf_t *qb, size_t len)
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

/*
 * Return n numbers of copied char. n will be less than num if the buffer
 * don't have enough space.
 */
size_t write_qbuf(qbuf_t *qb, const char *src, size_t num)
{
    size_t emptys = get_qbuf_emptys(qb);
    size_t n = emptys > num? num : emptys;

    if (n == 0) {
        return 0;
    }

    if (qb->in_pos >= qb->out_pos) {
        size_t right_offset = qb->maxsize - qb->in_pos;
        size_t rwriten = right_offset > n ? n : right_offset;
        size_t lwriten = n - rwriten;
        
        memcpy(qb->in_pos, src, rwriten);
        memcpy(qb->buf, src + rwriten, lwriten);
        qb->in_pos = (qb->in_pos + n) % qb->maxsize;
    } else {
        memcpy(qb->in_pos, src, n);
        qb->in_pos += n;
    }
    qb->num += n;
    return n;
}

size_t read_qbuf(qbuf_t *qb, char *dst, size_t num)
{
    size_t n = num > qb->num ? qb->num : num;

    if (n == 0) {
        return 0;
    }

    if (qb->in_pos >= qb->out_pos) {
        memcpy(dst, qb->out_pos, n);
        qb->out_pos += n;
    } else {
        size_t right_offset = qb->maxsize - qb->out_pos;
        size_t rreadn = right_offset > n ? n : right_offset;
        size_t lreadn = n - rreadn;

        memcpy(dst, qb->out_pos, rreadn);
        memcpy(dst + rreadn, qb->buf, lreadn);
        qb->out_pos = (qb->out_pos + n) % qb->maxsize;
    }
    qb->num -= n;
    return n;
}
int is_qbuf_empty(qbuf_t *qb)
{
    return qb->num == qb->maxsize;
}


void free_qbuf(qbuf_t *qb)
{
    free(qb->buf);
}