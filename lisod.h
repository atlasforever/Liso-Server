#ifndef _LISOD_H_
#define _LISOD_H_

#include <errno.h>
#include <openssl/ssl.h>
#include "request.h"
#include "queue_buf.h"
#include "parse.h"

#define NO_TEMP_FAILURE(stmt)                     \
    while ((stmt) == -1 && errno == EINTR); // loop when interrupted by signal

#define SERVER_VERSION "liso/1.0"



typedef enum {
    HTTP_TYPE,
    HTTPS_TYPE
} http_t;

typedef struct {
    http_t type;
    SSL *client_context;
    int sockfd;   // (-1) when this client doesn't exist

    qbuf_t *rbuf; // used for reading requests
    qbuf_t *wbuf; // used for writing responses

    parse_fsm_t pfsm; // buffer used for receving pipelined request
    Request request; // the current parsed request

    int need_close;
} http_client_t;

int liso_nb_recv(http_client_t *c, void* buf, size_t len);
int liso_nb_send(http_client_t *c, void* buf, size_t len);
#endif