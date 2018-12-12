#ifndef _LISOD_H_
#define _LISOD_H_

#include <errno.h>
#include <sys/select.h>
#include <openssl/ssl.h>
#include "request.h"
#include "queue_buf.h"
#include "parse.h"

#define NO_TEMP_FAILURE(stmt)                     \
    while ((stmt) == -1 && errno == EINTR); // loop when interrupted by signal

#define SERVER_VERSION "liso/1.0"
#define MAX_CLIENTS \
    ((FD_SETSIZE - 2) / 4) // leave 2 select-fd for HTTP and HTTPS ports. And each client will select 4 fds.



typedef enum {
    HTTP_TYPE,
    HTTPS_TYPE
} http_t;

typedef struct {
    http_t type;
    SSL *client_context;
    int sockfd;   // (-1) when this client doesn't exist

    int need_close;

    parse_fsm_t pfsm; // buffer used for receving pipelined request
    Request request; // the current parsed request
} http_client_t;

typedef struct {
    int maxfd;

    fd_set read_set;
    fd_set write_set;
    fd_set wready_set;
    fd_set rready_set;

    int nready;
    int maxci;

    SSL_CTX *ssl_ctx;
    
    int httpfd;
    int httpsfd;
    http_client_t clients[MAX_CLIENTS];
} client_pool_t;

int nb_read_fd(int fd, void* buf, size_t len);
int nb_read_ssl(SSL *s, void* buf, size_t len);
int nb_write_fd(int fd, void* buf, size_t len);
int nb_write_ssl(SSL *s, void* buf, size_t len);
#endif