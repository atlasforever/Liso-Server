/******************************************************************************
 * echo_server.c                                                               *
 *                                                                             *
 * Description: This file contains the C source code for an echo server.  The  *
 *              server runs on a hard-coded port and simply write back anything*
 *              sent to it by connected clients.  It does not support          *
 *              concurrent clients.                                            *
 *                                                                             *
 * Authors: Athula Balachandran <abalacha@cs.cmu.edu>,                         *
 *          Wolf Richter <wolf@cs.cmu.edu>                                     *
 *                                                                             *
 *******************************************************************************/

#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include "lisod.h"
#include "http_common.h"
#include "log.h"
#include "parse.h"
#include "request.h"


/* Command line arguments */
static in_port_t http_port;
static in_port_t https_port;
static char* log_file;
static char* lock_file;
char* www_folder;
static char* cgi_path;
static char* private_key_file;
static char* cert_file;


client_pool_t pool;

/* Declarations */
static void liso_shutdown(int status);
int daemonize(char* lock_file);


int close_socket(int sock)
{
    if (close(sock)) {
        log_error("Failed closing socket.");
        return 1;
    }
    return 0;
}

static void init_pool(int httpfd, int httpsfd, client_pool_t* p)
{
    /* no clients initially */
    p->maxci = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        p->clients[i].sockfd = -1;
        p->clients[i].type = HTTP_TYPE;
    }

    p->maxfd = httpfd > httpsfd ? httpfd : httpsfd;
    p->httpfd = httpfd;
    p->httpsfd = httpsfd;
    FD_ZERO(&(p->read_set));
    FD_SET(httpfd, &(p->read_set));
    FD_SET(httpsfd, &(p->read_set));
}

static int init_ssl(const char *key, const char *cert, client_pool_t *p)
{
    SSL_load_error_strings();
    SSL_library_init();

    /* we want to use TLSv1 only */
    if ((p->ssl_ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
        log_error("Error creating SSL context.");
        return -1;
    }

    /* register private key */
    if (SSL_CTX_use_PrivateKey_file(p->ssl_ctx, key, SSL_FILETYPE_PEM) == 0) {
        SSL_CTX_free(p->ssl_ctx);
        log_error("Error associating private key.");
        return -1;
    }

    /* register public key (certificate) */
    if (SSL_CTX_use_certificate_file(p->ssl_ctx, cert, SSL_FILETYPE_PEM) == 0) {
        SSL_CTX_free(p->ssl_ctx);
        log_error("Error associating certificate.");
        return -1;
    }

    return 0;
}

/*
 * Add a client to the pool. It's a HTTP client if ctx is NULL, otherwise HTTPS.
 */
int add_client(int clientfd, SSL* ctx, client_pool_t* p)
{
    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (p->clients[i].sockfd == -1) {
            p->clients[i].sockfd = clientfd;
            p->clients[i].type = ctx? HTTPS_TYPE : HTTP_TYPE;
            p->clients[i].client_context = ctx;
            p->clients[i].need_close = 0; // Persistent connection
            // initialize for persistent connection
            init_parse_fsm(&(p->clients[i].pfsm));
            if (init_request(&(p->clients[i].request)) == -1) {
                p->clients[i].sockfd = -1;
                log_error("init_request() failed");
                return -1;
            }

            FD_SET(clientfd, &(p->read_set));
            FD_SET(clientfd, &(p->write_set));
            if (i > p->maxci) {
                p->maxci = i;
            }
            if (clientfd > p->maxfd) {
                p->maxfd = clientfd;
            }
            log_info("Add a new client fd:%d", clientfd);
            return 0;
        }
    }

    log_info("add_client() failed: Too many clients");
    return -1;
}

int max(int a, int b)
{
    return a > b ? a : b;
}
int min(int a, int b)
{
    return a < b ? a : b;
}
static void update_rmed_maxci(client_pool_t* p)
{
    int maxi = -1;

    for (int i = 0; i < p->maxci; i++) {
        if (p->clients[i].sockfd != -1) {
            maxi = i;
        }
    }
    p->maxci = maxi;
}
static void update_rmed_maxfd(client_pool_t* p)
{
    int maxfd = p->httpfd > p->httpsfd ? p->httpfd : p->httpsfd;

    for (int i = 0; i <= p->maxci; i++) {
        if (p->clients[i].sockfd != -1) {
            int v = max(p->clients[i].sockfd,
                        max(p->clients[i].request.rfd, p->clients[i].request.wfd));
            if (v > maxfd) {
                maxfd = v;
            }
        }
    }
    p->maxfd = maxfd;
}

void remove_client(int old_idx, client_pool_t* p)
{
    if (p->clients[old_idx].sockfd == -1) {
        return;
    }

    http_client_t *c = &(p->clients[old_idx]);
    int cfd = c->sockfd;
    int rfd = c->request.rfd;
    int wfd = c->request.wfd;

    log_info("Remove one client, fd is %d", cfd);

    if (rfd != -1) {
        FD_CLR(rfd, &p->read_set);
    }
    if (wfd != -1) {
        FD_CLR(wfd, &p->write_set);
    }
    close_socket(cfd);
    FD_CLR(cfd, &p->read_set);
    FD_CLR(cfd, &p->write_set);
    c->sockfd = -1;

    reset_request(&(c->request));

    if (c->client_context) {
        SSL_free(c->client_context);
    }

    
    if (p->maxci == old_idx) {
        update_rmed_maxci(p);
    }

    if (p->maxfd == cfd || p->maxfd == rfd || p->maxfd == wfd) {
        update_rmed_maxfd(p);
    }
}


static int proc_cmd_line_args(int argc, char* argv[])
{
    if (argc != 9) {
        return -1;
    }
    /* wrong if atoi error or the number itself is 0 */
    if ((http_port = (in_port_t)atoi(argv[1])) == 0) {
        return -1;
    }
    if ((https_port = (in_port_t)atoi(argv[2])) == 0) {
        return -1;
    }
    log_file = argv[3];
    lock_file = argv[4];
    www_folder = argv[5];
    cgi_path = argv[6];
    private_key_file = argv[7];
    cert_file = argv[8];

    return 0;
}

static int open_listenfd(int port)
{
    int sock;
    struct sockaddr_in addr;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        log_error("socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    /* servers bind sockets to ports---notify the OS they accept connections */
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
        close_socket(sock);
        log_error("bind, errno is %d", errno);
        return -1;
    }

    if (listen(sock, 1024)) {
        close_socket(sock);
        log_error("listen");
        return -1;
    }
    return sock;
}

/* 
 * return client sock.
 * on error, return -1 
 */
static int proc_http_conn(int fd)
{
    int client_sock;

    NO_TEMP_FAILURE(client_sock = accept(fd, NULL, NULL));
    if (client_sock == -1) {
        log_error("accept, errno is %d", errno);
        return -1;
    }

    int flags = fcntl(client_sock, F_GETFL);
    if (flags == -1) {
        log_error("fcntl F_GETFL error");
        close_socket(client_sock);
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(client_sock, F_SETFL, flags) == -1) {
        log_error("fcntl F_SETFL error");
        close_socket(client_sock);
        return -1;
    }
    return client_sock;
}

/* 
 * return client SSL context.
 * on error, return NULL 
 */
static SSL* proc_https_conn(int lisntenfd, client_pool_t *p)
{
    SSL *client_context = NULL;
    int client_sock;

    client_sock = proc_http_conn(lisntenfd);
    if (client_sock == -1) {
        return NULL;
    }

    if ((client_context = SSL_new(p->ssl_ctx)) == NULL) {
        close_socket(client_sock);
        log_error("Error creating client SSL context.");
        return NULL;
    }
    if (SSL_set_fd(client_context, client_sock) == 0) {
        close_socket(client_sock);
        SSL_free(client_context);
        log_error("Error creating client SSL context.");
        return NULL;
    }
    if (SSL_accept(client_context) <= 0) {
        close_socket(client_sock);
        SSL_free(client_context);
        log_error("Error accepting (handshake) client SSL context.");
        return NULL;
    }
    return client_context;
}

static void liso_shutdown(int status)
{
    log_info("Liso Shutdown");
    if (pool.httpfd != -1) {
        close_socket(pool.httpfd);
    }
    if (pool.httpsfd != -1) {
        close_socket(pool.httpsfd);
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (pool.clients[i].sockfd != -1) {
            remove_client(i, &pool);
        }
    }
    close_log();
    exit(status);
}


/*
 * Non-blocking IO functions for HTTP or HTTPS connection.
 * 
 * They return number of bytes transferred(You shouldn't pass 0 as len). -1 on error. 0 on connection closed.
 * -2 indicates that this function should be called again later. (EAGAIN)
 */
int nb_recv_fd(int fd, void* buf, size_t len)
{
    int rn = 0;

    if (len == 0) {
        return -2;
    }
    NO_TEMP_FAILURE((rn = recv(fd, buf, len, MSG_DONTWAIT)));
    if (rn == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -2;
        } else {
            return -1;
        }
    } else if (rn == 0) {
        return 0;
    }
    return rn;
}
int nb_recv_ssl(SSL *s, void* buf, size_t len)
{
    int rn;

    if (len == 0) {
        return -2;
    }
    rn = SSL_read(s, buf, len);
    if (rn <= 0) {
        int err = SSL_get_error(s, rn);
        switch (err) {
        case SSL_ERROR_ZERO_RETURN:
            return 0;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return -2;
        default:
            return -1;
        }
    }
    return rn;
}
int nb_send_fd(int fd, void* buf, size_t len)
{
    int sn = 0;

    if (len == 0) {
        return -2;
    }
    NO_TEMP_FAILURE((sn = send(fd, buf, len, MSG_DONTWAIT)));
    if (sn == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -2;
        } else {
            return -1;
        }
    } else if (sn == 0) {
        return 0;
    }
    return sn;
}
int nb_send_ssl(SSL *s, void* buf, size_t len)
{
    int sn = 0;

    if (len == 0) {
        return -2;
    }
    sn = SSL_write(s, buf, len);
    if (sn <= 0) {
        int err = SSL_get_error(s, sn);
        switch (err) {
        case SSL_ERROR_ZERO_RETURN:
            return 0;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return -2;
        default:
            return -1;
        }
    }
    return sn;
}

/*
 * -1 on connection error. 0 on discard completed. 1 on not yet completed 
 */
void discard_req_body(http_client_t *c)
{
    clean_qbuf(c->request.readbuf);
}

/*
 * 0 on ok. -1 on connection closed. -2 on read errors. 
 */
int get_partial_req_body(http_client_t *c)
{
    Request *r = &(c->request);
    size_t emptys = get_qbuf_emptys(r->readbuf);
    size_t len = min(emptys, r->content_length);
    int rn;

    // nothing to read
    if (len == 0) {
        return 0;
    }
    
    if (c->type == HTTP_TYPE) {
        rn = nb_recv_fd(c->sockfd, get_qbuf_inaddr(r->readbuf), len);
    } else {
        rn = nb_recv_ssl(c->client_context, get_qbuf_inaddr(r->readbuf), len);
    }
    
    if (rn == -2) {
        return 0;
    } else if (rn == -1) {
        return -2;
    } else if (rn == 0) {
        return -1;
    }
    r->content_length -= rn;
    r->readbuf->num += rn;
    r->readbuf->in_pos += rn;
    return 0;
}
/*
 * 0 on ok. -1 on pipe closed(CGI itself shouldn't close). -2 on write errors.
 */
int partial_body_to_cgi(http_client_t *c)
{
    Request *r = &(c->request);
    size_t n = r->readbuf->num;
    int wn;

    if (n == 0) {
        return 0;
    }

    wn = nb_send_fd(r->wfd, get_qbuf_outaddr(r->readbuf), n);
    if (wn == -2) {
        return 0;
    } else if (wn == -1) {
        return -2;
    } else if (wn == 0) {
        return -1;
    }
    r->readbuf->num -= wn;
    r->readbuf->out_pos += wn;
    return 0;
}


/**
 * internal signal handler
 */
void signal_handler(int sig)
{
    switch (sig) {
    case SIGHUP:
        /* rehash the server */
        break;
    case SIGTERM:
        /* finalize and shutdown the server */
        // TODO: liso_shutdown(NULL, EXIT_SUCCESS);
        liso_shutdown(EXIT_SUCCESS);
        break;
    default:
        break;
        /* unhandled signal */
    }
}

/** 
 * internal function daemonizing the process
 */
int daemonize(char* lock_file)
{
    /* drop to having init() as parent */
    int i, lfp, pid = fork();
    char str[256] = { 0 };
    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);

    setsid();

    for (i = getdtablesize(); i >= 0; i--)
        close(i);

    i = open("/dev/null", O_RDWR);
    dup(i); /* stdout */
    dup(i); /* stderr */
    umask(027);

    lfp = open(lock_file, O_RDWR | O_CREAT, 0640);

    if (lfp < 0)
        exit(EXIT_FAILURE); /* can not open */

    if (lockf(lfp, F_TLOCK, 0) < 0)
        exit(EXIT_SUCCESS); /* can not lock */

    /* only first instance continues */
    sprintf(str, "%d\n", getpid());
    write(lfp, str, strlen(str)); /* record pid to lockfile */

    signal(SIGCHLD, SIG_IGN); /* child terminate signal */

    signal(SIGHUP, signal_handler); /* hangup signal */
    signal(SIGTERM, signal_handler); /* software termination signal from kill */

    // TODO: log --> "Successfully daemonized lisod process, pid %d."

    return EXIT_SUCCESS;
}




void proc_clients(client_pool_t* p)
{
    ssize_t rn;
    int ret;

    for (int i = 0; (i <= p->maxci) && (p->nready > 0); i++) {
        http_client_t *cl = &(p->clients[i]);
        int connfd = cl->sockfd;

        /* ready to read */
        if ((connfd > 0) && (FD_ISSET(connfd, &(p->rready_set)))) {
            p->nready--;
            rn = recv_one_request(&(p->clients[i]));
            if (rn == -1) {
                response_error(HTTP_BAD_REQUEST, connfd);
                remove_client(i, p);
            } else if (rn == 0) {
                log_debug("continue");
                continue;
            } else { // OK
                Request* request = alloc_request();
                p->clients[i].request = request;
                if (!request) {
                    log_error("alloc_request() failed");
                    if (response_error(HTTP_INTERNAL_SERVER_ERROR, connfd) == -1) {
                        log_error("Failed to send error response to sock %d", connfd);
                    }
                    remove_client(i, p);
                    continue;
                }

                ret = parse(p->clients[i].pfsm.buf, rn, request);
                log_debug("parse() return %d", ret);
                if (ret == 0) { // success
                    ret = do_request(request, connfd);
                    log_debug("do_request return %d", ret);
                    if (ret != 0) {
                        remove_client(i, p);
                    }
                } else { // error parsing
                    if (response_error(HTTP_BAD_REQUEST, connfd) == -1) {
                        log_error("Failed to send error response to sock %d", connfd);
                        remove_client(i, p);
                    }
                }
                free_request(request);
            }
        }




        if (connfd == -1) {
            continue;
        }
        switch (cl->request.states) {
        case READ_REQ_HEADERS:

            // When there is a error, just send a response and close this connection.
            // So don't care about body.
            if (FD_ISSET(connfd, &(p->rready_set))) {
                p->nready--;
                int rn;

                rn = recv_one_request(cl);
                if (rn == 0) {
                    log_debug("Read the rest part next time");
                    // continue;
                } else if (rn == -1) {
                    cl->need_close = 1;
                    response_error(HTTP_BAD_REQUEST, &(cl->request));
                    cl->request.states = SEND_STATIC_HEADERS;
                } else { // received a request
                    int parse_r = parse(cl->pfsm.buf, rn, &(cl->request));
                    log_debug("parse() return %d", parse_r);

                    if (parse_r == 0) {
                        // A parsed request. Handle request line and headers
                        int do_ret = do_request(&(cl->request));
                        if (do_ret >= 0) {
                            cl->request.states = WAIT_REQ_BODY;
                            if (do_ret == 1) {
                                cl->need_close = 1;
                            }
                        } else {
                            response_error(-do_ret, &(cl->request));
                            cl->request.states = SEND_STATIC_HEADERS;
                            cl->need_close = 1;
                        }
                    } else {
                        response_error(HTTP_BAD_REQUEST, &(cl->request));
                        cl->request.states = SEND_STATIC_HEADERS;
                        cl->need_close = 1;
                    }
                }
            }
            break;
        case WAIT_REQ_BODY:
            // No message body to read or to send
            if (cl->request.content_length == 0 && cl->request.readbuf->num == 0) {
                cl->request.states = SEND_STATIC_HEADERS;
            }

            if (cl->request.content_length > 0 && FD_ISSET(connfd, &p->rready_set)) {
                p->nready--;
                if (get_partial_req_body(cl) < 0) {
                    // Don't allow client close before we send response.
                    cl->need_close = 1;
                    cl->request.states = CLOSE;
                }
            }
            if (cl->request.readbuf->num > 0) {
                if (cl->request.resource_type == DYNAMIC_RESOURCE
                    && FD_ISSET(cl->request.wfd , &p->wready_set)) {
                       p->nready--;
                    if (partial_body_to_cgi(cl) < 0) {
                        remember to close wfd after send complete
                    // Don't allow CGI close before we close wfd.
                        response_error(HTTP_INTERNAL_SERVER_ERROR, &cl->request);
                        cl->need_close = 1;
                        cl->request.states = SEND_STATIC_HEADERS;
                    } 
                } else if (cl->request.resource_type == STATIC_RESOURCE) {
                    discard_req_body(cl);
                }
            }
            break;
        case SEND_STATIC_HEADERS:
            if (cl->request.writebuf->num == 0) {
                cl->request.states = SEND_CONTENT;
            }

            if (cl->request.writebuf->num > 0
                && FD_ISSET(connfd, &p->wready_set)) {
                
            }
            break;
        case SEND_CONTENT:
            break;
        case CLOSE:
            if (cl->need_close) {
                remove_client(i, &pool)
            }
        default:
            break;
        }
    }
}

int main(int argc, char* argv[])
{
    int httpfd, httpsfd;

    /* Initializations */
    if (proc_cmd_line_args(argc, argv) == -1) {
        fprintf(stderr, "Please input right cmd args\n");
        exit(EXIT_FAILURE);
    }

    daemonize(lock_file);

    if (init_log(log_file) == -1) {
        fprintf(stderr, "init_log failed\n");
        exit(EXIT_FAILURE);
    }
    if ((httpfd = open_listenfd(http_port)) == -1) {
        close_log();
        exit(EXIT_FAILURE);
    }
    if ((httpsfd = open_listenfd(https_port)) == -1) {
        close_log();
        exit(EXIT_FAILURE);
    }
    init_pool(httpfd, httpsfd, &pool);
    if (init_ssl(private_key_file, cert_file, &pool) == -1) {
        close_log();
        exit(EXIT_FAILURE);
    }



    log_info("------------Lisod Starts------------");
    /* finally, loop waiting for input and then write it back */
    while (1) {
        pool.rready_set = pool.read_set;
        pool.wready_set = pool.write_set;
        /* restart from EINTR */
        NO_TEMP_FAILURE(pool.nready = select(pool.maxfd + 1,
                            &(pool.rready_set), &(pool.wready_set), NULL, NULL));
        if (pool.nready == -1) // Fatal error
        {
            log_error("select");
            liso_shutdown(EXIT_FAILURE);
        }

        if (FD_ISSET(httpfd, &(pool.rready_set))) {
            log_info("A new HTTP connection");
            pool.nready--;
            int clientfd = proc_http_conn(httpfd);
            if (clientfd != -1) {
                if (add_client(clientfd, NULL, &pool) == -1) {
                    close_socket(clientfd);
                }
            } else {
                log_error("Fail to create HTTP client");
            }
        }
        if (FD_ISSET(httpsfd, &(pool.rready_set))) {
            log_info("A new HTTPS connection");
            pool.nready--;
            SSL* ctx = proc_https_conn(httpsfd, &pool);
            if (ctx) {
                int clientfd = SSL_get_fd(ctx);
                if (add_client(clientfd, ctx, &pool) == -1) {
                    close_socket(clientfd);
                }
            } else {
                log_error("Fail to create HTTPS client");
            }
        }

        proc_clients(&pool);
    }

    liso_shutdown(EXIT_SUCCESS);
}