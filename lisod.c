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
#include <sys/select.h>
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

#define BUF_SIZE 4096
#define MAX_CLIENTS \
    ((FD_SETSIZE - 2) / 3) // leave 2 select-fd for HTTP and HTTPS ports. And each client will have 3 fds.

/* Command line arguments */
static in_port_t http_port;
static in_port_t https_port;
static char* log_file;
static char* lock_file;
char* www_folder;
static char* cgi_path;
static char* private_key_file;
static char* cert_file;


typedef struct {
    int maxfd;
    int left_rfds;
    int left_wfds;
    fd_set read_set;
    fd_set ready_set;
    int nready;
    int maxci;

    SSL_CTX *ssl_ctx;
    
    int httpfd;
    int httpsfd;
    http_client_t clients[MAX_CLIENTS];
} client_pool_t;
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
    p->left_rfds = FD_SETSIZE;
    p->left_wfds = 0;
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
            p->clients[i].need_close = 0;
            // initialize for persistent connection
            init_parse_fsm(&(p->clients[i].pfsm));
            if (init_request(&(p->clients[i].request)) == -1) {
                log_error("init_request() failed");
                return -1;
            }

            FD_SET(clientfd, &(p->read_set));
            p->left_rfds--;
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
            if (p->clients[i].sockfd > maxfd) {
                maxfd = p->clients[i].sockfd;
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

    int old_fd = p->clients[old_idx].sockfd;
    http_client_t *c = &(p->clients[old_idx]);

    log_info("Remove one client, fd is %d", old_fd);
    close_socket(old_fd);
    FD_CLR(old_fd, &p->read_set);
    c->sockfd = -1;
    if (c->request) {
        free_request(p->clients[old_fd].request);
    }
    if (c->client_context) {
        SSL_free(c->client_context);
    }

    
    if (p->maxci == old_idx) {
        update_rmed_maxci(p);
    }
    if (p->maxfd == old_fd) {
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
 * Non-blocking IO function for HTTP or HTTPS connection.
 * 
 * Both return number of bytes transferred. -1 on error. 0 on connection closed.
 * -2 indicates that this function should be called again later.
 */
int liso_nb_recv(http_client_t *c, void* buf, size_t len)
{
    int rn = 0;

    if (c->type == HTTPS_TYPE) {
        rn = ssl_read(c->client_context, buf, len);
        if (rn <= 0) {
            int err = SSL_get_error(c->client_context, rn);
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
    } else {
        NO_TEMP_FAILURE((rn = recv(c->sockfd, buf, len, MSG_DONTWAIT)));
        if (rn == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -2;
            } else {
                return -1;
            }
        } else if (rn == 0) {
            return 0;
        }
    }
    return rn;
}
int liso_nb_send(http_client_t *c, void* buf, size_t len)
{
    int sn = 0;

    if (c->type == HTTPS_TYPE) {
        sn = ssl_write(c->client_context, buf, len);
        if (sn <= 0) {
            int err = SSL_get_error(c->client_context, sn);
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
    } else {
        NO_TEMP_FAILURE((sn = send(c->sockfd, buf, len, MSG_DONTWAIT)));
        if (sn == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -2;
            } else {
                return -1;
            }
        } else if (sn == 0) {
            return 0;
        }
    }
    return sn;
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
        if ((connfd > 0) && (FD_ISSET(connfd, &(p->ready_set)))) {
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
            if (FD_ISSET(connfd, &(p->ready_set))) {
                p->nready--;
                int rn = recv_one_request(cl);
                if (rn == 0) {
                    log_debug("continue");
                    continue;
                } else if (rn == -1) {
                    response_error
                }
            }
            break;
        case WAIT_STATIC_REQ_BODY:
            break;
        case WAIT_CGI_REQ_BODY:
            break;
        case SEND_STATIC_HEADERS:
            //break;
        case SEND_CONTENT:
            break;
        case CLOSE:
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
        pool.ready_set = pool.read_set;
        /* restart from EINTR */
        NO_TEMP_FAILURE(pool.nready = select(pool.maxfd + 1,
                            &(pool.ready_set), NULL, NULL, NULL));
        if (pool.nready == -1) // Fatal error
        {
            log_error("select");
            liso_shutdown(EXIT_FAILURE);
        }

        if (FD_ISSET(httpfd, &(pool.ready_set))) {
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
        if (FD_ISSET(httpsfd, &(pool.ready_set))) {
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