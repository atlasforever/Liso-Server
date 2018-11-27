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

#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>

#include "http_common.h"
#include "log.h"
#include "common.h"
#include "parse.h"
#include "request.h"

#define ECHO_PORT 9999
#define BUF_SIZE 4096
#define MAX_CLIENTS \
    (FD_SETSIZE - 1) // leave one select-fd for server's listenfd

/* Command line arguments */
static in_port_t http_port;
static in_port_t https_port;
static char *log_file;
static char *lock_file;
char *www_folder;
static char *cgi_path;
static char *private_key_file;
static char *cert_file;

/* Information about a connection */
typedef struct {
    parse_fsm pfsm;
} client_conn;

typedef struct {
    int maxfd;
    fd_set read_set;
    fd_set ready_set;
    int nready;
    int maxci;
    int listenfd;
    int clientfds[MAX_CLIENTS];
    client_conn client_conns[MAX_CLIENTS];
} pool;

int close_socket(int sock)
{
    if (close(sock)) {
        log_error("Failed closing socket.");
        return 1;
    }
    return 0;
}

void init_pool(int listenfd, pool* p)
{
    /* no clients initially */
    p->maxci = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        p->clientfds[i] = -1;
    }

    p->maxfd = listenfd;
    p->listenfd = listenfd;
    FD_ZERO(&(p->read_set));
    FD_SET(listenfd, &(p->read_set));
}

void add_client(int clientfd, pool* p)
{
    log_info("Add a new client fd:%d", clientfd);

    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (p->clientfds[i] == -1) {
            p->nready--;
            p->clientfds[i] = clientfd;

            // initialize for persistent connection
            init_parse_fsm(&(p->client_conns[i].pfsm));

            FD_SET(clientfd, &(p->read_set));
            if (i > p->maxci) {
                p->maxci = i;
            }
            if (clientfd > p->maxfd) {
                p->maxfd = clientfd;
            }
            break;
        }
    }
    if (i == FD_SETSIZE) {
        log_info("Too many clients");
    }
    return;
}

static void update_rmed_maxci(pool* p)
{
    int maxi = -1;

    for (int i = 0; i < p->maxci; i++) {
        if (p->clientfds[i] != -1) {
            maxi = i;
        }
    }
    p->maxci = maxi;
}
static void update_rmed_maxfd(pool* p)
{
    int maxfd = p->listenfd;
    for (int i = 0; i <= p->maxci; i++) {
        if (p->clientfds[i] != -1) {
            if (p->clientfds[i] > maxfd) {
                maxfd = p->clientfds[i];
            }
        }
    }
    p->maxfd = maxfd;
}

void remove_client(int old_idx, pool *p)
{
    if (p->clientfds[old_idx] == -1) {
        return;
    }
    
    int old_fd = p->clientfds[old_idx];
    log_info("Remove one client, fd is %d", old_fd);
    close_socket(old_fd);
    FD_CLR(old_fd, &p->read_set);
    p->clientfds[old_idx] = -1;

    if (p->maxci == old_idx) {
        update_rmed_maxci(p);
    }
    if (p->maxfd == old_fd) {
        update_rmed_maxfd(p);
    }
}

/* we can assume the fd is avaliable */
void proc_one_client(int idx, pool *p)
{

}

void proc_clients(pool *p)
{
    int connfd;
    ssize_t rn;
    Request *request;
    int ret;

    for (int i = 0; (i <= p->maxci) && (p->nready > 0); i++) {
        connfd = p->clientfds[i];

        /* ready to read */
        if ((connfd > 0) && (FD_ISSET(connfd, &(p->ready_set)))) {
            p->nready--;
            rn = recv_one_request(&p->client_conns[i].pfsm, connfd);
            if (rn == -1) {
                remove_client(i, p);
            } else if (rn == 0) {
                log_debug("continue");
                continue;
            } else {    // OK
                request = alloc_request();
                if (!request) {
                    log_error("alloc_request() failed");
                    if (response_error(HTTP_INTERNAL_SERVER_ERROR, connfd) == -1) {
                        log_error("Failed to send error response to sock %d", connfd);
                    }
                    remove_client(i, p);
                    continue;
                }

                ret = parse(p->client_conns[i].pfsm.buf, rn, request);
                log_debug("ret is %d", ret);
                if (ret == 0) {
                    // success, do something
                    ret = do_request(request, connfd);
                    if (ret == -1) {
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
    }
}

void close_all_clients(pool *p)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (p->clientfds[i] != -1) {
            remove_client(i, p);
        }
    }
}

static int proc_cmd_line_args(int argc, char* argv[])
{
    if (argc != 9) {
        return -1;
    }
    /* wrong if atoi error or the number itself is 0 */
    if ((http_port = (in_port_t)atoi(argv[1])) == 0) {return -1;}
    if ((https_port = (in_port_t)atoi(argv[2])) == 0) {return -1;}
    log_file = argv[3];
    lock_file = argv[4];
    www_folder = argv[5];
    cgi_path = argv[6];
    private_key_file = argv[7];
    cert_file = argv[8];

    return 0;
}

static int init(int argc, char* argv[])
{
    if (proc_cmd_line_args(argc, argv) == -1) {
        fprintf(stderr, "Please input right cmd args\n");
        return -1;
    }
    if (init_log(log_file) == -1) {
        fprintf(stderr, "init_log failed\n");
        return -1;
    }

    
    return 0;
}

static int open_listenfd()
{
    int sock;
    struct sockaddr_in addr;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        log_error("socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ECHO_PORT);
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
int main(int argc, char* argv[])
{
    int sock, client_sock;
    socklen_t cli_size;
    struct sockaddr_in cli_addr;

    static pool pool;
    /* init all */
    if (init(argc, argv) == -1) {exit(EXIT_FAILURE);}
    if (proc_cmd_line_args(argc, argv) == -1) {
        fprintf(stderr, "Please input right cmd args\n");
        exit(EXIT_FAILURE);
    }
    if (init_log(log_file) == -1) {
        fprintf(stderr, "init_log failed\n");
        exit(EXIT_FAILURE);
    }
    if ((sock = open_listenfd()) == -1) {
        close_log();
        exit(EXIT_FAILURE);
    }
    init_pool(sock, &pool);


    log_info("------------Lisod Starts------------");
    /* finally, loop waiting for input and then write it back */
    while (1) {
        pool.ready_set = pool.read_set;
        /* restart from EINTR */
        NO_TEMP_FAILURE(pool.nready = select(pool.maxfd + 1, 
                                    &(pool.ready_set), NULL, NULL, NULL));
        if (pool.nready == -1) // Fatal error
        {
            close_all_clients(&pool);
            close_socket(sock);
            log_error("select");
            close_log();
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(sock, &(pool.ready_set))) // a client tries to connect
        {
            cli_size = sizeof(cli_addr);
            NO_TEMP_FAILURE(client_sock = accept(sock, (struct sockaddr*)&cli_addr, &cli_size));
            log_debug("new connection:%d", client_sock);
            if (client_sock == -1)
            {
                log_error("accept, errno is %d", errno);
                if (errno != EMFILE) {  // skip it if too many fd opened
                    close_all_clients(&pool);
                    close_socket(sock);
                    close_log();
                    exit(EXIT_FAILURE);
                }
            } else {
                add_client(client_sock, &pool);
            }
        }
        proc_clients(&pool);
    }

    close_all_clients(&pool);
    close_socket(sock);
    close_log();
    return EXIT_SUCCESS;
}
