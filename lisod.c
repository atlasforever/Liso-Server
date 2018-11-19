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

#include "log.h"
#include "common.h"

#define ECHO_PORT 9999
#define BUF_SIZE 4096
#define MAX_CLIENTS \
    (FD_SETSIZE - 1) // leave one select-fd for server's listenfd

/* Command line arguments */
static int http_port;
static int https_port;
static char *log_file;
static char *lock_file;
static char *www_folder;
static char *cgi_path;
static char *private_key_file;
static char *cert_file;

typedef struct {
    int maxfd;
    fd_set read_set;
    fd_set ready_set;
    int nready;
    int maxci;
    int listenfd;
    int clientfds[MAX_CLIENTS];
    char buffers[MAX_CLIENTS][BUF_SIZE];
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
    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (p->clientfds[i] == -1) {
            p->nready--;
            p->clientfds[i] = clientfd;
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

void proc_clients(pool* p)
{
    int connfd;
    ssize_t rn, sn;

    for (int i = 0; (i <= p->maxci) && (p->nready > 0); i++) {
        connfd = p->clientfds[i];

        /* ready to read */
        if ((connfd > 0) && (FD_ISSET(connfd, &(p->ready_set)))) {
            p->nready--;
            NO_TEMP_FAILURE(rn = recv(connfd, p->buffers[i], BUF_SIZE, 0));

            if (rn >= 1) {
                NO_TEMP_FAILURE(sn = send(connfd, p->buffers[i], rn, 0));
                if (sn != rn) { /* wrong when sn != rn. Remove the client on send errors */
                    log_error("send failed");
                    if (p->maxci == i) {
                        update_rmed_maxci(p);
                    }
                    if (p->maxfd == connfd) {
                        update_rmed_maxfd(p);
                    }
                    close_socket(connfd);
                    FD_CLR(connfd, &(p->read_set));
                    p->clientfds[i] = -1;
                }
            }
            else { /* remove the client on EOF or recv errors */
                if (p->maxci == i) {
                    update_rmed_maxci(p);
                }
                if (p->maxfd == connfd) {
                    update_rmed_maxfd(p);
                }
                close_socket(connfd);
                FD_CLR(connfd, &(p->read_set));
                p->clientfds[i] = -1;
            }
        }
    }
}

void close_all_clients(pool* p)
{
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (p->clientfds[i] != -1) {
            close_socket(p->clientfds[i]);
        }
    }
}

static int proc_cmd_line_args(int argc, char* argv[])
{
    if (argc != 9) {
        return -1;
    }
    /* wrong if atoi error or the number itself is 0 */
    if ((http_port = atoi(argv[1])) == 0) {return -1;}
    if ((https_port = atoi(argv[2])) == 0) {return -1;}
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
    int sock, client_sock;
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
        log_error("bind");
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
    struct sockaddr_in addr, cli_addr;

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

        if (FD_ISSET(sock,
                &(pool.ready_set))) // this socket is ready to be accepted
        {
            cli_size = sizeof(cli_addr);
            NO_TEMP_FAILURE(client_sock = accept(sock, (struct sockaddr*)&cli_addr, &cli_size));
            if (client_sock == -1)
            {
                close_all_clients(&pool);
                close_socket(sock);
                log_error("accept");
                close_log();
                exit(EXIT_FAILURE);
            }

            add_client(client_sock, &pool);
        }

        proc_clients(&pool);
    }

    close_all_clients(&pool);
    close_socket(sock);
    close_log();
    return EXIT_SUCCESS;
}
