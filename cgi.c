#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "lisod.h"
#include "request.h"
#include "log.h"

int init_cgi_bin(char *path, Request *r)
{
    // cgi-bin's stdin and stdout
    int stdin_pipe[2];
    int stdout_pipe[2];
    int pid;

    if (pipe(stdin_pipe) < 0) {
        log_error("Error piping for stdin");
        return -1;
    }
    if (pipe(stdout_pipe) < 0) {
        log_error("Error piping for stdout");
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(stdin_pipe[0]);
        close(stdin_pipe[1]);
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        log_error("Fork failed in init_cgi_bin()");
        return -1;
    }

    // Child
    if (pid == 0) {
        close(stdin_pipe[1]);
        close(stdout_pipe[0]); 
        dup2(stdout_pipe[1], fileno(stdout));
        dup2(stdin_pipe[0], fileno(stdin));

    }

    // Parent
    if (pid > 0) {
        log_info("Create a process %d for CGI", pid);
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);

        fcntl(stdin_pipe[1], F_SETFL, fcntl(stdin_pipe[1], F_GETFL) | O_NONBLOCK);
        fcntl(stdout_pipe[0], F_SETFL, fcntl(stdout_pipe[0], F_GETFL) | O_NONBLOCK);
        r->wfd = stdin_pipe[1];
        r->rfd = stdout_pipe[0];
    }
    return 0;
}

static void handle_in_cgi(int stdin_pipe[2], int stdout_pipe[2], char *path, Request *r)
{
    int errfd;
    int ret;
    char *filename;

    /* Prepare file descriptors */
    errfd = open("/dev/null", O_RDWR);
    if (errfd == -1) {
        exit(EXIT_FAILURE);
    }
    NO_TEMP_FAILURE(ret = dup2(stdout_pipe[1], fileno(stdout)));
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
    NO_TEMP_FAILURE(ret = dup2(stdin_pipe[0], fileno(stdin)));
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
    NO_TEMP_FAILURE(ret = dup2(errfd, fileno(stderr)));
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
    // Close useless fds
    for (int i = 0; i < getdtablesize(); i++) {
        if (i != fileno(stdout) && i != fileno(stdin) && i != fileno(stderr)) {
            if (close(i) < 0) {
                exit(EXIT_FAILURE);
            }
        }
    }

    
    

}