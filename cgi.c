#include <unistd.h>
#include <stdlib>
#include "request.h"
#include "log.h"

int init_cgi_bin(Request *r)
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
        log_error("Fork failed in init_cgi_bin()");
        return -1;
    }

    // Child
    if (pid == 0) {
        close(stdin_pipe[0]);
        close(stdout_pipe[0]); 
        dup2(stdout_pipe[1], fileno(stdout));
        dup2(stdin_pipe[0], fileno(stdin));
        
    }
}