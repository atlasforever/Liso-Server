#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <libgen.h>

#include "lisod.h"
#include "request.h"
#include "log.h"

#define CGI_ARGS_NUM 1
#define CGI_ENVS_NUM 22

char* www_folder;

int exec_cgi_bin(char *path, http_client_t *cl)
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
        cl->request.wfd = stdin_pipe[1];
        cl->request.rfd = stdout_pipe[0];
    }
    return 0;
}

static void cgi_init(int stdip[2], int stdop[2], char *path, http_client_t *cl)
{
    int errfd;
    int ret;
    char *args[CGI_ARGS_NUM + 1];
    char *envs[CGI_ENVS_NUM + 1];
    
    /* Prepare file descriptors */
    errfd = open("/dev/null", O_RDWR);
    if (errfd == -1) {
        exit(EXIT_FAILURE);
    }
    NO_TEMP_FAILURE(ret = dup2(stdop[1], fileno(stdout)));
    if (ret == -1) {
        exit(EXIT_FAILURE);
    }
    NO_TEMP_FAILURE(ret = dup2(stdip[0], fileno(stdin)));
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


static int make_cgi_args(char *path, char *args[])
{
    char *filename;

    // 2 for  "./", 1 for nul
    // no need to free(), because execve will be called later.
    if (filename = malloc(NAME_MAX + 2 + 1)) {
        return -1;
    }
    sprintf(filename, "./%s", basename(path));

    args[0] = filename;
    args[1] = NULL;

    return 0;
}

static int make_cgi_envs(http_client_t *cl, char *envs[])
{
    Request *r = &cl->request;
    char *values[CGI_ENVS_NUM];
    char *path_info = 


}

static int set_env_by_str(char *envname, char *envvalue, char **dst)
{
    size_t n;
    char *line, *value;
    
    value = envvalue ? envvalue : "";

    n = strlen(envname) + 1 + strlen(value);
    line = malloc(n + 1);
    if (!line) {
        return -1;
    }

    sprintf(line, "%s:%s", envname, value);
    *dst = line;
    return 0;
}




int sep_scriptname_pathinfo(const char *path, char *out_sn, char *out_pi)
{
    int ret;
    size_t path_len = strlen(path);
    size_t root_len;
    char *rpath = make_realpath(path);
    if (!rpath) {
        return -1;
    }

    root_len = strlen(rpath) - path_len;
    strcpy(out_sn, "");
    strcpy(out_pi, "");


    while (1) {
        if (access(rpath, X_OK) == 0) {
            strcpy(out_sn, rpath + root_len);
            strcpy(out_pi, path + strlen(out_sn));
            ret = 0;
            break;
        } else {
            char *slash = strrchr(rpath, '/');
            if (!slash) {
                ret = -1;
                break;
            } else {
                *slash = '\0';
            }
        }
    }

    free(rpath);
    return ret;
}