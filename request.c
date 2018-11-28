#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <string.h>

#include "http_common.h"
#include "log.h"
#include "parse.h"
#include "common.h"
#include "request.h"

extern char *www_folder;

const char *default_index = "index.html";

static int do_GET_request(Request *request, int fd);
static int do_HEAD_request(Request *request, int fd);
static int do_POST_request(Request *request, int fd);
static int send_body_by_file(char *filepath, size_t len, int fd);
static int send_body_by_buf(char *body, size_t len, int fd);
static int end_headers(int fd, int hasBody);
static int send_header(char *name, char *value, int fd);
static int send_response_line(char *version, int code, char *phrase, int fd);
static unsigned long get_file_size(char *path);
static char *get_MMIE(const char *filename);
static int get_mtime(const char *path, time_t *mt);
static char* get_header_value(Request *request, const char *name);



int do_request(Request *request, int sockfd)
{
    // Not compatible with HTTP 1.0
    if (strcmp(HTTP_VERSION, request->http_version) != 0) {
        response_error(HTTP_BAD_REQUEST, sockfd);
    }

    if (strcmp("GET", request->http_method) == 0) {
        return do_GET_request(request, sockfd);
    } else if (strcmp("HEAD", request->http_method) == 0) {
        return do_HEAD_request(request, sockfd);
    } else if (strcmp("POST", request->http_method) == 0) {
        return do_POST_request(request, sockfd);
    }

    return response_error(HTTP_NOT_IMPLEMENTED, sockfd);
}

/* 0: ok. 
 * 1: ok. client wants to close the connection
 * -1: error. Need to close the connection
 */
static int do_GET_request(Request *request, int fd)
{
    struct tm *stm;
    time_t now, mtime;
    char msg[35], mtbuf[35];
    unsigned long sz;

    log_info("A GET Request");
    char *path = malloc(HTTP_URI_MAX_SIZE + 256);
    if (!path) {
        if (response_error(HTTP_INTERNAL_SERVER_ERROR, fd) == -1) {return -1;}
        return 0;
    }

    /* Generate the actual file path */
    strcpy(path, www_folder);
    // the folder should end with '/'
    log_debug("path is:%s", path);
    log_debug("uri is:%s", request->http_uri);
    if (path[strlen(path) - 1] != '/') {
        strcat(path, "/");
    }
    if (strcmp(request->http_uri, "/") == 0 || strcmp(request->http_uri, " ") == 0) {
        strcat(path, default_index);
    } else if (request->http_uri[0] == '/') {
        // already a slash in www_path
        strcat(path, request->http_uri + 1);
    } else {
        // only support "abs_path"
        log_info("A invalid path:%s", request->http_uri);
        free(path);
        if (response_error(HTTP_NOT_FOUND, fd) == -1) {return -1;}
        return 0;
    }

    log_debug("finnaly, path is:%s", path);
    if (access(path, F_OK | R_OK) != 0) {
        log_debug("fail to read this file:%s", path);
        free(path);
        if (response_error(HTTP_NOT_FOUND, fd) == -1) {return -1;}
        return 0;
    }
    sz = get_file_size(path);
    if (sz == -1) {
        log_error("get_file_size failed");
        free(path);
        if (response_error(HTTP_INTERNAL_SERVER_ERROR, fd) == -1) {return -1;};
        return 0;
    }

    // get time. gmtime() is NOT thread safe
    now = time(0);
    stm = gmtime(&now);
    strftime(msg, 35, "%a, %d %b %Y %H:%M:%S %Z", stm);
    
    // last modified
    if (get_mtime(path, &mtime) == -1) {
        free(path);
        if (response_error(HTTP_INTERNAL_SERVER_ERROR, fd) == -1) {return -1;};
        return 0;
    }
    stm = gmtime(&mtime);
    strftime(mtbuf, 35, "%a, %d %b %Y %H:%M:%S %Z", stm);



    if (send_response_line(HTTP_VERSION, HTTP_OK, "OK", fd) == -1) {free(path); return -1;}  
    if (send_header("Date", msg, fd) == -1) {free(path); return -1;}
    if (send_header("Connection", "keep-alive", fd) == -1) {free(path); return -1;}
    if (send_header("Server", SERVER_VERSION, fd) == -1) {free(path); return -1;}
    sprintf(msg, "%ld", sz);
    if (send_header("Content-Length", msg, fd) == -1) {free(path); return -1;}
    if (send_header("Content-Type", get_MMIE(path), fd) == -1) {free(path); return -1;}
    if (send_header("Last-Modified", mtbuf, fd) == -1) {free(path); return -1;}
    if (end_headers(fd, 1) == -1) {free(path); return -1;}
    if (send_body_by_file(path, sz, fd) == -1) {free(path); return -1;}

    free(path);

    char *v = get_header_value(request, "Connection");
    if (!v || strcmp(v, "close") == 0) {
        return 0;
    } else {
        return 1;
    }
}

/* Just copy-and-paste from do_GET_request() */
static int do_HEAD_request(Request *request, int fd)
{
    struct tm *stm;
    time_t now, mtime;
    char msg[35], mtbuf[35];
    unsigned long sz;

    log_info("A HEAD Request");
    char *path = malloc(HTTP_URI_MAX_SIZE + 256);
    if (!path) {
        if (response_error(HTTP_INTERNAL_SERVER_ERROR, fd) == -1) {return -1;}
        return 0;
    }

    /* Generate the actual file path */
    strcpy(path, www_folder);
    // the folder should end with '/'
    log_debug("path is:%s", path);
    log_debug("uri is:%s", request->http_uri);
    if (path[strlen(path) - 1] != '/') {
        strcat(path, "/");
    }
    if (strcmp(request->http_uri, "/") == 0 || strcmp(request->http_uri, " ") == 0) {
        strcat(path, default_index);
    } else if (request->http_uri[0] == '/') {
        // already a slash in www_path
        strcat(path, request->http_uri + 1);
    } else {
        // only support "abs_path"
        log_info("A invalid path:%s", request->http_uri);
        free(path);
        if (response_error(HTTP_NOT_FOUND, fd) == -1) {return -1;}
        return 0;
    }
    
    if (access(path, F_OK | R_OK) != 0) {
        log_debug("fail to read this file:%s", path);
        free(path);
        if (response_error(HTTP_NOT_FOUND, fd) == -1) {return -1;}
        return 0;
    }
    sz = get_file_size(path);
    if (sz == -1) {
        log_error("get_file_size failed");
        free(path);
        if (response_error(HTTP_INTERNAL_SERVER_ERROR, fd) == -1) {return -1;};
        return 0;
    }

    // get time. gmtime() is NOT thread safe
    now = time(0);
    stm = gmtime(&now);
    strftime(msg, 35, "%a, %d %b %Y %H:%M:%S %Z", stm);
    
    // last modified
    if (get_mtime(path, &mtime) == -1) {
        free(path);
        if (response_error(HTTP_INTERNAL_SERVER_ERROR, fd) == -1) {return -1;};
        return 0;
    }
    stm = gmtime(&mtime);
    strftime(mtbuf, 35, "%a, %d %b %Y %H:%M:%S %Z", stm);



    if (send_response_line(HTTP_VERSION, HTTP_OK, "OK", fd) == -1) {free(path); return -1;}  
    if (send_header("Date", msg, fd) == -1) {free(path); return -1;}
    if (send_header("Connection", "keep-alive", fd) == -1) {free(path); return -1;}
    if (send_header("Server", SERVER_VERSION, fd) == -1) {free(path); return -1;}
    sprintf(msg, "%ld", sz);
    if (send_header("Content-Length", msg, fd) == -1) {free(path); return -1;}
    if (send_header("Content-Type", get_MMIE(path), fd) == -1) {free(path); return -1;}
    if (send_header("Last-Modified", mtbuf, fd) == -1) {free(path); return -1;}
    if (end_headers(fd, 1) == -1) {free(path); return -1;}

    free(path);
    char *v = get_header_value(request, "Connection");
    if (!v || strcmp(v, "close") == 0) {
        return 0;
    } else {
        return 1;
    }
}

static int do_POST_request(Request *request, int fd)
{
    Request_header *first_hdr = request->headers->next;
    char *v;
    char nouse[256];
    long len, rn = 0, total = 0;

    log_info("A POST Request");
    for (Request_header *cur = first_hdr; cur; cur = cur->next) {
        log_debug("Name is %s", cur->header_name);
        log_debug("Value is %s", cur->header_value);
    }

    // A dummy POST request handler. I will finish the real work with the CGI part in Checkpoint3

    // we do no thing
    if (send_response_line(HTTP_VERSION, HTTP_OK, "OK", fd) == -1) {return -1;}
    if (end_headers(fd, 1) == -1) {return -1;}


    v = get_header_value(request, "Content-Length");
    if (!v || (len = atoi(v) <= 0)) {
        // do nothing
    } else {    // abandon the body
        while (total < len) {
            NO_TEMP_FAILURE(rn = recv(fd, nouse, 256, 0));
            if (rn == -1) {
                return -1;
            } else if (rn == 0) {
                continue;
            } else {
                total += rn;
            }
        }
    }

    v = get_header_value(request, "Connection");
    if (!v || strcmp(v, "close") == 0) {
        return 0;
    } else {
        return 1;
    }
}

int response_error(int code, int fd)
{
    char msg[64], *body;
    int len;
    struct tm *stm;
    time_t now;

    switch (code) {
    case HTTP_NOT_FOUND:
        if (send_response_line(HTTP_VERSION, HTTP_NOT_FOUND, "Not Found", fd) == -1) {return -1;}
        len = strlen(HTTP_404_PAGE);
        body = HTTP_404_PAGE;
        break;
    case HTTP_NOT_ALLOWED:
        if (send_response_line(HTTP_VERSION, HTTP_NOT_ALLOWED, "Not Allowed", fd) == -1) {return -1;}
        len = strlen(HTTP_405_PAGE);
        body = HTTP_405_PAGE;
        break;
    case HTTP_INTERNAL_SERVER_ERROR:
        if (send_response_line(HTTP_VERSION, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error", fd) == -1) {
            return -1;
        }
        len = strlen(HTTP_500_PAGE);
        body = HTTP_500_PAGE;
        break;
    case HTTP_NOT_IMPLEMENTED:
        if (send_response_line(HTTP_VERSION, HTTP_NOT_IMPLEMENTED, "Not Implemented", fd) == -1) {return -1;}
        len = strlen(HTTP_501_PAGE);
        body = HTTP_501_PAGE;
        break;
    default:    /* Default is Bad Request */
        if (send_response_line(HTTP_VERSION, HTTP_BAD_REQUEST, "Bad Request", fd) == -1) {return -1;}
        len = strlen(HTTP_400_PAGE);
        body = HTTP_400_PAGE;
        break;
    }

    now = time(0);
    stm = gmtime(&now);
    strftime(msg, 64, "%a, %d %b %Y %H:%M:%S %Z", stm);

    if (send_header("Date", msg, fd) == -1) {return -1;}
    if (send_header("Connection", "close", fd) == -1) {return -1;}
    if (send_header("Server", SERVER_VERSION, fd) == -1) {return -1;}

    sprintf(msg, "%d", len);
    if (send_header("Content-Length", msg, fd) == -1) {return -1;}
    if (end_headers(fd, 1) == -1) {return -1;}

    if (send_body_by_buf(body, len, fd) == -1) {return -1;}

    return 0;
}

static char* get_header_value(Request *request, const char *name)
{
    Request_header *cur = request->headers->next;

    for (; cur; cur = cur->next) {
        if (strcmp(name, cur->header_name) == 0) {
            return cur->header_value;
        }
    }
    return NULL;
}
static int get_mtime(const char *path, time_t *mt)
{
    struct stat sb;

    if (stat(path, &sb) == -1) {
        return -1;
    }
    *mt = sb.st_mtime;
    return 0;
}
static unsigned long get_file_size(char *path)
{
    unsigned long sz;
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0L, SEEK_END);
    sz = (unsigned long)ftell(fp);
    fclose(fp);
    return sz;
}

static char *get_MMIE(const char *filename)
{
    char *dot = strrchr(filename, '.');
    char *ext;
    if (!dot || dot == filename) {
        log_debug("no ext:%s", dot);
        return MIME_OCTET_STREAM;
    }

    ext = dot + 1;
    if (strcmp(ext, "html") == 0) {
        return MIME_HTML;
    } else if (strcmp(ext, "css") == 0) {
        return MIME_CSS;
    } else if (strcmp(ext, "gif") == 0) {
        return MIME_GIF;
    } else if (strcmp(ext, "jpeg") == 0) {
        return MIME_JPEG;
    } else if (strcmp(ext, "png") == 0) {
        return MIME_PNG;
    } else {
        log_debug("unknown ext:%s", ext);
        return MIME_OCTET_STREAM;
    }
}

static int send_body_by_file(char *filepath, size_t len, int fd)
{
    ssize_t ret;
    FILE *fp = fopen(filepath, "r");
    int filefd;
    if (!fp) {
        return -1;
    }
    
    filefd = fileno(fp);
    ret = sendfile(fd, filefd, NULL, len);
    if (ret == -1) {
        log_error("sendfile failed");
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int send_body_by_buf(char *body, size_t len, int fd)
{
    ssize_t sn;

    NO_TEMP_FAILURE(sn = send(fd, body, len, 0));
    if (sn != len) {
        return -1;
    }
    return 0;
}
static int end_headers(int fd, int hasBody)
{
    ssize_t sn;
    int flags;

    flags = hasBody? MSG_MORE : 0;
    NO_TEMP_FAILURE(sn = send(fd, "\r\n", 2, flags));
    if (sn != 2) {
        return -1;
    }
    return 0;
}
static int send_header(char *name, char *value, int fd)
{
    int nl = strlen(name);
    int vl = strlen(value); 
    ssize_t sn;

    NO_TEMP_FAILURE(sn = send(fd, name, nl, MSG_MORE));
    if (sn != nl) {
        return -1;
    }

    NO_TEMP_FAILURE(sn = send(fd, ": ", 2, MSG_MORE));
    if (sn != 2) {
        return -1;
    }

    NO_TEMP_FAILURE(sn = send(fd, value, vl, MSG_MORE));
    if (sn != vl) {
        return -1;
    }

    NO_TEMP_FAILURE(sn = send(fd, "\r\n", 2, MSG_MORE));
    if (sn != 2) {
        return -1;
    }
    return 0;
}
static int send_response_line(char *version, int code, char *phrase, int fd)
{
    char cstr[6];
    int vl = strlen(version);
    int pl = strlen(phrase);
    ssize_t sn;

    NO_TEMP_FAILURE(sn = send(fd, version, vl, MSG_MORE));
    if (sn != vl) {
        return -1;
    }

    snprintf(cstr, 6, " %d ", code);
    NO_TEMP_FAILURE(sn = send(fd, cstr, 5, MSG_MORE));
    if (sn != 5) {
        return -1;
    }

    NO_TEMP_FAILURE(sn = send(fd, phrase, pl, MSG_MORE));
    if (sn != pl) {
        return -1;
    }

    NO_TEMP_FAILURE(sn = send(fd, "\r\n", 2, MSG_MORE));
    if (sn != 2) {
        return -1;
    }
    return 0;
}