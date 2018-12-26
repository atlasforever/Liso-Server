#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <string.h>
#include <linux/limits.h>

#include "http_common.h"
#include "log.h"
#include "lisod.h"
#include "request.h"
#include "cgi.h"

#define WRITE_BUFFER_MAX_SIZE 2048
#define READ_BUFFER_MAX_SIZE 2048

extern char *www_folder;
extern client_pool_t pool;
extern const char *cgi_path;
const char *default_index = "index.html";


static int do_GET_request(Request *request);
static int do_HEAD_request(Request *request);
static int do_POST_request(Request *request);
static int send_body_by_file(char *filepath, size_t len, int fd);
static int send_body_by_buf(char *body, size_t len, int fd);
static void add_status_line(char *version, int code, char *phrase, Request *r);
static void add_rsp_header(char *name, char *value, Request *r);
static void end_rsp_headers(Request *r);
static unsigned long get_file_size(char *path);
static char *get_MMIE(const char *filename);
static int get_mtime(const char *path, time_t *mt);
static int is_cgi_request(Request *r);

/* 
 * 0: ok.
 * 1: ok. But this connection need to be closed.
 * < 0: (-HTTP STATUS CODE). Error. Need to close the connection
 */
int do_request(Request *request)
{
    // Not compatible with HTTP 1.0
    if (strcmp(HTTP_VERSION, request->http_version) != 0) {
        return -HTTP_BAD_REQUEST;
    }

    if (strcmp("GET", request->http_method) == 0) {
        return do_GET_request(request);
    } else if (strcmp("HEAD", request->http_method) == 0) {
        return do_HEAD_request(request);
    } else if (strcmp("POST", request->http_method) == 0) {
        return do_POST_request(request);
    } else {
        return -HTTP_NOT_IMPLEMENTED;
    }
}

/* 
 * 0: ok.
 * 1: ok. But this connection need to be closed.
 * < 0: (-HTTP STATUS CODE). Error. Need to close the connection
 */
static int do_GET_request(Request *request)
{
    struct tm *stm;
    time_t now, mtime;
    char msg[35], mtbuf[35];
    unsigned long sz;
    int close_flag;


    log_info("A GET Request");
    char *path = malloc(PATH_MAX); // including null
    if (!path) {
        return -HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Generate the actual file path */
    strcpy(path, www_folder);
    // the folder should end with '/'
    log_debug("path is:%s", path);
    log_debug("uri is:%s", request->http_path);
    if (path[strlen(path) - 1] != '/') {
        strcat(path, "/");
    }
    if (strcmp(request->http_path, "/") == 0 || strcmp(request->http_path, " ") == 0) {
        strcat(path, default_index);
    } else if (request->http_path[0] == '/') {
        // already a slash in www_path
        strcat(path, request->http_path + 1);
    } else {
        // only support "abs_path"
        log_info("A invalid path:%s", request->http_path);
        free(path);
        return -HTTP_NOT_FOUND;
    }

    log_debug("finnaly, path is:%s", path);
    if (access(path, F_OK | R_OK) != 0) {
        log_debug("fail to read this file:%s", path);
        free(path);
        return -HTTP_NOT_FOUND;
    }
    sz = get_file_size(path);
    if (sz == -1) {
        log_error("get_file_size failed");
        free(path);
        return -HTTP_INTERNAL_SERVER_ERROR;
    }

    // get time. Notice that gmtime() is NOT thread safe
    now = time(0);
    stm = gmtime(&now);
    strftime(msg, 35, "%a, %d %b %Y %H:%M:%S %Z", stm);
    
    // last modified
    if (get_mtime(path, &mtime) == -1) {
        free(path);
        return -HTTP_INTERNAL_SERVER_ERROR;
    }
    stm = gmtime(&mtime);
    strftime(mtbuf, 35, "%a, %d %b %Y %H:%M:%S %Z", stm);

    // Detect Connection field
    char *value;
    value = get_header_value(request, "Connection");
    if (value && (strcmp(value, "close") == 0)) {
        close_flag = 1;
    } else {
        close_flag = 0;
    }

    // get content-length
    value = get_header_value(request, "Content-Length");
    if (value && atoi(value) > 0) {
        request->content_length = value;
    }

    // Send headers
    add_status_line(HTTP_VERSION, HTTP_OK, "OK", request);
    add_rsp_header("Date", msg, request);
    add_rsp_header("Connection", close_flag ? "close" : "keep-alive", request);
    add_rsp_header("Server", SERVER_VERSION, request);
    sprintf(msg, "%ld", sz);
    add_rsp_header("Content-Length", msg, request);
    add_rsp_header("Content-Type", get_MMIE(path), request);
    add_rsp_header("Last-Modified", mtbuf, request);
    end_rsp_headers(request);
    if (send_body_by_file(path, sz, fd) == -1) {free(path); return -1;}

    free(path);
    if (close_flag) {
        return 1;
    } else {
        return 0;
    }
}

/* Just copy-and-paste from do_GET_request() */
static int do_HEAD_request(Request *request)
{
    struct tm *stm;
    time_t now, mtime;
    char msg[35], mtbuf[35];
    unsigned long sz;

    log_info("A HEAD Request");
    char *path = malloc(HTTP_PATH_MAX_SIZE + 256);
    if (!path) {
        if (response_error(HTTP_INTERNAL_SERVER_ERROR, fd) == -1) {return -1;}
        return 0;
    }

    /* Generate the actual file path */
    strcpy(path, www_folder);
    // the folder should end with '/'
    log_debug("path is:%s", path);
    log_debug("uri is:%s", request->http_path);
    if (path[strlen(path) - 1] != '/') {
        strcat(path, "/");
    }
    if (strcmp(request->http_path, "/") == 0 || strcmp(request->http_path, " ") == 0) {
        strcat(path, default_index);
    } else if (request->http_path[0] == '/') {
        // already a slash in www_path
        strcat(path, request->http_path + 1);
    } else {
        // only support "abs_path"
        log_info("A invalid path:%s", request->http_path);
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

    char *cnt = get_header_value(request, "Connection");
    if (cnt && (strcmp(cnt, "close") == 0)) {
        return 1;
    } else {
        return 0;
    }
}

static int do_POST_request(Request *request)
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

    char *cnt = get_header_value(request, "Connection");
    if (cnt && (strcmp(cnt, "close") == 0)) {
        return 1;
    } else {
        return 0;
    }
}

/* Prepare response for errors and stop original process */
void response_error(int code, Request *r)
{
    char msg[64], *body;
    struct tm *stm;
    time_t now;

    // Stop what we originally want to send
    close_content_rfd(r);
    close_content_wfd(r);

    // just send error response and exit this request
    r->states = SEND_CONTENT;

    clean_qbuf(r->writebuf);
    switch (code) {
    case HTTP_NOT_FOUND:
        add_status_line(HTTP_VERSION, HTTP_NOT_FOUND, "Not Found", r);
        body = HTTP_404_PAGE;
        break;
    case HTTP_NOT_ALLOWED:
        send_response_line(HTTP_VERSION, HTTP_NOT_ALLOWED, "Not Allowed", r);
        body = HTTP_405_PAGE;
        break;
    case HTTP_INTERNAL_SERVER_ERROR:
        send_response_line(HTTP_VERSION, HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error", r);
        body = HTTP_500_PAGE;
        break;
    case HTTP_NOT_IMPLEMENTED:
        send_response_line(HTTP_VERSION, HTTP_NOT_IMPLEMENTED, "Not Implemented", r);
        body = HTTP_501_PAGE;
        break;
    default:
        send_response_line(HTTP_VERSION, HTTP_BAD_REQUEST, "Bad Request", r);
        body = HTTP_400_PAGE;
        break;
    }

    now = time(0);
    stm = gmtime(&now);
    strftime(msg, 64, "%a, %d %b %Y %H:%M:%S %Z", stm);

    add_rsp_header("Date", msg, r);
    add_rsp_header("Connection", "close", r);
    add_rsp_header("Server", SERVER_VERSION, r);

    sprintf(msg, "%d", strlen(body));
    add_rsp_header("Content-Length", msg, r);
    end_rsp_headers(r);
}


int is_cgi_request(Request *r)
{
    return (strncmp(cgi_path, r->http_path, strlen(cgi_path)) == 0);
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





/* IO functions */
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

static void append_def_err_page(char *body, Request *r)
{
    size_t len = strlen(body);
    if (len > get_qbuf_emptys(r->writebuf)) {
        log_error("Buffer is not enough for error page");
        return;
    }

    produce_qbuf(r->writebuf, body, len);
}
static void end_rsp_headers(Request *r)
{
    if (2 > get_qbuf_emptys(r->writebuf)) {
        log_error("Your headers are too long! Don't send end");
        return;
    }

    produce_qbuf(r->writebuf, "\r\n", 2);
}
static void add_rsp_header(char *name, char *value, Request *r)
{
    size_t nl = strlen(name);
    size_t vl = strlen(value); 
    size_t total = nl + 2 + vl + 2;// include ": " and "\r\n"
    
    if (total > get_qbuf_emptys(r->writebuf)) {
        log_error("Your headers are too long! Don't send this header");
        return;
    }

    produce_qbuf(r->writebuf, name, nl);
    produce_qbuf(r->writebuf, ": ", 2);
    produce_qbuf(r->writebuf, value, vl);
    produce_qbuf(r->writebuf, "\r\n", 2);
}
static void add_status_line(char *version, int code, char *phrase, Request *r)
{
    const size_t MIDDLE = 1 + 3 + 1; // SP code SP
    char cstr[MIDDLE + 1];
    size_t vl = strlen(version);
    size_t pl = strlen(phrase);
    size_t total = vl + MIDDLE + pl + 2;
    
    if (total > get_qbuf_emptys(r->writebuf)) {
        log_error("Your status line is too long! Don't send it");
        return;
    }
    snprintf(cstr, 6, " %d ", code);

    produce_qbuf(r->writebuf, version, vl);
    produce_qbuf(r->writebuf, cstr, MIDDLE);
    produce_qbuf(r->writebuf, phrase, pl);
    produce_qbuf(r->writebuf, "\r\n", 2);
}


int init_request(Request *r)
{
    // It's just a dummy head for linked list.
    r->headers = (Request_header*)malloc(sizeof(Request_header));
    if (!(r->headers)) {
        return -1;
    }
    r->headers->next = NULL;

    r->header_count = 0;
    alloc_qbuf(r->writebuf, WRITE_BUFFER_MAX_SIZE);
    alloc_qbuf(r->readbuf, READ_BUFFER_MAX_SIZE);
    r->resource_type = STATIC_RESOURCE;
    r->content_length = 0;
    r->states = READ_REQ_HEADERS;
    r->rfd = -1;
    r->wfd = -1;
    return 0;
}

static void free_headers(Request_header* head)
{
    Request_header* tmp;
    Request_header* new_hd = head;

    while (new_hd != NULL) {
        tmp = new_hd->next;
        free(new_hd);
        new_hd = tmp;
    }
}

void close_content_wfd(Request *r)
{
    if (r->wfd != -1) {
        close(r->wfd);
        r->wfd = -1;
        FD_CLR(r->wfd, &pool.wready_set);
    }
}
void close_content_rfd(Request *r)
{
    if (r->rfd != -1) {
        close(r->rfd);
        r->rfd = -1;
        FD_CLR(r->rfd, &pool.rready_set);
    }
}

// It doesn't free but reuse some alloced space for next time.
void reset_request(Request* r)
{
    free_headers(r->headers->next);
    r->header_count = 0;

    close_content_wfd(r);
    close_content_rfd(r);
    // Not free but clean
    clean_qbuf(r->readbuf);
    clean_qbuf(r->writebuf);
    r->content_length = 0;
	r->states = READ_REQ_HEADERS;
	r->resource_type = STATIC_RESOURCE;
}


// NULL on error. You should free the returned buffer with free().
char* make_realpath(const char *vpath)
{
    size_t vplen = strlen(vpath);
    size_t wflen = strlen(www_folder);
    size_t l = vplen + wflen + 1;
    char *buf;

    if (l > PATH_MAX) {
        log_debug("Real path too long");
        return NULL;
    }
    if (vpath[0] != '/') {
        log_debug("Virtual path should begin with slash");
        return NULL;
    }

    buf = malloc(l + 1);
    if (!buf) {
        log_error("malloc fail");
        return NULL;
    }

    strcpy(buf, www_folder);
    if (www_folder[wflen - 1] == '\0') {
        strcpy(buf + wflen - 1, vpath);
    } else {
        strcpy(buf + wflen, vpath);
    }
    return buf;
}