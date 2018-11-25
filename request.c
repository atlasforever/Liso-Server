#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#include "http_common.h"
#include "log.h"
#include "parse.h"
#include "common.h"
#include "request.h"

#define RESPONSE_LINE_MAX_SIZE 64
#define HEADER_MAX_SIZE 
void do_request(Request *request, int sockfd)
{
    // Not compatible
    if (strncmp(HTTP_VERSION, request->HTTP_VERSION, strlen(HTTP_VERSION)) != 0) {
        response_error(HTTP_BAD_REQUEST, sockfd);
        return;
    }
    if (strncmp("GET", request->http_method, 3) == 0) {

    } else if (strncmp("HEAD", request->http_method, 4) == 0) {

    } else if (strncmp("POST", request->http_method, 4) == 0) {

    } else {
        response_error(HTTP_NOT_IMPLEMENTED, sockfd);
        return;
    }
}


void response_error(int code, int fd)
{
    char msg[64];
    int len, ret;
    struct tm *stm;
    time_t now;

    switch (code) {
    case HTTP_BAD_REQUEST:
    
        sprintf(msg, "%s %d %s\r\n", HTTP_VERSION, 400, "Bad Request");
        break;
    case HTTP_NOT_FOUND:
        sprintf(msg, "%s %d %s\r\n", HTTP_VERSION, 404, "Not Found");
        break;
    case HTTP_NOT_ALLOWED:
        sprintf(msg, "%s %d %s\r\n", HTTP_VERSION, 405, "Not Allowed");
        break;
    case HTTP_INTERNAL_SERVER_ERROR:
        sprintf(msg, "%s %d %s\r\n", HTTP_VERSION, 500, "Internal Server Error");
        break;
    case HTTP_NOT_IMPLEMENTED:
        sprintf(msg, "%s %d %s\r\n", HTTP_VERSION, 501, "Not Implemented");
        break;
    default:
        sprintf(msg, "%s %d %s\r\n", HTTP_VERSION, 400, "Bad Request");
        break;
    }

    now = time(0);
    stm = gmtime(&now);
    strftime()
    strcat(msg, 64, "%a, %d %b %Y %H:%M:%S %Z", stm);
    send_header("Date", msg, fd);
    send_header("Server", SERVER_VERSION);


}

static int end_headers(int fd)
{
    NO_TEMP_FAILURE(sn = send(fd, "\r\n", 2, 0));
    if (sn != 2) {
        return -1;
    }
    return 0;
}
static int send_header(char *name, char *value, int fd)
{
    int nl = strlen(name);
    int vl = strlen(value); 
    int sn;

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
    int sn;

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