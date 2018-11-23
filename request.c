#include <sys/types.h>
#include <sys/socket.h>

#include "http_common.h"
#include "parse.h"
#include "common.h"
#include "request.h"

void response_400(int sockfd)
{
    char msg[512];
    int len, ret;

    sprintf(msg, "%s %d %s\r\n", HTTP_VERSION, 400, "Bad Request");
    strcat(msg, "Server: Liso\r\n\r\n");

    len = strlen(msg);
    NO_TEMP_FAILURE(ret = send(sockfd, msg, len, 0));
    if (ret != len) {printf("send 400 failed!\n");}
}