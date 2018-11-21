/* C declarations used in actions */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "parse.h"

int main(int argc, char **argv){
  //Read from the file the sample
  int fd_in = open(argv[1], O_RDONLY);
  int index;
  Request_header *cur;
  char buf[REQUEST_MAX_SIZE];
	if(fd_in < 0) {
		printf("Failed to open the file\n");
		return 0;
	}
  int readRet = read(fd_in,buf,REQUEST_MAX_SIZE);
  //Parse the buffer to the parse function. You will need to pass the socket fd and the buffer would need to
  //be read from that fd
  Request *request = (Request*)alloc_request();
  int parseRet = parse(buf,readRet,fd_in, request);
  if (parseRet == URI_LONG_FAILURE) {printf("URI TOO LONG!!!!!!!!!!\n");return 0;}
  else if (parseRet == REQUEST_FAILURE) {printf("Bad Request!!!!!!!!!"); return 0;}

  //Just printing everything
  printf("Http Method %s\n",request->http_method);
  printf("Http Version %s\n",request->http_version);
  printf("Http Uri %s\n",request->http_uri);
  for (index = 0, cur = request->headers->next;
       index < request->header_count;
       index++, cur = cur->next) {
    printf("Request Header\n");
    printf("Header name %s Header Value %s\n",cur->header_name,cur->header_value);
  }
  free_request(request);
  return 0;
}