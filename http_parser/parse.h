#ifndef _PARSER_H_
#define _PARSER_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SUCCESS 0
#define FAILURE -1

/* Size limits in HTTP Message */
#define REQUEST_MAX_SIZE 8192
#define HTTP_VERSION_MAX_SIZE 32
#define HTTP_METHOD_MAX_SIZE 32
#define HTTP_URI_MAX_SIZE 4096
#define HEADER_NAME_MAX_SIZE 64
#define HEADER_VALUE_MAX_SIZE 4096

//Header field
typedef struct Request_header Request_header;
struct Request_header
{
	char header_name[HEADER_NAME_MAX_SIZE + 1];
	char header_value[HEADER_VALUE_MAX_SIZE + 1];
	Request_header *next;
};

//HTTP Request Header
typedef struct
{
	char http_version[HTTP_VERSION_MAX_SIZE + 1];
	char http_method[HTTP_METHOD_MAX_SIZE + 1];
	char http_uri[HTTP_URI_MAX_SIZE + 1];
	Request_header *headers;	// dummy linked list head for headers 
	int header_count;
} Request;

Request* parse(char *buffer, int size,int socketFd);
void free_headers(Request_header *head);

#endif