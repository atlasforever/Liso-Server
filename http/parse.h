#ifndef _PARSER_H_
#define _PARSER_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SUCCESS 0

/* error reasons from yyparse() */
#define URI_LONG_FAILURE 1	// for 414 URI Too Long
#define REQUEST_FAILURE	2	// for 400 Bad Request
#define OTHER_FAILURE 3		// for 500 Internal Server Error


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


// State machine for parsing pipelining requests
typedef struct
{
    int state;
    int compelted;
    char buf[REQUEST_MAX_SIZE];
    int total_bytes;
    // resume checking CRLFCRLF from this index in buf.
    int idx2parse;
} parse_fsm;


void init_parse_fsm(parse_fsm *fsm);
int recv_one_request(parse_fsm *fsm, int sock);
int parse(char* buffer, int size, Request* request);
Request* alloc_request();
void free_request(Request *rqst);

#endif