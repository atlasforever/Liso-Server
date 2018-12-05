#ifndef _PARSER_H_
#define _PARSER_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "request.h"

#define SUCCESS 0

/* error reasons from yyparse() */
#define URI_LONG_FAILURE 1	// for 414 URI Too Long
#define REQUEST_FAILURE	2	// for 400 Bad Request
#define OTHER_FAILURE 3		// for 500 Internal Server Error


// State machine for parsing pipelining requests
typedef struct
{
    int state;
    int compelted;
    char buf[REQUEST_MAX_SIZE];
    int total_bytes;
    // resume checking CRLFCRLF from this index in buf.
    int idx2parse;
} parse_fsm_t;


void init_parse_fsm(parse_fsm_t *fsm);
int recv_one_request(http_client_t *client);
int parse(char* buffer, int size, Request* request);

#endif