#ifndef _REQUEST_H_
#define _REQUEST_H_

#include "queue_buf.h"

/* Size limits in HTTP Message */
#define REQUEST_MAX_SIZE 8192
#define HTTP_VERSION_MAX_SIZE 32
#define HTTP_METHOD_MAX_SIZE 32
#define HTTP_URI_MAX_SIZE 2048
#define HEADER_NAME_MAX_SIZE 64
#define HEADER_VALUE_MAX_SIZE 4096

// Header field
typedef struct Request_header Request_header;
struct Request_header
{
	char header_name[HEADER_NAME_MAX_SIZE + 1];
	char header_value[HEADER_VALUE_MAX_SIZE + 1];
	Request_header *next;
};

// HTTP Request States
typedef enum {
    READ_REQ_HEADERS,
	WAIT_REQ_BODY,
	SEND_CONTENT,	// send all of a response
    CLOSE
} request_states_t;
typedef enum {
	STATIC_RESOURCE,
	DYNAMIC_RESOURCE
} request_resource_t;
// HTTP Request Header
typedef struct
{
	char http_version[HTTP_VERSION_MAX_SIZE + 1];
	char http_method[HTTP_METHOD_MAX_SIZE + 1];
	char http_uri[HTTP_URI_MAX_SIZE + 1];
	Request_header *headers;	// dummy head of linked list for headers 
	int header_count;
	int content_length;
	
	request_states_t states;
	request_resource_t resource_type;

	int rfd; // used to read from a fd presenting a static file or a CGI program
	int wfd; // used to write to a fd presenting a static file or a CGI program
	// Response for static request, except the static-file-body part.
	qbuf_t *readbuf;
	qbuf_t *writebuf;
} Request;


int init_request(Request *r);
void reset_request(Request* r);
int do_request(Request *request);
void response_error(int code, Request *r);
int is_cgi_request(Request *r);
void close_content_wfd(int *fd);
void close_content_rfd(int *fd);

// Default error pages
#define HTTP_400_PAGE "<html><head>\r    \
<title> 400 Bad Request</title>\r  \
</head><body><h1> Bad Request</h1></body></html>\r"

#define HTTP_404_PAGE "<html><head>\r    \
<title> 404 Not Found</title>\r  \
</head><body><h1> Not Found</h1></body></html>\r"

#define HTTP_405_PAGE "<html><head>\r    \
<title> 405 Not Allowed</title>\r  \
</head><body><h1> Not Allowed</h1></body></html>\r"

#define HTTP_500_PAGE "<html><head>\r    \
<title> 500 Internal Server Error</title>\r  \
</head><body><h1> Internal Server Error</h1></body></html>\r"

#define HTTP_501_PAGE "<html><head>\r    \
<title> 501 Not Implemented</title>\r  \
</head><body><h1> Not Implemented</h1></body></html>\r"


#endif