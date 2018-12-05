#ifndef _REQUEST_H_
#define _REQUEST_H_

/* Size limits in HTTP Message */
#define REQUEST_MAX_SIZE 8192
#define RESPONSE_MAX_SIZE_EXP_BODY 2048
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
    WAIT_STATIC_REQ_BODY,
    WAIT_CGI_REQ_BODY,
    SEND_STATIC_HEADERS,	// Headers of response for static content 
    SEND_CONTENT,	// Can be a static content file or CGI's output 
    CLOSE
} request_states_t;

// HTTP Request Header
typedef struct
{
	char http_version[HTTP_VERSION_MAX_SIZE + 1];
	char http_method[HTTP_METHOD_MAX_SIZE + 1];
	char http_uri[HTTP_URI_MAX_SIZE + 1];
	Request_header *headers;	// dummy head of linked list for headers 
	int header_count;

	// Response headers buffer
	char resp_headers[RESPONSE_MAX_SIZE_EXP_BODY];

	request_states_t states;
	int rfd; // file or CGI-pipe fd this request needs to read from
	int wfd; // file or CGI-pipe fd this request needs to write to
} Request;


int init_request(Request *r);
void free_request(Request *rqst);
int do_request(Request *request, int sockfd);
int response_error(int code, int fd);


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