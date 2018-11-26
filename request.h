#ifndef _REQUEST_H_
#define _REQUEST_H_

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