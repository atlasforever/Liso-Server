#include "parse.h"

/* Comes from generated Yacc code */ 
int yyparse();
void set_parsing_options(char *buf, size_t siz, Request *request, int *_err_reason);


/**
* Given a char buffer returns the parsed request headers
* success: return 0, parsed request saved to *request
* fail: URI_LONG_FAILURE or REQUEST_FAILURE or OTHER_FAILURE(see parse.h)
*/
int parse(char *buffer, int size, int socketFd, Request *request) {
  //Differant states in the state machine
	enum {
		STATE_START = 0, STATE_CR, STATE_CRLF, STATE_CRLFCR, STATE_CRLFCRLF
	};

	int i = 0, state;
	int err_reason;
	size_t offset = 0;
	char ch;
	char buf[REQUEST_MAX_SIZE];
	memset(buf, 0, REQUEST_MAX_SIZE);

	state = STATE_START;
	while (state != STATE_CRLFCRLF) {
		char expected = 0;

		if (i == size)
			break;

		ch = buffer[i++];
		buf[offset++] = ch;

		switch (state) {
		case STATE_START:
		case STATE_CRLF:
			expected = '\r';
			break;
		case STATE_CR:
		case STATE_CRLFCR:
			expected = '\n';
			break;
		default:
			state = STATE_START;
			continue;
		}

		if (ch == expected)
			state++;
		else
			state = STATE_START;

	}

  //Valid End State
	if (state == STATE_CRLFCRLF) {
    request->header_count=0;
    //TODO You will need to handle resizing this in parser.y
		request->headers->next = NULL;
		set_parsing_options(buf, i, request, &err_reason);

		if (yyparse() == SUCCESS) {
      return 0;
		} else {	// fail parsing
			return err_reason;
		}
	} else {	// not a valid CRLFCRLF end
		return REQUEST_FAILURE;
	}
}


static void free_headers(Request_header *head)
{
	Request_header *tmp;
	Request_header *new_hd = head;
	
	while(new_hd != NULL) {
		tmp = new_hd->next;
		free(new_hd);
		new_hd = tmp;
	}
}

Request* alloc_request()
{
	Request *r = (Request*)malloc(sizeof(Request));
	if (!r) {return NULL;}
	r->headers = (Request_header*)malloc(sizeof(Request_header));
	if (!(r->headers)) {
		free(r);
		return NULL;
	}
	return r;
}
void free_request(Request *rqst)
{
	free_headers(rqst->headers);
	free(rqst);
}