#include "parse.h"

/**
* Given a char buffer returns the parsed request headers
*/
Request * parse(char *buffer, int size, int socketFd) {
  //Differant states in the state machine
	enum {
		STATE_START = 0, STATE_CR, STATE_CRLF, STATE_CRLFCR, STATE_CRLFCRLF
	};

	int i = 0, state;
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
		Request *request = (Request *) malloc(sizeof(Request));
    request->header_count=0;
    //TODO You will need to handle resizing this in parser.y
    request->headers = (Request_header *) malloc(sizeof(Request_header)*1);
		request->headers->next = NULL;
		set_parsing_options(buf, i, request);

		if (yyparse() == SUCCESS) {
      return request;
		}
	}
  //TODO Handle Malformed Requests
  printf("Parsing Failed\n");
}

void free_headers(Request_header *head)
{
	Request_header *tmp;
	Request_header *new_hd = head;
	
	while(new_hd != NULL) {
		tmp = new_hd->next;
		free(new_hd);
		new_hd = tmp;
	}
}