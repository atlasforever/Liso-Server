/**
 * @file parser.y
 * @brief Grammar for HTTP
 * @author Rajul Bhatnagar (2016)
 */

%{
#include "parse.h"
#include "request.h"

/* Define YACCDEBUG to enable debug messages for this lex file */
//#define YACCDEBUG
#define YYERROR_VERBOSE
#ifdef YACCDEBUG
#include <stdio.h>
#define YPRINTF(...) printf(__VA_ARGS__)
#else
#define YPRINTF(...)
#endif

/* yyparse() calls yyerror() on error */
void yyerror (const char *s);

void set_parsing_options(char *buf, size_t siz, Request *request, int *_err_reason);

/* yyparse() calls yylex() to get tokens */
extern int yylex();


/*
** Global variables required for parsing from buffer
** instead of stdin:
*/

/* Pointer to the buffer that contains input */
char *parsing_buf;

/* Current position in the buffer */
int parsing_offset;

/* Buffer size */
size_t parsing_buf_siz;

/* Current parsing_request Header Struct */
Request *parsing_request;
/* To append linked list of headers*/
Request_header *cur_request_header;
/* Error reason */
int *err_reason;
%}


/* Various types values that we can get from lex */
%union {
	char str[8192];	/* from REQUEST_MAX_SIZE */
	int i;
}

%start request

/*
 * Tokens that yacc expects from lex, essentially these are the tokens
 * declared in declaration section of lex file.
 */
%token t_crlf
%token t_backslash
%token t_digit
%token t_dot
%token t_token_char
%token t_lws
%token t_colon
%token t_separators
%token t_sp
%token t_ws

/* Type of value returned for these tokens */
%type<str> t_crlf
%type<i> t_backslash
%type<i> t_digit
%type<i> t_dot
%type<i> t_token_char
%type<str> t_lws
%type<i> t_colon
%type<i> t_separators
%type<i> t_sp
%type<str> t_ws

/*
 * Followed by this, you should have types defined for all the intermediate
 * rules that you will define. These are some of the intermediate rules:
 */
%type<i> allowed_char_for_token
%type<i> allowed_char_for_text
%type<str> ows
%type<str> token
%type<str> text

%%

/*
** The following 2 rules define a token.
*/

/*
 * Rule 1: Allowed characters in a token
 *
 * An excerpt from RFC 2616:
 * --
 * token          = 1*<any CHAR except CTLs or separators>
 * --
 */
allowed_char_for_token:
t_token_char; |
t_digit {
	$$ = '0' + $1;
}; |
t_dot;

/*
 * Rule 2: A token is a sequence of all allowed token chars.
 */
token:
allowed_char_for_token {
	YPRINTF("token: Matched rule 1.\n");
	snprintf($$, REQUEST_MAX_SIZE, "%c", $1);
}; |
token allowed_char_for_token {
	YPRINTF("token: Matched rule 2.\n");
  	if (snprintf($$, REQUEST_MAX_SIZE, "%s%c", $1, $2) < 0) {
		/* make gcc happy */
		*err_reason = REQUEST_FAILURE;
		YYABORT;
	  };
};

/*
** The following 2 rules define text.
*/
/*
 *
 * Rule 3: Allowed characters in text
 *
 * An excerpt from RFC 2616, section 2.2:
 * --
 * The TEXT rule is only used for descriptive field contents and values
 * that are not intended to be interpreted by the message parser. Words
 * of *TEXT MAY contain characters from character sets other than ISO-
 * 8859-1 [22] only when encoded according to the rules of RFC 2047
 * [14].
 *
 * TEXT = <any OCTET except CTLs, but including LWS>
 * --
 *
 */

allowed_char_for_text:
allowed_char_for_token; |
t_separators {
	$$ = $1;
}; |
t_colon {
	$$ = $1;
}; |
t_backslash {
	$$ = $1;
};

/*
 * Rule 4: Text is a sequence of characters allowed in text as per RFC. May
 * 	   also contains spaces.
 */
text: allowed_char_for_text {
	YPRINTF("text: Matched rule 1.\n");
	if (snprintf($$, REQUEST_MAX_SIZE, "%c", $1) < 0) {
		/* make gcc happy */
		*err_reason = REQUEST_FAILURE;
		YYABORT;
	};
}; |
text ows allowed_char_for_text {
	YPRINTF("text: Matched rule 2.\n");
	if (snprintf($$, REQUEST_MAX_SIZE, "%s%s%c", $1, $2, $3) < 0) {
		/* make gcc happy */
		*err_reason = REQUEST_FAILURE;
		YYABORT;
	};
};

/*
 * Rule 5: Optional white spaces
 */
ows: {
	YPRINTF("OWS: Matched rule 1\n");
	$$[0]=0;
}; |
t_sp {
	YPRINTF("OWS: Matched rule 2\n");
	snprintf($$, REQUEST_MAX_SIZE, "%c", $1);
}; |
t_ws {
	YPRINTF("OWS: Matched rule 3\n");
	snprintf($$, REQUEST_MAX_SIZE, "%s", $1);
};

request_line: token t_sp text t_sp text t_crlf {
	YPRINTF("request_Line:\n%s\n%s\n%s\n",$1, $3,$5);
	/* Stop parsing */
	if (strlen($1) > HTTP_METHOD_MAX_SIZE || strlen($5) > HTTP_VERSION_MAX_SIZE) {
		*err_reason = REQUEST_FAILURE;
		YYABORT;
	}
	if (strlen($3) > HTTP_URI_MAX_SIZE) {
		*err_reason = URI_LONG_FAILURE;
		YYABORT;
	}
	strcpy(parsing_request->http_method, $1);
	strcpy(parsing_request->http_uri, $3);
	strcpy(parsing_request->http_version, $5);
}

request_header: token ows t_colon ows text ows t_crlf {
	YPRINTF("request_Header:\n%s\n%s\n",$1,$5);

	Request_header *tmp = (Request_header *) malloc(sizeof(Request_header)*1);

	if (!tmp) {*err_reason = OTHER_FAILURE; YYABORT;}
	if (strlen($1) > HEADER_NAME_MAX_SIZE || strlen($5) > HEADER_VALUE_MAX_SIZE) {
		*err_reason = REQUEST_FAILURE;
		YYABORT;
	}

	strcpy(tmp->header_name, $1);
	strcpy(tmp->header_value, $5);
	parsing_request->header_count++;

	cur_request_header->next = tmp;
	cur_request_header = cur_request_header->next;
	cur_request_header->next = NULL;
};

request_headers: {	/* there can be no headers at all */
	YPRINTF("the last request_Headers\n");
}; |
request_header request_headers { /* For multiple headers */
};

/*
 * You need to fill this rule, and you are done! You have all the assembly
 * needed. You may wish to define your own rules. Please read RFC 2616
 * and the annotated excerpted text on the course website. All the best!
 *
 */
request: request_line request_headers t_crlf{
	YPRINTF("parsing_request: Matched Success.\n");
	return SUCCESS;
};

%%

/* C code */

void set_parsing_options(char *buf, size_t siz, Request *request, int *_err_reason)
{
	parsing_buf = buf;
	parsing_offset = 0;
	parsing_buf_siz = siz;
	parsing_request = request;
	cur_request_header = request->headers;

	err_reason = _err_reason;
	*err_reason = REQUEST_FAILURE;
}

void yyerror (const char *s) {}
