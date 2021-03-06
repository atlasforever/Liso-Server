#include <sys/types.h>
#include <sys/socket.h>
#include "lisod.h"
#include "log.h"
#include "parse.h"

/* Comes from generated Yacc code */
int yyparse();
void set_parsing_options(char* buf, size_t siz, Request* request, int* _err_reason);

/* States in the state machine */
enum {
    STATE_START = 0,
    STATE_CR,
    STATE_CRLF,
    STATE_CRLFCR,
    STATE_CRLFCRLF
};


/**
* Given a char buffer returns the parsed request headers
* Success: return 0, parsed request saved to *request*
* Fail: URI_LONG_FAILURE or REQUEST_FAILURE or OTHER_FAILURE(see parse.h)
*/
int parse(char* buffer, int size, Request* request)
{
    int err_reason;

    request->header_count = 0;
    //TODO You will need to handle resizing this in parser.y
    request->headers->next = NULL;
    set_parsing_options(buffer, size, request, &err_reason);
    if (yyparse() == SUCCESS) {
        return 0;
    } else { // fail parsing
        return err_reason;
    }
}

/**
 * Read one request from a nonblocking sock. Caller may call this function many
 * times to completely read one HTTP request.
 * 
 * Return value: n
 * n > 0: Finishing reading a whole request. Size is n
 * 0: Reading is NOT yet completed. Wait to be called nex time.
 * -1: Connection error
 * -2: Bad Request
 */
int recv_one_request(http_client_t *client)
{
    int rn;
    parse_fsm_t *fsm = &(client->pfsm);
    size_t len;

    // Begin to read a new request
    if (fsm->compelted) {
        int offset = fsm->total_bytes - fsm->idx2parse;

        fsm->state = STATE_START;
        fsm->compelted = 0;
        memcpy(fsm->buf, &fsm->buf[fsm->idx2parse], offset);
        fsm->total_bytes = offset;
        fsm->idx2parse = 0;
    }

    len = REQUEST_MAX_SIZE - fsm->total_bytes;
    if (len > 0) {
        if (client->type == HTTP_TYPE) {
            rn = nb_read_fd(client->sockfd, &fsm->buf[fsm->total_bytes], len);
        } else {
            rn = nb_read_ssl(client->client_context, &fsm->buf[fsm->total_bytes], len);
        }
    }
    

    if (rn == -1 || rn == 0) {
        // Client shouldn't close socket now
        fsm->compelted = 1;
        return -1;
    } else if (rn == -2) {
        return 0;
    }

    fsm->total_bytes += rn;

    while (fsm->state != STATE_CRLFCRLF) {
        char expected = 0;

        // Have not seen a CRLFCRLF
        if (fsm->idx2parse == fsm->total_bytes) {
            if (fsm->total_bytes == REQUEST_MAX_SIZE) {
                return -2;  // Request is larger than MAXSIZE
            } else {
                return 0;
            }
        }
        
        switch (fsm->state) {
            case STATE_START:
            case STATE_CRLF:
                expected = '\r';
                break;
            case STATE_CR:
            case STATE_CRLFCR:
                expected = '\n';
                break;
            default:
                log_debug("This state value %d is impossable!!", fsm->state);
                return -1;
        }

        if (fsm->buf[fsm->idx2parse] == expected) {
            fsm->state++;
        } else {
            fsm->state = STATE_START;
        }
        fsm->idx2parse++;
    }

    // Success
    fsm->compelted = 1;
    return fsm->idx2parse;
}

void init_parse_fsm(parse_fsm_t *fsm)
{
    fsm->compelted = 0;
    fsm->idx2parse = 0;
    fsm->state = STATE_START;
    fsm->total_bytes = 0;
}