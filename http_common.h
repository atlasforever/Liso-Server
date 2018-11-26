#ifndef _HTTP_COMMON_H_
#define _HTTP_COMMON_H_


#define HTTP_VERSION "HTTP/1.1"

/*
 * Supported MIME
 */
#define MIME_HTML "text/html"
#define MIME_CSS  "text/css"
#define MIME_PNG  "image/png"
#define MIME_GIF  "image/gif"
#define MIME_JPEG "image/jpeg"
#define MIME_OCTET_STREAM "application/octet-stream"

/*
 * Status Codes
 */
#define HTTP_CONTINUE                           100
#define HTTP_SWITCHING_PROTOCOLS                101

#define HTTP_OK                                 200
#define HTT_CREATED                             201
#define HTTP_ACCEPTED                           202
#define HTTP_NON_AUTHORITATIVE_INFORMATION      203
#define HTTP_NO_CONTENT                         204
#define HTTP_RESET_CONTENT                      205
#define HTTP_PARTIAL_CONTENT                    206
/* No Redirection status code yet */
#define HTTP_BAD_REQUEST                        400
#define HTTP_UNAUTHORIZED                       401
#define HTTP_PAYMENT_REQUIRED                   402
#define HTTP_FORBIDDEN                          403
#define HTTP_NOT_FOUND                          404
#define HTTP_NOT_ALLOWED                        405
#define HTTP_NOT_ACCEPTABLE                     406
#define HTTP_PROXY_AUTHENTICATION_REQUIRED      407
#define HTTP_REQUEST_TIME_OUT                   408
#define HTTP_CONFLICT                           409
#define HTTP_GONE                               410
#define HTTP_LENGTH_REQUIRED                    411
#define HTTP_PRECONDITION_FAILED                412
#define HTTP_REQUEST_ENTITY_TOO_LARGE           413
#define HTTP_REQUEST_URI_TOO_LARGE              414
#define HTTP_UNSUPPORTED_MEDIA_TYPE             415
#define HTTP_RANGE_NOT_SATISFIABLE              416
#define HTTP_EXPECTATION_FAILED                 417

#define HTTP_INTERNAL_SERVER_ERROR              500
#define HTTP_NOT_IMPLEMENTED                    501
#define HTTP_BAD_GATEWAY                        502
#define HTTP_SERVICE_UNAVAILABLE                503
#define HTTP_GATEWAY_TIME_OUT                   504
#define HTTP_VERSION_NOT_SUPPORTED              505





#endif