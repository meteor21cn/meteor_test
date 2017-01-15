#ifndef _HTTP_PARSE_H_
#define _HTTP_PARSE_H_
#include "http_proxy.h"

int http_parse_request_line( char *b ,int length, http_request_t  *r);
int http_parse_request_header_body(char *b ,int length ,http_request_t *r);
int http_parse_response_line(char *b, int length, http_response_t *r);
int http_parse_response_header_body(char *b,http_response_t *r);

#endif/* _HTTP_PARSE_H_ */