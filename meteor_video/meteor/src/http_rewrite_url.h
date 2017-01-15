#ifndef _HTTP_REWRITE_URL_H_
#define _HTTP_REWRITE_URL_H_


#include <streamhtmlparser/htmlparser.h>

typedef struct {
    char *data;
    int length;
}meteor_str_t;


typedef struct{
    htmlparser_ctx *ctx;

    const char *url;
    int inside_url;
    int quoted;
    int last_attr_type;
    char rewrite_url[1024];
} htmlparser_ctx_ext_t;


int rewrite_url_in_m3u8( socks_worker_process_t *process, socks_connection_t *con,http_response_t * response );

int get_passwd_without_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, socks_passwd_t **passwd);
int get_passwd_with_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, socks_passwd_t **passwd);
int update_passwd_cache(socks_worker_process_t *process, socks_order_t *order);
int delete_passwd_from_cache(socks_worker_process_t *process, socks_order_t *order, socks_passwd_t *passwd);

#endif