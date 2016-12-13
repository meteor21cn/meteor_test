#ifndef _HTTP_REWRITE_URL_H_
#define _HTTP_REWRITE_URL_H_


#include <streamhtmlparser/htmlparser.h>

typedef struct{
    htmlparser_ctx *ctx;

    char *url;
    int inside_url;
    int quoted;
    int last_attr_type;
    int rewrite_first;
    char rewrite_url[1024];
} htmlparser_ctx_ext;

int rewrite_url_in_file( socks_worker_process_t *process, socks_connection_t *con,http_response_t * response );

int add_to_md5_cache( socks_worker_process_t *process, socks_order_t *order, char *addr, char *passwd);
int get_md5_without_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, char **passwd);
int get_md5_with_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, char **passwd);
int update_md5_cache(socks_worker_process_t *process, socks_order_t *order);

#endif