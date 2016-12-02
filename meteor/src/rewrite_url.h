#ifndef _REWRITE_URL_H_
#define _REWRITE_URL_H_

int rewrite_url_in_file( socks_worker_process_t *process, socks_connection_t *con,http_response_t * response );

int add_to_md5_cache( socks_worker_process_t *process, socks_order_t *order, char *addr, char *passwd);
int get_md5_without_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, char *passwd);
int get_md5_with_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, char *passwd);
int update_md5_cache(socks_worker_process_t *process, socks_order_t *order);

#endif