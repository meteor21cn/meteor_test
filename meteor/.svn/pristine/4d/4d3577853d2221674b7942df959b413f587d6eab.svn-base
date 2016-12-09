#ifndef _HTTP_TRANSFORM_H_
#define _HTTP_TRANSFORM_H_

#include "meteor.h"
#include "sockd.h"
#include "http_parse.h"
#include "http_proxy.h"
#include "sockd_tcp.h"
#include "http_rewrite_url.h"

#define HTTP_CHUNKED_END "0\r\n\r\n"

int connect_http_remote_host_ipv4(socks_worker_process_t *process, socks_connection_t *con );

int send_create_tunnel_response(socks_worker_process_t *process, socks_connection_t *con, 
	http_proxy_response_t *proxy_response, int status);

int send_https_response(socks_worker_process_t *process, socks_connection_t *con, 
	http_proxy_response_t *proxy_response, int status);

#endif /* _HTTP_TRANSFORM_H_ */


