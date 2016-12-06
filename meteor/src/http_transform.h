#ifndef _HTTP_TRANSFORM_H_
#define _HTTP_TRANSFORM_H_

#include "meteor.h"
#include "sockd.h"
#include "http_parse.h"
#include "sockd_tcp.h"
#include "http_rewrite_url.h"

int connect_http_remote_host_ipv4(socks_worker_process_t *process, socks_connection_t *con );

int send_http_response(socks_worker_process_t *process, socks_connection_t *con, http_proxy_response_t *proxy_response, int proxy_mode);

#endif /* _HTTP_TRANSFORM_H_ */


