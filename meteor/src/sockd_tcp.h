#ifndef SOCKD_TCP_H_
#define SOCKD_TCP_H_

#include "meteor.h"
#include "sockd.h"

int _test_tcp_connect_result( int fd );

int _connect_remote_host_ipv4(socks_worker_process_t *process, socks_connection_t *con );

void _transform_tcp_data( socks_worker_process_t *process, socks_connection_t *con, int send_fd, int up_direct );

void _connect_remote_host_complete_cb(socks_worker_process_t *process, int remote_fd, int events, void *arg);

void _tcp_data_transform_cb(socks_worker_process_t *process, int fd, int events, void *arg);

#endif //SOCKD_TCP_H_

