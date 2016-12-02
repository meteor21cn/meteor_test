#ifndef METEOR_AUTH_H_
#define METEOR_AUTH_H_

#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>

#include "meteor.h"
#include "sockd.h"
#include "../lib/md5c.h"

int _init_activity_if_exist(  socks_worker_process_t *process, socks_order_t *order, long nowms );

int _add_to_order_cache( socks_worker_process_t *process, socks_order_t *order );

int _add_to_activity_cache( socks_worker_process_t *process, flow_pool_activity_t *activity );

int _add_to_session_cache( socks_worker_process_t *process, socks_order_t *order, socks_session_t *session );

#endif //METEOR_AUTH_H_


