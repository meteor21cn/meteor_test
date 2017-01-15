#ifndef HTTP_AUTH_H_
#define HTTP_AUTH_H_

#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>

#include "meteor.h"
#include "sockd.h"
#include "../lib/md5c.h"

mtr_auth_reply_t * http_auth(socks_worker_process_t *process, socks_connection_t *con,
    http_info_t *http_info, mtr_auth_reply_t *reply);

#endif //HTTP_AUTH_H_


