#ifndef SOCKD_AUTH_H_
#define SOCKD_AUTH_H_

#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>

#include "meteor.h"
#include "sockd.h"
#include "../lib/md5c.h"

struct socks_auth_req_s 
{
    unsigned char auth_method;
    unsigned char method_version;
    socks_string_t user_name;
    socks_string_t passwd;
} ;

mtr_auth_reply_t *do_first_auth( socks_worker_process_t *process, socks_connection_t *con, 
                socks_auth_req_t *req, mtr_auth_reply_t *reply );

int do_second_auth(socks_worker_process_t *process, socks_connection_t *con, socks_command_t *cmd, 
    socks_command_reply_t *reply );


int send_auth_reply( socks_worker_process_t *process, socks_connection_t *con, mtr_auth_reply_t *reply );

#endif //SOCKD_AUTH_H_


