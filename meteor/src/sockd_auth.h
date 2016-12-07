#ifndef SOCKD_AUTH_H_
#define SOCKD_AUTH_H_

#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>

#include "meteor.h"
#include "sockd.h"
#include "../lib/md5c.h"

#define SOCKS_METHOD_VERSION		0x01

#define SOCKS_AUTH_SUCCESS 			0x00    //success
#define SOCKS_AUTH_ERR_UNKOWN		0xff    //unknow error
#define SOCKS_AUTH_ERR_ORDER_STATUS	0xfe    //order status not available
#define SOCKS_AUTH_ERR_SYS_BUSY		0xfd    //sys busy
#define SOCKS_AUTH_ERR_FROZEN		0xfc    //token frozen
#define SOCKS_AUTH_ERR_NO_FOUND		0xfb    //token no found or expired
#define SOCKS_AUTH_ERR_VERSION		0xfa    //method version error
#define SOCKS_AUTH_ERR_NO_PASS		0xf9    //error user or passwd, app_pname

#define SOCKS_AUTH_NONE				0x00
#define SOCKS_AUTH_USER_PASSWORD	0x02
#define SOCKS_AUTH_FLOW_PACKAGE		0x81
#define SOCKS_AUTH_NOT_ACCEPTABLE	0xFF


struct socks_auth_req_s 
{
	unsigned char auth_method;
	unsigned char method_version;
	socks_string_t user_name;
	socks_string_t passwd;
} ;

struct socks_auth_reply_s
{
	unsigned char method_version;
	unsigned char status;
	unsigned char order_status;
	int order_balance;
	uint32_t used_today;
	long company_balance;
} ;

socks_auth_reply_t *do_first_auth( socks_worker_process_t *process, socks_connection_t *con, 
				socks_auth_req_t *req, socks_auth_reply_t *reply );

int do_second_auth(socks_worker_process_t *process, socks_connection_t *con, socks_command_t *cmd, 
	socks_command_reply_t *reply );


int send_auth_reply( socks_worker_process_t *process, socks_connection_t *con, socks_auth_reply_t *reply );

#endif //SOCKD_AUTH_H_


