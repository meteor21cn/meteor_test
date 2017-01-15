#ifndef HTTP_AUTH_H_
#define HTTP_AUTH_H_

#include <string.h>
#include <time.h>
#include <hiredis/hiredis.h>

#include "meteor.h"
#include "sockd.h"
#include "../lib/md5c.h"

#define HTTP_AUTH_SUCCESS 			0x00	//success
#define HTTP_AUTH_ERR_UNKOWN		0xff	//unknow error
#define HTTP_AUTH_ERR_ORDER_STATUS	0xfe	//order status not available
#define HTTP_AUTH_ERR_SYS_BUSY		0xfd	//sys busy
#define HTTP_AUTH_ERR_FROZEN		0xfc	//token frozen
#define HTTP_AUTH_ERR_NO_FOUND		0xfb	//token no found or expired
#define HTTP_AUTH_ERR_AT_FLAG		0xfa	//at-flag error
#define HTTP_AUTH_ERR_AUTH_MODE		0xf9	//auth mode error
#define HTTP_AUTH_ERR_AUTH_FAILED		0xf8	//error user or passwd, app_pname

#define HTTP_CONNECT_ERR			0xf7	//error connect remote

#define HTTP_AUTH_NONE			0x00
#define HTTP_AUTH_USER_PASSWORD		0x01

struct http_proxy_response_s
{
	unsigned char status;
	unsigned int order_status;
	int order_balance;
	uint32_t used_today;
	long company_balance;
} ;

http_proxy_response_t * http_auth(socks_worker_process_t *process, socks_connection_t *con,
	http_info_t *http_info, http_proxy_response_t *response);

#endif //HTTP_AUTH_H_


