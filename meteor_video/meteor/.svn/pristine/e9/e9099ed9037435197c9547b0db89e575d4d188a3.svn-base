#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "sockd_auth.h"
#include "sockd_redis.h"
#include "meteor_auth.h"

static int _socks_check_order( socks_worker_process_t *process, socks_order_t *order, socks_session_t *session, long nowms );

static int _copy_req_to_session(socks_session_t * session, socks_auth_req_t *req);

static int _socks_check_activity_if_exist( socks_worker_process_t *process, socks_order_t *order, socks_auth_reply_t *reply, long nowms );

static int _socks_check_passwd(unsigned char *token, unsigned char *addr, unsigned char *key, unsigned char *passwd);


//	check username
socks_auth_reply_t *do_first_auth( socks_worker_process_t *process, socks_connection_t *con, socks_auth_req_t *req, socks_auth_reply_t *reply )
{
	if ( _copy_req_to_session(con->session, req )< 0){
		// user和passwd不合协议规范，认为鉴权不通过
		reply->status = SOCKS_AUTH_ERR_NO_PASS;
		return reply;
	}
	sys_log(LL_DEBUG, "[ %s:%d ] token:%s, app:%s, passwd:%s", __FILE__, __LINE__, con->session->token, con->session->app_pname, con->session->passwd );

	int closed = 0;
	long now = get_current_ms();
	socks_order_t *order = NULL;

	rb_key_t key;
	rb_node_t *node, *next;
	key.pkey = con->session->token;
	node = rb_tree_search( &process->order_cache, &key );
	// 在本机缓存已经存在
	if( node ){
		order = (socks_order_t *)node->data;
		if( !order ){
			reply->status = SOCKS_AUTH_ERR_UNKOWN;
			return reply;
		}

		if( order->order_key_endtime < now ){
			// key过期，重新从redis读取
			reply->status = get_order_data_from_redis( process->redis_connect, order, con->session->token );
			if( reply->status != SOCKS_AUTH_SUCCESS){
				reply->order_status = order->order_status;
				reply->order_balance = order->order_balance;
				reply->used_today = order->today_used_flow;
				reply->company_balance = get_balance_of_flow_pool( process, order);
				return reply;
			}
		}

		//检查活动的状态，如果存在活动的话
		reply->status = _socks_check_activity_if_exist(  process, order, reply, now);
		if( reply->status != SOCKS_AUTH_SUCCESS ){
			reply->order_balance = order->order_balance;
			reply->used_today = order->today_used_flow;
			reply->company_balance = get_balance_of_flow_pool( process, order);
			return reply;
		}

		// 判断订单状态
		reply->status = _socks_check_order( process, order, con->session, now );
		if( reply->status == SOCKS_AUTH_SUCCESS || reply->status == SOCKS_AUTH_ERR_ORDER_STATUS ){
			con->session->order = order;
			reply->order_status = order->order_status;
			reply->order_balance = order->order_balance;
			reply->used_today = order->today_used_flow;
			reply->company_balance = get_balance_of_flow_pool( process, order);
		}

		if( reply->status == SOCKS_AUTH_SUCCESS ){
			//建立session和order的关联关系
			if( _add_to_session_cache( process, order, con->session )<0 ){
				reply->status = SOCKS_AUTH_ERR_SYS_BUSY;
				return reply;
			}

			// 保存到order timer
			if( add_order_to_timer_queue( process, order )<0 ){
				reply->status = SOCKS_AUTH_ERR_SYS_BUSY;
				return reply;
			}
		}
		
		return reply;
	
	}

	// 检查是否是过期的或无效的token，避免查询redis
	node = rb_tree_search( &process->invalid_orders, &key);
	if( node ){
		order = (socks_order_t *)node->data;
		if( order )
			order->last_update_stamp = now;
		reply->status = SOCKS_AUTH_ERR_NO_FOUND;
		return reply;
	}

	// 本机缓存不存在token，从redis读取
	order = order_pool_pop( process );
	if( !order ){
		reply->status = SOCKS_AUTH_ERR_SYS_BUSY;
		return reply;
	}
	
	int pool = order->pool;
	memset( order, 0, sizeof(order) );
	order->pool = pool;		// 确保pool的标识位不被覆盖，用于内存回收处理
	order->last_update_stamp = now;
	order->last_data_stamp = now;
	order->last_chk_stamp = now;
	
	reply->status = get_order_data_from_redis( process->redis_connect, order, con->session->token );
	if( reply->status != SOCKS_AUTH_SUCCESS ){
		reply->order_status = order->order_status;
		reply->order_balance = order->order_balance;
		reply->used_today = order->today_used_flow;
		reply->company_balance = get_balance_of_flow_pool( process, order);
		order_pool_add( process, order);
		// 无效token，加入无效token的缓存
		add_order_to_invalid_cache( process, order );
		return reply;
	}

	// 如果是流量池活动，进行初始化，忽略初始化失败的情况。FIXME?
	_init_activity_if_exist(  process,  order, now);

	//检查活动的状态，如果存在活动的话
	reply->status = _socks_check_activity_if_exist(  process, order, reply, now);
	if( reply->status != SOCKS_AUTH_SUCCESS ){
		reply->order_balance = order->order_balance;
		reply->used_today = order->today_used_flow;
		reply->company_balance = get_balance_of_flow_pool( process, order);
		order_pool_add( process, order);
		add_order_to_invalid_cache( process, order );
		return reply;
	}

	// 判断订单状态
	reply->status = _socks_check_order( process, order, con->session, now );
	if( reply->status == SOCKS_AUTH_SUCCESS || reply->status == SOCKS_AUTH_ERR_ORDER_STATUS ){
		con->session->order = order;
		reply->order_status = order->order_status;
		reply->order_balance = order->order_balance;
		reply->used_today = order->today_used_flow;
		reply->company_balance = get_balance_of_flow_pool( process, order);
	}

	if( reply->status != SOCKS_AUTH_SUCCESS ){
		order_pool_add( process, order);
		add_order_to_invalid_cache( process, order );
		return reply;
	}
	//将order放入process的order cache
	if( _add_to_order_cache( process, order ) <0 ){
		order_pool_add( process, order);
		reply->status = SOCKS_AUTH_ERR_SYS_BUSY;
		return reply;
	}

	//建立session和order的关联关系
	if( _add_to_session_cache( process, order, con->session )<0 ){
		order_pool_add( process, order);
		reply->status = SOCKS_AUTH_ERR_SYS_BUSY;
		return reply;
	}

	// 保存到order timer
	if( add_order_to_timer_queue( process, order )<0 ){
		order_pool_add( process, order);
		reply->status = SOCKS_AUTH_ERR_SYS_BUSY;
		return reply;
	}
	
	del_from_new_session_cache( process, con->session );
	
	return reply;
}


// the second auth
int do_second_auth(socks_worker_process_t *process, socks_connection_t *con, socks_command_t *cmd, 
	socks_command_reply_t *reply )
{
	socks_order_t *order = con->session->order;
	if (order == NULL) {
		reply->status = SOCKS_CMD_ERR_AUTH_1ST;
		return reply->status;
	}
	
	char *addr;
	if( cmd->host.atype == SOCKS_ATYPE_IPV4 )
		addr = inet_ntoa( cmd->host.addr.ipv4 );
	else if( cmd->host.atype == SOCKS_ATYPE_DOMAIN )
		addr = cmd->host.addr.domain;
	else if( cmd->host.atype == SOCKS_ATYPE_IPV6){
		// TODO: 
		//addr = cmd->host.addr.ipv6.ip;
		reply->status = SOCKS_CMD_ERR_ATYPE;
		return reply->status;
	}
	else{
		reply->status = SOCKS_CMD_ERR_ATYPE;
		return reply->status;
	}
	
	reply->status = _socks_check_passwd(con->session->token, addr, order->order_key, con->session->passwd );
	if( reply->status == SOCKS_CMD_ERR_AUTH_2ND ){
		//if failed, try get data from redis, then try again
		reply->status = get_order_data_from_redis( process->redis_connect, order, order->token );
		if( reply->status != SOCKS_AUTH_SUCCESS ){
			return reply->status;
		}

		reply->status = _socks_check_passwd(con->session->token, addr, order->order_key, con->session->passwd );
		if( reply->status == SOCKS_CMD_ERR_AUTH_2ND ){
			order->auth_fail_times++;
			sys_log(LL_DEBUG, "check passwd failed! passwd: %s|%s|%s", con->session->token, 
				order->order_key, addr);
		}
	}

	return reply->status;
}


int send_auth_reply( socks_worker_process_t *process, socks_connection_t *con, socks_auth_reply_t *reply )
{
	//因为地址对齐原因，需要单项copy
	memcpy((void *)&con->buf[0], (void *)reply, 3*sizeof(unsigned char) );
	con->data_length = 3*sizeof(unsigned char);
	memcpy((void *)&con->buf[con->data_length], (void *)&reply->order_balance, sizeof(reply->order_balance) );
	con->data_length += sizeof(reply->order_balance);
	memcpy((void *)&con->buf[con->data_length], (void *)&reply->used_today, sizeof(reply->used_today) );
	con->data_length += sizeof(reply->used_today);
	memcpy((void *)&con->buf[con->data_length], (void *)&reply->company_balance, sizeof(reply->company_balance) );
	con->data_length += sizeof(reply->company_balance);

	int will_send = con->data_length;
	if( con->auth_method == SOCKS_AUTH_USER_PASSWORD )
		will_send = 2;
	
	int len = _send_data_until_length( con, con->fd, will_send );
	if(len <= 0 )	
	{  
		sys_log(LL_ERROR, "[ %s:%d ] auth result send failed, fd:%d", __FILE__, __LINE__, con->fd );
		close_session( process, con->session);
	}
	else
		do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 0, 0 );
	return len;
}


static int _copy_req_to_session(socks_session_t * session, socks_auth_req_t *req)
{
	u_char *pos = (u_char *)strchr( req->user_name.data, '|' );
	if( pos ){
		int len = pos - req->user_name.data;
		if( len < SESSION_TOKEN_MAX_LEN && len>= SESSION_TOKEN_MIN_LEN )
			strncpy(session->token, req->user_name.data, len );
		else
			return -1;

		len = req->user_name.len-len-1;
		if( len <SESSION_APP_PNAME_MAX_LEN )
			strncpy(session->app_pname, pos+1, len );
		else
			return -1;
	}
	else
		return -1;
		

	if (req->passwd.len < SESSION_PASSWD_MAX_LEN){
		strncpy(session->passwd, req->passwd.data, req->passwd.len);
		return 0;
	}

	return -1;
}

static int _socks_check_order( socks_worker_process_t *process, socks_order_t *order, socks_session_t *session, long nowms )
{
	if( order->auth_fail_times >= AUTH_FAIL_TIMES_THRESHOLD ){
		if( order->frozen_stamp + g_config.order_frozen_timeout<nowms && order->frozen_stamp != 0){
			order->auth_fail_times = 0;
			order->frozen = 0;
			order->frozen_stamp = 0;
		}
		else{
			order->frozen = 1;
			order->frozen_stamp = nowms;
			return SOCKS_AUTH_ERR_FROZEN;
		}	
	}

	if( strstr( order->order_apps, session->app_pname ) == NULL){
		get_order_data_from_redis( process->redis_connect, order, order->token );
		if( strstr( order->order_apps, session->app_pname ) == NULL){
			order->auth_fail_times++;
			return SOCKS_AUTH_ERR_NO_PASS;
		}
	}

	if( order->order_endtime < nowms ){
		if( order->order_status != ORDER_STATUS_EXPIRED	&& order->close_updated==0 ){
			order->order_status = ORDER_STATUS_EXPIRED;
			add_order_to_will_close_queue( process, order );
		}
	}

	if( order->order_status != ORDER_STATUS_SUCCESS || order->order_balance <= 0){
		return SOCKS_AUTH_ERR_ORDER_STATUS;
	}

	return SOCKS_AUTH_SUCCESS;
}

static int _socks_check_activity_if_exist( socks_worker_process_t *process, socks_order_t *order, socks_auth_reply_t *reply, long nowms )
{
	if ( !order->activity ){
		reply->order_status = order->order_status;
		return SOCKS_AUTH_SUCCESS;
	}

	flow_pool_activity_t *activity = order->activity;
	
	if (activity->today_over){
		reply->order_status = ACTIVITY_STATUS_NO_DAILY;
		add_order_to_will_close_queue( process, order );
		return SOCKS_AUTH_ERR_ORDER_STATUS;
	}

	if( activity->activity_endtime < nowms ){
		if( activity->activity_status != ACTIVITY_STATUS_EXPIRED && activity->close_updated==0 ){
			activity->activity_status = ACTIVITY_STATUS_EXPIRED;
			// FIXME:  
			order->order_status = ORDER_STATUS_EXPIRED;
			add_order_to_will_close_queue( process, order );
		}
	}
	if( activity->activity_balance <= 0 ){
		if( activity->activity_status != ACTIVITY_STATUS_NO_BALANCE && activity->close_updated==0 ){
			activity->activity_status = ACTIVITY_STATUS_NO_BALANCE;
			add_order_to_will_close_queue( process, order );
		}
	}

	if( activity->activity_status != ACTIVITY_STATUS_NORMAL ){
		reply->order_status = activity->activity_status;
		return SOCKS_AUTH_ERR_ORDER_STATUS;
	}

	reply->order_status = order->order_status;
	return SOCKS_AUTH_SUCCESS;
}

static int _socks_check_passwd(unsigned char *token, unsigned char *addr, unsigned char *key, unsigned char *passwd)
{
	char  conbinedstr[1024];
	char  decrypt[16];
	char  hex[33];

	memset( conbinedstr, 0, sizeof(conbinedstr ) );
	memset( decrypt, 0, sizeof(decrypt ) );
	memset( hex, 0, sizeof(hex ) );
	
	/*strcpy(conbinedstr, token);
	strcat(conbinedstr, addr);
	strcat(conbinedstr, key);*/
	sprintf( conbinedstr, "%s|%s|%s", token, key, addr);

	MD5_CTX md5;
	MD5Init(&md5);              
	MD5Update( &md5, conbinedstr, strlen((char *)conbinedstr) );
	MD5Final( &md5, decrypt );       
	MDString2Hex( decrypt, hex ); 

	if(strcmp( passwd, hex) != 0){
		return SOCKS_CMD_ERR_AUTH_2ND;
	}
	
	return SOCKS_CMD_SUCCESS;
	
}




