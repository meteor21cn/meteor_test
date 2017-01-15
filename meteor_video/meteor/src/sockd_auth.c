#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "sockd_auth.h"
#include "sockd_redis.h"
#include "meteor_auth.h"

static int _copy_req_to_session(socks_session_t * session, socks_auth_req_t *req);

//  check username
mtr_auth_reply_t *do_first_auth( socks_worker_process_t *process, socks_connection_t *con, socks_auth_req_t *req, mtr_auth_reply_t *reply )
{
    if ( _copy_req_to_session(con->session, req )< 0){
        // user和passwd不合协议规范，认为鉴权不通过
        reply->status = SOCKS_AUTH_ERR_NO_PASS;
        return reply;
    }
    sys_log(LL_DEBUG, "[ %s:%d ] token:%s, app:%s, passwd:%s", __FILE__, __LINE__, con->session->token, con->session->app_pname, con->session->passwd );

    reply = auth_order(AUTH_SOCKS, process, con, reply);
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
    
    reply->status = check_passwd(AUTH_SOCKS, con->session->token, addr, order->order_key, con->session->passwd );
    if( reply->status == SOCKS_CMD_ERR_AUTH_2ND ){
        //if failed, try get data from redis, then try again
        reply->status = get_order_data_from_redis( process->redis_connect, order, order->token );
        if( reply->status != MTR_ORDER_AUTH_SUCCESS ){
            return reply->status;
        }

        reply->status = check_passwd(AUTH_SOCKS, con->session->token, addr, order->order_key, con->session->passwd );
        if( reply->status == SOCKS_CMD_ERR_AUTH_2ND ){
            order->auth_fail_times++;
            sys_log(LL_DEBUG, "check passwd failed! passwd: %s|%s|%s", con->session->token, 
                order->order_key, addr);
        }
    }

    return reply->status;
}


int send_auth_reply( socks_worker_process_t *process, socks_connection_t *con, mtr_auth_reply_t *reply )
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