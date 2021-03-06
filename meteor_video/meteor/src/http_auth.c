#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "sockd_auth.h"
#include "sockd_redis.h"
#include "meteor_auth.h"
#include "http_auth.h"
#include "http_proxy.h"

static int _copy_http_info_to_session(socks_session_t * session, http_request_t *request);

static int _check_at_flag_avai(http_info_t *http_info);

static int _http_passwd_check(socks_worker_process_t *process, socks_connection_t *con, 
    http_info_t *http_info, mtr_auth_reply_t *reply );

mtr_auth_reply_t * http_auth(socks_worker_process_t *process, socks_connection_t *con,
    http_info_t *http_info, mtr_auth_reply_t *reply)
{
    if ( _copy_http_info_to_session(con->session, &http_info->request )< 0){
        // user和passwd不合协议规范，认为鉴权不通过
        reply->status = HTTP_AUTH_ERR_AUTH_FAILED;
        return reply;
    }
    sys_log(LL_DEBUG, "[ %s:%d ] token:%s, app:%s, passwd:%s", __FILE__, __LINE__, con->session->token, con->session->app_pname, con->session->passwd );

    socks_order_t *order = con->session->order;
    //检查session是否已有订单
    if (order){
        //若session已有订单，将本次请求订单和已有订单进行对比，不一致则返回错误
        if (strcmp(con->session->token, order->token) != 0){
            reply->status = HTTP_AUTH_ERR_AUTH_FAILED;
            return reply;
        }
    }

    if(http_info->auth_successed == 1){
        //如果session之前鉴权成功，此次不用进行鉴权
        reply->status = MTR_ORDER_AUTH_SUCCESS;
        reply->order_status = order->order_status;
        reply->order_balance = order->order_balance;
        reply->used_today = order->today_used_flow;
        reply->company_balance = get_balance_of_flow_pool( process, order);
        return reply;
    }

    if (_check_at_flag_avai( http_info) < 0){
        reply->status = HTTP_AUTH_ERR_AT_FLAG;
        sys_log(LL_DEBUG, "[ %s:%d ] error at_flag: %d, domain_flag: %d", __FILE__, __LINE__,  http_info->request.at_flag, http_info->request.domain_flag);
        return reply;
    }

    switch(http_info->request.auth_mode)
    {
        case HTTP_AUTH_USER_PASSWORD:
        {
            auth_order(AUTH_SOCKS, process, con, reply);
            if (reply->status != MTR_ORDER_AUTH_SUCCESS){
                sys_log(LL_DEBUG, "[ %s:%d ] error auth failed ! status: %d", __FILE__, __LINE__,  reply->status);
                return reply;
            }

            _http_passwd_check(process, con, http_info, reply);
            if(reply->status != MTR_ORDER_AUTH_SUCCESS){
                sys_log(LL_DEBUG, "[ %s:%d ] error passwd ! status: %d", __FILE__, __LINE__,  reply->status);
                return reply;
            }

            http_info->auth_successed = 1;
            return reply;
        }

        default :
        {
            reply->status = HTTP_AUTH_ERR_AUTH_MODE;
            sys_log(LL_DEBUG, "[ %s:%d ] error auth_mode", __FILE__, __LINE__,  http_info->request.auth_mode);
            return reply;
        }
    }

}

static int _copy_http_info_to_session(socks_session_t * session, http_request_t *request)
{
    int len = request->auth_info_token_end - request->auth_info_token_start + 1;
    if (len < SESSION_TOKEN_MAX_LEN && len>= SESSION_TOKEN_MIN_LEN + 1){
        memcpy(session->token, request->auth_info_token_start, len);
        session->token[len] = '\0';
    }
    else
        return -1;

    len = request->auth_info_app_end - request->auth_info_app_start + 1;
    if( len <SESSION_APP_PNAME_MAX_LEN && len > 1){
        memcpy(session->app_pname, request->auth_info_app_start, len);
        session->app_pname[len] = '\0';
    }
    else
        return -1;

    len = request->auth_info_passwd_end - request->auth_info_passwd_start + 1;
    if( len <SESSION_PASSWD_MAX_LEN  && len > 1){
        memcpy(session->passwd, request->auth_info_passwd_start, len);
        session->passwd[len] = '\0';
    }
    else
        return -1;
    
    return 0;
}

static int _check_at_flag_avai(http_info_t *http_info)
{
    switch(http_info->request.at_flag)
    {
        case HTTP_AT_FLAG_NONE:
        {
            if (http_info->request.domain_flag != HTTP_DOMAIN_FLAG_NONE)
                return -1;
            else
                return 0;
        }

        case HTTP_AT_FLAG_FIRST_CHILD:
        case HTTP_AT_FLAG_SAME:
        case HTTP_AT_FLAG_PARENT:
        case HTTP_AT_FLAG_ALL:
        {
            if (http_info->request.domain_flag != HTTP_DOMAIN_FLAG_REWRITE)
                return -1;
            else
                return 0;
        }

        default:
        {
            return -1;
        }
    }
}

static int _http_passwd_check(socks_worker_process_t *process, socks_connection_t *con, 
    http_info_t *http_info, mtr_auth_reply_t *reply )
{
    socks_order_t *order = con->session->order;
    if (order == NULL) {
        reply->status = HTTP_AUTH_ERR_AUTH_FAILED;
        return reply->status;
    }
    
    //FIXME
    unsigned char addr[512];
    memset(addr, 0, sizeof(addr));
    int len;
    if ( http_info->request.proxy_mode == HTTP_PROXY_MODE_FORWORD ||
        http_info->request.proxy_mode == HTTP_PROXY_MODE_TUNNEL){
        //forword mode
        /*if (http_info->request.header_port_end)
            len = http_info->request.header_port_end - http_info->request.header_host_start + 1;
        else
            len = http_info->request.header_host_end - http_info->request.header_host_start + 1;*/
        if(http_info->request.header_host_start){
            len = http_info->request.header_host_end - http_info->request.header_host_start + 1;
        }
        else if( http_info->request.http_version == HTTP_VERSION_10){
            len = http_info->request.host_end - http_info->request.host_start + 1;
        }

         if(len <= 1){
            sys_log(LL_ERROR, "[ %s:%d ] get  dest host failed !", __FILE__, __LINE__);
            reply->status = HTTP_AUTH_ERR_AUTH_FAILED;
            return reply->status;
        }

        if(http_info->request.header_host_start){
            memcpy(addr, http_info->request.header_host_start, len);
        }
        else if( http_info->request.http_version == HTTP_VERSION_10){
            memcpy(addr, http_info->request.host_start, len);
        }
        
    }
    else if (http_info->request.proxy_mode == HTTP_PROXY_MODE_REVERSE){
        //reverse mode
        /*if (http_info->request.dest_port_end)
            len = http_info->request.dest_port_end - http_info->request.dest_host_start + 1;
        else
            len = http_info->request.dest_host_end - http_info->request.dest_host_start + 1;*/
        if(http_info->request.dest_host_start)
            len = http_info->request.dest_host_end - http_info->request.dest_host_start + 1;

        if(len <= 1){
            sys_log(LL_ERROR, "[ %s:%d ] get  dest host failed !", __FILE__, __LINE__);
            reply->status = HTTP_AUTH_ERR_AUTH_FAILED;
            return reply->status;
        }
        memcpy(addr, http_info->request.dest_host_start, len);
    }
    
    reply->status = check_passwd(AUTH_HTTP, con->session->token, addr, order->order_key, con->session->passwd );
    if( reply->status == HTTP_AUTH_ERR_AUTH_FAILED ){
        //if failed, try get data from redis, then try again
        reply->status = get_order_data_from_redis( process->redis_connect, order, order->token );
        if( reply->status != MTR_ORDER_AUTH_SUCCESS ){
            return reply->status;
        }

        reply->status = check_passwd(AUTH_HTTP, con->session->token, addr, order->order_key, con->session->passwd );
        if( reply->status == HTTP_AUTH_ERR_AUTH_FAILED ){
            order->auth_fail_times++;
            sys_log(LL_DEBUG, "check passwd failed! passwd: %s|%s|%s", con->session->token, 
                order->order_key, addr);
        }
    }

    return reply->status;
}