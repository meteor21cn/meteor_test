#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "sockd_auth.h"
#include "sockd_redis.h"
#include "meteor_auth.h"

extern socks_module_config_t g_config;

int init_activity_if_exist(  socks_worker_process_t *process, socks_order_t *order, long nowms )
{
    if( order->flow_pool_activity_id<=0 )
        return 0;
    
    flow_pool_activity_t *activity = NULL;
    rb_key_t key;
    rb_node_t *node;
    key.lkey = order->flow_pool_activity_id;
    node = rb_tree_search( &process->activity_cache, &key );
    if (!node){
        activity = (flow_pool_activity_t *)calloc(1, sizeof(flow_pool_activity_t));
        if( activity == NULL ){
            sys_log(LL_ERROR, "[ %s:%d ] no memory for activity, activity_id:%d", __FILE__, __LINE__, 
                order->flow_pool_activity_id );
            return -1;
        }
        memset( activity, 0, sizeof(activity) );
        activity->activity_id = order->flow_pool_activity_id;
        if( get_activity_data_from_redis( process->redis_connect, activity)<0 ){
            free( activity );
            return -1;
        }
        
        activity->last_update_stamp = nowms;
        activity->last_data_stamp = nowms;
        order->activity = activity;
        if( add_to_activity_cache(process, activity)<0 ){
            return -1;
        }
    }
    else{
        activity = (flow_pool_activity_t *)node->data;
        order->activity = activity;
    }
    add_to_activity_today_userset( process->redis_connect, order );
    return 0;

}

int add_to_order_cache( socks_worker_process_t *process, socks_order_t *order )
{
    rb_node_t *node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for order_cache rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
        return -1;
    }
    node->key.pkey = order->token;
    node->data = (void *)order;
    if( rb_tree_insert_node( &process->order_cache, node, 0 )<0 )
        rb_list_add( &process->rb_node_pool, node );
    return 0;
}

int add_to_activity_cache( socks_worker_process_t *process, flow_pool_activity_t *activity )
{
    rb_node_t *node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for activity_cache rb_node, activity_id:%s", __FILE__, __LINE__, activity->activity_id);
        return -1;
    }
    node->key.lkey = activity->activity_id;
    node->data = (void *)activity;
    if( rb_tree_insert_node( &process->activity_cache, node, 0 )<0 )
        rb_list_add( &process->rb_node_pool, node );
    return 0;
}


int add_to_session_cache( socks_worker_process_t *process, socks_order_t *order, socks_session_t *session )
{
    session->order = order;
    if (order->session_cache.size == 0)
        rb_tree_init_for_ptr_key( &order->session_cache );

    rb_node_t * node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for session_cache rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
        return -1;
    }
    node->key.pkey = (void *)session;
    node->data = (void *)session;
    if (rb_tree_insert_node( &order->session_cache, node, 0 )< 0 )
        rb_list_add( &process->rb_node_pool, node );
    return 0;
}

int check_activity_if_exist( socks_worker_process_t *process, socks_order_t *order,
    mtr_auth_reply_t *reply, long nowms )
{
    if ( !order->activity ){
        return MTR_ORDER_AUTH_SUCCESS;
    }

    flow_pool_activity_t *activity = order->activity;
    
    if (activity->today_over){
        reply->order_status = ACTIVITY_STATUS_NO_DAILY;
        add_order_to_will_close_queue( process, order );
        return MTR_ORDER_AUTH_ERR_ORDER_STATUS;
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
        return MTR_ORDER_AUTH_ERR_ORDER_STATUS;
    }

    reply->order_status = order->order_status;
    return MTR_ORDER_AUTH_SUCCESS;
}

int check_passwd(unsigned int proxy_mode, unsigned char *token, unsigned char *addr, unsigned char *key, unsigned char *passwd)
{
    char  conbinedstr[1024];
    char  decrypt[16];
    char  hex[33];

    memset( conbinedstr, 0, sizeof(conbinedstr ) );
    memset( decrypt, 0, sizeof(decrypt ) );
    memset( hex, 0, sizeof(hex ) );
    
    sprintf( conbinedstr, "%s|%s|%s", token, key, addr);

    MD5_CTX md5;
    MD5Init(&md5);              
    MD5Update( &md5, conbinedstr, strlen((char *)conbinedstr) );
    MD5Final( &md5, decrypt );       
    MDString2Hex( decrypt, hex ); 

    if(strcmp( passwd, hex) != 0){
        if (proxy_mode == AUTH_SOCKS){
            return SOCKS_CMD_ERR_AUTH_2ND;
        }
        else if (proxy_mode == AUTH_HTTP){
            return HTTP_AUTH_ERR_AUTH_FAILED;
        }
        
    }
    
    if (proxy_mode == AUTH_SOCKS){
        return SOCKS_CMD_SUCCESS;
    }
    else if (proxy_mode == AUTH_HTTP){
        return MTR_ORDER_AUTH_SUCCESS;
    }
}

int check_order( unsigned int proxy_mode, socks_worker_process_t *process, socks_order_t *order, 
    socks_session_t *session, long nowms )
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
            return MTR_ORDER_AUTH_ERR_FROZEN;
        }   
    }

    if( strstr( order->order_apps, session->app_pname ) == NULL){
        get_order_data_from_redis( process->redis_connect, order, order->token );
        if( strstr( order->order_apps, session->app_pname ) == NULL){
            order->auth_fail_times++;
            if (proxy_mode == AUTH_SOCKS){
                return SOCKS_AUTH_ERR_NO_PASS;
            }
            else if (proxy_mode == AUTH_HTTP){
                return HTTP_AUTH_ERR_AUTH_FAILED;
            }
        }
    }

    if( order->order_endtime < nowms ){
        if( order->order_status != ORDER_STATUS_EXPIRED && order->close_updated==0 ){
            order->order_status = ORDER_STATUS_EXPIRED;
            add_order_to_will_close_queue( process, order );
        }
    }

    if( order->order_status != ORDER_STATUS_SUCCESS || order->order_balance <= 0){
        return MTR_ORDER_AUTH_ERR_ORDER_STATUS;
    }

    return MTR_ORDER_AUTH_SUCCESS;
}

mtr_auth_reply_t * auth_order(unsigned int proxy_mode, socks_worker_process_t *process, 
    socks_connection_t *con, mtr_auth_reply_t *reply)
{
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
            reply->status = MTR_ORDER_AUTH_ERR_UNKOWN;
            return reply;
        }

        if( order->order_key_endtime < now ){
            // key过期，重新从redis读取
            long order_key_endtime_old = order->order_key_endtime;
            reply->status = get_order_data_from_redis( process->redis_connect, order, con->session->token );
            if( reply->status != MTR_ORDER_AUTH_SUCCESS){
                reply->order_status = order->order_status;
                reply->order_balance = order->order_balance;
                reply->used_today = order->today_used_flow;
                reply->company_balance = get_balance_of_flow_pool( process, order);
                return reply;
            }

            if( order->order_key_endtime <= order_key_endtime_old ){
                reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
                reply->order_status = order->order_status;
                reply->order_balance = order->order_balance;
                reply->used_today = order->today_used_flow;
                reply->company_balance = get_balance_of_flow_pool( process, order);
                return reply;
            }
            else{
                update_passwd_cache(process, order);
            }
        }

        //检查活动的状态，如果存在活动的话
        reply->status = check_activity_if_exist( process, order, reply, now);
        if( reply->status != MTR_ORDER_AUTH_SUCCESS ){
            reply->order_balance = order->order_balance;
            reply->used_today = order->today_used_flow;
            reply->company_balance = get_balance_of_flow_pool( process, order);
            return reply;
        }

        // 判断订单状态
        reply->status = check_order( proxy_mode, process, order, con->session, now );
        if( reply->status == MTR_ORDER_AUTH_SUCCESS || reply->status == MTR_ORDER_AUTH_ERR_ORDER_STATUS ){
            con->session->order = order;
            reply->order_status = order->order_status;
            reply->order_balance = order->order_balance;
            reply->used_today = order->today_used_flow;
            reply->company_balance = get_balance_of_flow_pool( process, order);
        }

        if( reply->status == MTR_ORDER_AUTH_SUCCESS ){
            //建立session和order的关联关系
            if( add_to_session_cache( process, order, con->session )<0 ){
                reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
                return reply;
            }

            // 保存到order timer
            if( add_order_to_timer_queue( process, order )<0 ){
                reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
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
        reply->status = MTR_ORDER_AUTH_ERR_NO_FOUND;
        return reply;
    }

    // 本机缓存不存在token，从redis读取
    order = order_pool_pop( process );
    if( !order ){
        reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
        return reply;
    }
    
    int pool = order->pool;
    memset( order, 0, sizeof(order) );
    order->pool = pool;     // 确保pool的标识位不被覆盖，用于内存回收处理
    order->last_update_stamp = now;
    order->last_data_stamp = now;
    order->last_chk_stamp = now;
    
    reply->status = get_order_data_from_redis( process->redis_connect, order, con->session->token );
    if( reply->status != MTR_ORDER_AUTH_SUCCESS ){
        reply->order_status = order->order_status;
        reply->order_balance = order->order_balance;
        reply->used_today = order->today_used_flow;
        reply->company_balance = get_balance_of_flow_pool( process, order);
        order_pool_add( process, order);
        // 无效token，加入无效token的缓存
        add_order_to_invalid_cache( process, order );
        return reply;
    }

    if(order->order_key_endtime < now){
        // key过期
        reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
        reply->order_status = order->order_status;
        reply->order_balance = order->order_balance;
        reply->used_today = order->today_used_flow;
        reply->company_balance = get_balance_of_flow_pool( process, order);
        return reply;
    }

    // 如果是流量池活动，进行初始化，忽略初始化失败的情况。FIXME?
    init_activity_if_exist(  process,  order, now);

    //检查活动的状态，如果存在活动的话
    reply->status = check_activity_if_exist( process, order, reply, now);
    if( reply->status != MTR_ORDER_AUTH_SUCCESS ){
        reply->order_balance = order->order_balance;
        reply->used_today = order->today_used_flow;
        reply->company_balance = get_balance_of_flow_pool( process, order);
        order_pool_add( process, order);
        add_order_to_invalid_cache( process, order );
        return reply;
    }

    // 判断订单状态
    reply->status = check_order( proxy_mode, process, order, con->session, now );
    if( reply->status == MTR_ORDER_AUTH_SUCCESS || reply->status == MTR_ORDER_AUTH_ERR_ORDER_STATUS ){
        con->session->order = order;
        reply->order_status = order->order_status;
        reply->order_balance = order->order_balance;
        reply->used_today = order->today_used_flow;
        reply->company_balance = get_balance_of_flow_pool( process, order);
    }

    if( reply->status != MTR_ORDER_AUTH_SUCCESS ){
        order_pool_add( process, order);
        add_order_to_invalid_cache( process, order );
        return reply;
    }
    //将order放入process的order cache
    if( add_to_order_cache( process, order ) <0 ){
        order_pool_add( process, order);
        reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
        return reply;
    }

    //建立session和order的关联关系
    if( add_to_session_cache( process, order, con->session )<0 ){
        order_pool_add( process, order);
        reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
        return reply;
    }

    // 保存到order timer
    if( add_order_to_timer_queue( process, order )<0 ){
        order_pool_add( process, order);
        reply->status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
        return reply;
    }
    
    del_from_new_session_cache( process, con->session );
    
    return reply;
}