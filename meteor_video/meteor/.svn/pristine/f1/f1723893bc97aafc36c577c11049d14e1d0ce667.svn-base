#include <hiredis/hiredis.h>
#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "meteor_auth.h"
#include "sockd_redis.h"

extern socks_module_config_t g_config;

static int _parse_order_events( socks_worker_process_t *process, int event );
static int _parse_activity_events( socks_worker_process_t *process, int activity_event);
static char * _get_redis_errmsg( redisContext* redis_connect, redisReply * reply);
static int _try_reconnect_redis( redisContext** redis_connect, int redis_op_result);

redisContext * redis_init()
{
    redisContext *redis_connect = redisConnect( g_config.redis_host, g_config.redis_port );
    
    if (redis_connect != NULL) 
    {
        if( redis_connect->err ){ 
            fprintf(stderr, "cannot connect to redis server %s:%d\n", g_config.redis_host, g_config.redis_port);
            redisFree(redis_connect);
            return NULL;
        }
        return redis_connect;
    }
    fprintf(stderr, "cannot connect to redis server %s:%d\n", g_config.redis_host, g_config.redis_port);
    return NULL;
}

int check_redis_connect(redisContext** redis_connect)
{
    redisReply *reply = (redisReply*)redisCommand(*redis_connect, "ping");  
    if (reply == NULL)
    {
        fprintf(stderr, "cannot connect to redis server %s:%d\n", g_config.redis_host, g_config.redis_port);
        redisFree(*redis_connect);
        *redis_connect = redis_init();
        if( *redis_init == NULL )
            return -1;
    }
    else
        freeReplyObject(reply);
    return 0;
}

int get_order_data_from_redis(redisContext * redis_connect, socks_order_t *order, unsigned char * token )
{
    int i;
    int err = MTR_ORDER_AUTH_SUCCESS;
    int redis_order_field_count = 0;
    strcpy(order->token, token);

    redisReply *reply = (redisReply *)redisCommand(redis_connect, "hgetall %s%s", REDIS_KEY_PREFIX_ORDER, token );
    if (reply == NULL || reply->type != REDIS_REPLY_ARRAY || reply->elements == 0 )
    {
        sys_log(LL_ERROR, "[ %s:%d ] redis error:%s", __FILE__, __LINE__, _get_redis_errmsg( redis_connect, reply) );
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &redis_connect, REDIS_ERR );
        return MTR_ORDER_AUTH_ERR_NO_FOUND;
    }

    order->idle = 0;
    for( i=0; i<reply->elements; i+=2 )
    {
        if ( !strcmp(reply->element[i]->str, REDIS_FIELD_ORDER_ID) )
        {
            if(strlen(reply->element[i+1]->str)<ORDER_ORDER_ID_LEN )
                strcpy(order->order_id, reply->element[i+1]->str);
            else{
                err = MTR_ORDER_AUTH_ERR_UNKOWN;
                strncpy(order->order_id, reply->element[i+1]->str, ORDER_ORDER_ID_LEN-1 );
                sys_log(LL_ERROR, "[ %s:%d ] order id from redis too long:%s, token:%s", __FILE__, __LINE__, 
                    reply->element[i+1]->str, token );
            }
            redis_order_field_count++;
        }
        else if ( !strcmp(reply->element[i]->str, REDIS_FIELD_PHONE_ID ) )
        {
            if(strlen(reply->element[i+1]->str)<ORDER_PHONE_ID_LEN)
                strcpy(order->phone_id, reply->element[i+1]->str);
            else{
                err = MTR_ORDER_AUTH_ERR_UNKOWN;
                strncpy(order->phone_id, reply->element[i+1]->str, ORDER_PHONE_ID_LEN-1 );
                sys_log(LL_ERROR, "[ %s:%d ] phone_id from redis too long:%s, token:%s", __FILE__, __LINE__, 
                    reply->element[i+1]->str, token );
            }
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ORDER_KEY ) )
        {
            if(strlen(reply->element[i+1]->str)<ORDER_KEY_LEN)
                strcpy(order->order_key, reply->element[i+1]->str);
            else{
                err = MTR_ORDER_AUTH_ERR_UNKOWN;
                strncpy(order->order_key, reply->element[i+1]->str, ORDER_KEY_LEN-1 );
                sys_log(LL_ERROR, "[ %s:%d ] order_key from redis too long:%s, token:%s", __FILE__, __LINE__, 
                    reply->element[i+1]->str, token );
            }
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ORDER_APPS ) )
        {
            if(strlen(reply->element[i+1]->str)<ORDER_APPS_LEN)
                strcpy(order->order_apps, reply->element[i+1]->str);
            else{
                err = MTR_ORDER_AUTH_ERR_UNKOWN;
                strncpy(order->order_apps, reply->element[i+1]->str, ORDER_APPS_LEN-1 );
                sys_log(LL_ERROR, "[ %s:%d ] order_apps from redis too long:%s, token:%s", __FILE__, __LINE__, 
                    reply->element[i+1]->str, token );
            }
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ORDER_STATUS ) )
        {
            order->order_status = atoi(reply->element[i+1]->str);
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ORDER_BALANCE ) )
        {
            order->order_balance = atoi(reply->element[i+1]->str);
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_TODAY_USED_FLOW) )
        {
            order->today_used_flow = atoi(reply->element[i+1]->str);
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_TODAY_USED_STAMP) )
        {
            order->today_used_flow_stamp = atol(reply->element[i+1]->str);
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ORDER_KEY_END_TIME ) )
        {
            order->order_key_endtime = atol(reply->element[i+1]->str) + ORDER_KEY_ENDTIME_INCREASEMENT;
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ORDER_END_TIME ) )
        {
            order->order_endtime = atol(reply->element[i+1]->str);
            redis_order_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ACTIVITY_ID ) )
        {
            order->flow_pool_activity_id = atol(reply->element[i+1]->str);
            redis_order_field_count++;
        }
        else{
            sys_log(LL_ERROR, "[ %s:%d ] error order field, %s:%s", __FILE__, __LINE__, 
                reply->element[i]->str, reply->element[i+1]->str );
        }
    }
    
    sys_log(LL_DEBUG, "[ %s:%d ] token:%s, get %d order fields", __FILE__, __LINE__, token, redis_order_field_count );

    freeReplyObject(reply);
    return err;
}

int get_activity_data_from_redis(redisContext * redis_connect, flow_pool_activity_t *activity )
{
    int i;
    int err = 0;
    int redis_activity_field_count = 0;
 
    redisReply *reply = (redisReply *)redisCommand(redis_connect, "hgetall %s%ld", REDIS_KEY_PREFIX_ACTIVITY, activity->activity_id );
    if (reply == NULL || reply->type != REDIS_REPLY_ARRAY || reply->elements == 0 )
    {
        sys_log(LL_ERROR, "[ %s:%d ] get_activity_data_from_redis error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( redis_connect, reply) );
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &redis_connect, REDIS_ERR );
        return -1;
    }

    for( i=0; i<reply->elements; i+=2 )
    {
        if ( !strcmp(reply->element[i]->str, REDIS_FIELD_ACTIVITY_ID) )
        {
            activity->activity_id = atol(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else if ( !strcmp(reply->element[i]->str, REDIS_FIELD_ACTIVITY_START_TIME ) )
        {
            activity->activity_starttime = atol(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ACTIVITY_END_TIME ) )
        {
            activity->activity_endtime = atol(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ACTIVITY_STATUS ) )
        {
            activity->activity_status = atoi(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_ACTIVITY_BALANCE ) )
        {
            activity->activity_balance = atol(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_TODAY_FLOW_LIMIT ) )
        {
            activity->today_flow_limit = atol(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_TODAY_USER_LIMIT) )
        {
            activity->today_user_limit = atoi(reply->element[i+1]->str);
            redis_activity_field_count++;
        }       
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_TODAY_USERS) )
        {
            activity->today_users = atoi(reply->element[i+1]->str);
            redis_activity_field_count++;
        }       
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_TODAY_USED_FLOW) )
        {
            activity->today_used_flow = atol(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else if (  !strcmp(reply->element[i]->str, REDIS_FIELD_TODAY_USED_STAMP) )
        {
            activity->today_used_flow_stamp = atol(reply->element[i+1]->str);
            redis_activity_field_count++;
        }
        else{
            sys_log(LL_ERROR, "[ %s:%d ] error activity field, %s:%s", __FILE__, __LINE__, reply->element[i]->str, 
                reply->element[i+1]->str );
        }
    }
    
    if( activity->today_flow_limit>0 )
        activity->today_over = ((activity->today_used_flow>activity->today_flow_limit )?1:0);
    if( activity->today_user_limit>0 && activity->today_over == 0 )
        activity->today_over = ((activity->today_users >activity->today_user_limit )?1:0);

    sys_log(LL_DEBUG, "[ %s:%d ] activity_id:%ld, get %d activity fields", __FILE__, __LINE__, 
        activity->activity_id, redis_activity_field_count );

    freeReplyObject(reply);
    return err;
}

int add_to_activity_today_userset(redisContext * redis_connect, socks_order_t *order )
{
    if( !order->activity )
        return 0;
 
    redisReply *reply = (redisReply *)redisCommand(redis_connect, "SADD %s%ld %s", REDIS_KEY_PREFIX_ACTIVITY_TODAY_USERS, 
        order->activity->activity_id, order->order_id );
    if (reply == NULL || reply->type != REDIS_REPLY_INTEGER )
    {
        sys_log(LL_ERROR, "[ %s:%d ] add_to_activity_today_userset error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( redis_connect, reply) );
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &redis_connect, REDIS_ERR );
        return -1;
    }
    freeReplyObject(reply);
    return 0;
}

int update_order_to_redis( socks_worker_process_t *process, socks_order_t *order )
{
    // 更新订单剩余流量
    int ret;
    if( order->no_saved_kbyte==0 )
        ret = redisAppendCommand( process->redis_connect, "hincrby %s%s %s %ld", REDIS_KEY_PREFIX_ORDER, order->token,
            REDIS_FIELD_ORDER_BALANCE,  order->no_saved_kbyte );
    else
        ret = redisAppendCommand( process->redis_connect, "hincrby %s%s %s -%ld", REDIS_KEY_PREFIX_ORDER, order->token,
            REDIS_FIELD_ORDER_BALANCE,  order->no_saved_kbyte );
    if( ret != REDIS_OK ){
        sys_log(LL_ERROR, "[ %s:%d ] append cmd to update order balance error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, NULL) );
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }
    
    time_t now = time(NULL);
    long tuf_stamp = 0;
    if( (order->today_used_flow_stamp+SECONDS_OF_ONE_DAY) < now ){
        // 重置今日流量消耗
        tuf_stamp = get_mid_night_second(now);
        ret = redisAppendCommand( process->redis_connect, "HMSET %s%s %s %ld %s %ld", REDIS_KEY_PREFIX_ORDER, order->token,
            REDIS_FIELD_TODAY_USED_FLOW, order->no_saved_kbyte, REDIS_FIELD_TODAY_USED_STAMP, tuf_stamp );
        if( ret != REDIS_OK ){
            sys_log(LL_ERROR, "[ %s:%d ] append cmd to reset tuf_stamp error:%s", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, NULL) );
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
    }
    else{
        // 更新今日流量消耗
        ret = redisAppendCommand( process->redis_connect, "hincrby %s%s %s %ld", REDIS_KEY_PREFIX_ORDER, order->token,
            REDIS_FIELD_TODAY_USED_FLOW, order->no_saved_kbyte );
        if( ret != REDIS_OK ){
            sys_log(LL_ERROR, "[ %s:%d ] append cmd to update tuf error:%s", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, NULL) );
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
    }

    long nowms = get_current_ms();
    int update_order_status = (order->order_status==ORDER_STATUS_NO_BALANCE || 
        order->order_status==ORDER_STATUS_EXPIRED) && !order->close_updated;
    
    char *redis_event = REDIS_KEY_ORDER_UPDATE_EVENT;
    if( update_order_status ){
        // 更新订单状态
        ret = redisAppendCommand( process->redis_connect, "HSET %s%s %s %d", REDIS_KEY_PREFIX_ORDER, order->token,
            REDIS_FIELD_ORDER_STATUS, order->order_status );
        if( ret != REDIS_OK ){
            sys_log(LL_ERROR, "[ %s:%d ] append cmd to update order status error:%s", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, NULL) );
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
        
        redis_event = (order->order_status==ORDER_STATUS_NO_BALANCE) ? REDIS_KEY_ORDER_OVERFLOW_EVENT : REDIS_KEY_ORDER_EXPIRED_EVENT;
    }

    //添加过期或溢出或更新事件
    ret = redisAppendCommand( process->redis_connect, "ZADD %s %ld %s", redis_event, nowms, order->token );
    if( ret != REDIS_OK ){
        sys_log(LL_ERROR, "[ %s:%d ] append cmd to order event error:%s, event:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, NULL), redis_event );
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }
    
    redisReply *reply = NULL;

    // 获取结果:更新订单剩余流量
    ret = redisGetReply( process->redis_connect, (void **)&reply );
    if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_INTEGER )
    {
        sys_log(LL_ERROR, "[ %s:%d ] update order_balance error:%s, order_id:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, reply), order->order_id);
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }
    order->order_balance = (int)reply->integer;
    freeReplyObject(reply);

    if( tuf_stamp ){
        // 获取结果:重置今日流量消耗
        ret = redisGetReply( process->redis_connect, (void **)&reply );
        if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_STATUS || strcmp(reply->str,"OK") )
        {
            sys_log(LL_ERROR, "[ %s:%d ] reset today_used_flow error:%s, order_id:%s", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, reply), order->order_id);
            if( reply )
                freeReplyObject(reply);
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
        order->today_used_flow = order->no_saved_kbyte;
        order->today_used_flow_stamp = tuf_stamp;
        freeReplyObject(reply);
    }
    else{
        // 获取结果:更新今日流量消耗
        ret = redisGetReply( process->redis_connect, (void **)&reply );
        if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_INTEGER )
        {
            sys_log(LL_ERROR, "[ %s:%d ] update today_used_flow error:%s, order_id:%s", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, reply), order->order_id);
            if( reply )
                freeReplyObject(reply);
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
        order->today_used_flow = (uint32_t)reply->integer;;
        freeReplyObject(reply);
    }
    order->no_saved_kbyte = 0;
    sys_log(LL_DEBUG, "[ %s:%d ] order id:%s, update balance:%ld, today_used_flow:%ld", __FILE__, __LINE__, 
        order->order_id, order->order_balance, order->today_used_flow );

    if( update_order_status ){
        // 获取结果:更新订单状态
        ret = redisGetReply( process->redis_connect, (void **)&reply );
        if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_INTEGER )
        {
            sys_log(LL_ERROR, "[ %s:%d ] update order_status error:%s, order_id:%s", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, reply), order->order_id);
            if( reply )
                freeReplyObject(reply);
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
        order->close_updated = 1;
        freeReplyObject(reply);
    }
    
    //更新成功后刷新时戳, 如果是更新事件, 加入到定时器中
    order->last_update_stamp = nowms;
    if( !update_order_status ){
        // 保存到order timer
        add_order_to_timer_queue( process, order );
    }
    
    // 获取结果:添加过期或溢出或更新事件
    ret = redisGetReply( process->redis_connect, (void **)&reply );
    if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_INTEGER )
    {
        sys_log(LL_ERROR, "[ %s:%d ] add event:%d error:%s, order_id:%s", __FILE__, __LINE__, redis_event, 
            reply?reply->str:"unknow", order->order_id);
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }
    freeReplyObject(reply);

    return 0;
}

int update_activity_to_redis( socks_worker_process_t *process, flow_pool_activity_t *activity )
{
    // 更新活动剩余流量
    int ret;
    if ( activity->no_saved_kbyte == 0 )
        ret = redisAppendCommand( process->redis_connect, "hincrby %s%ld %s %ld", REDIS_KEY_PREFIX_ACTIVITY,
            activity->activity_id,  REDIS_FIELD_ACTIVITY_BALANCE,  activity->no_saved_kbyte );
    else
        ret = redisAppendCommand( process->redis_connect, "hincrby %s%ld %s -%ld", REDIS_KEY_PREFIX_ACTIVITY, 
        activity->activity_id, REDIS_FIELD_ACTIVITY_BALANCE,  activity->no_saved_kbyte );

    if( ret != REDIS_OK ){
        sys_log(LL_ERROR, "[ %s:%d ] append cmd to update activity balance error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, NULL) );
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }

    // 池的情况比较特殊,涉及多进程更新, 今日流量消耗的零点切换需由管理中心负责，子进程只负责提交增量
    // 更新今日流量消耗
    ret = redisAppendCommand( process->redis_connect, "hincrby %s%ld %s %ld", REDIS_KEY_PREFIX_ACTIVITY, 
    activity->activity_id, REDIS_FIELD_TODAY_USED_FLOW, activity->no_saved_kbyte );
    if( ret != REDIS_OK ){
        sys_log(LL_ERROR, "[ %s:%d ] append cmd to update tuf of activity error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, NULL) );
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }

    int update_activity_status = (activity->activity_status==ACTIVITY_STATUS_NO_BALANCE || 
        activity->activity_status==ACTIVITY_STATUS_EXPIRED ) && !activity->close_updated;

    if( update_activity_status ){
        // 更新活动状态
        ret = redisAppendCommand( process->redis_connect, "HSET %s%ld %s %d", REDIS_KEY_PREFIX_ACTIVITY, 
            activity->activity_id,  REDIS_FIELD_ACTIVITY_STATUS, activity->activity_status );
        if( ret != REDIS_OK ){
            sys_log(LL_ERROR, "[ %s:%d ] append cmd to update activity status error:%s", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, NULL) );
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
    }

    redisReply *reply = NULL;

    // 获取结果:更新剩余流量
    ret = redisGetReply( process->redis_connect, (void **)&reply );
    if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_INTEGER )
    {
        sys_log(LL_ERROR, "[ %s:%d ] update activity_balance error:%s, activity_id:%ld", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, reply), activity->activity_id);
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }
    activity->activity_balance = (long)reply->integer;
    freeReplyObject(reply);


    // 获取结果:更新今日流量消耗
    ret = redisGetReply( process->redis_connect, (void **)&reply );
    if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_INTEGER )
    {
        sys_log(LL_ERROR, "[ %s:%d ] update today_used_flow error:%s, activity_id:%ld", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, reply),  activity->activity_id);
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }
    activity->today_used_flow = (long)reply->integer;
    freeReplyObject(reply);

    activity->no_saved_kbyte = 0;
    sys_log(LL_DEBUG, "[ %s:%d ] activity_id:%ld, update balance:%ld, today_used_flow:%ld", __FILE__, __LINE__,  
        activity->activity_id, activity->activity_balance, activity->today_used_flow );

    if( update_activity_status ){
        // 获取结果:更新活动状态
        ret = redisGetReply( process->redis_connect, (void **)&reply );
        if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_INTEGER )
        {
            sys_log(LL_ERROR, "[ %s:%d ] update activity_status error:%s, activity_id:%ld", __FILE__, __LINE__, 
                _get_redis_errmsg( process->redis_connect, reply), activity->activity_id );
            if( reply )
                freeReplyObject(reply);
            _try_reconnect_redis( &process->redis_connect, ret );
            return -1;
        }
        activity->close_updated = 1;
        freeReplyObject(reply);
    }
    
    //更新成功后刷新时戳
    activity->last_update_stamp = get_current_ms();

    //主动从redis获取更新数据
    get_activity_data_from_redis( process->redis_connect, activity );
    return 0;
}

// 从redis取出事件并放入process中
int get_order_events_from_redis( socks_worker_process_t *process )
{
    long nowms = get_current_ms();

    // 获取溢出事件
    int ret = redisAppendCommand( process->redis_connect, "ZRANGEBYSCORE %s (%ld +INF WITHSCORES", REDIS_KEY_ORDER_OVERFLOW_EVENT, 
        process->last_check_order_event_stamp );
    if( ret != REDIS_OK ){
        sys_log(LL_ERROR, "[ %s:%d ] append cmd for order overflow event error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, NULL) );
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }
    
    // 获取更新事件
    ret = redisAppendCommand( process->redis_connect, "ZRANGEBYSCORE %s (%ld +INF WITHSCORES", REDIS_KEY_ORDER_UPDATE_EVENT, 
        process->last_check_order_event_stamp );
    if( ret != REDIS_OK ){
        sys_log(LL_ERROR, "[ %s:%d ] append cmd for order update event error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, NULL) );
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }

    // 获取结果:获取溢出事件
    ret = _parse_order_events( process, REDIS_OVERFLOW_EVENT );
    if( ret< 0 )
        return -1;
    
    // 获取结果:获取更新事件
    ret = _parse_order_events( process, REDIS_UPDATE_EVENT );
    if( ret< 0 )
        return -1;

    process->last_check_order_event_stamp = nowms;
    return 0;
}

static int _parse_order_events( socks_worker_process_t *process, int event )
{
    redisReply *reply = NULL;
    int i, ret, valid_order_count = 0;
    rb_key_t key;

    // 获取结果:获取事件
    char *event_name = (event==REDIS_OVERFLOW_EVENT? "overflow":"update");
    order_timer_t *event_pool = (event==REDIS_OVERFLOW_EVENT?(&process->overflow_events):(&process->update_events));

    ret = redisGetReply( process->redis_connect, (void **)&reply );
    if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_ARRAY )
    {
        sys_log(LL_ERROR, "[ %s:%d ] get %s event error:%s, stamp:%ld", __FILE__, __LINE__, event_name,
            reply?reply->str:"unknow", process->last_check_order_event_stamp );
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }

    for( i=0; i<reply->elements; i+=2 )
    {
        key.pkey = reply->element[i]->str;
        long stamp = atol(reply->element[i+1]->str);
        rb_node_t *node = rb_tree_search( &process->order_cache, &key);
        
        // 如果找不到订单或订单更新时戳是本机的时戳就忽略该事件
        if( node ){
            socks_order_t *order = (socks_order_t *)node->data;
            if( order && order->last_update_stamp != stamp ){
                valid_order_count++;
                
                rb_node_t *evnode = rb_list_pop( &process->rb_node_pool );
                if( evnode ){
                    evnode->key.pkey = order->token;
                    evnode->data = (void *)order;
                    order->redis_event_stamp = stamp;
                    if( rb_tree_insert_node ( event_pool, evnode,0 )<0 )
                        rb_list_add( &process->rb_node_pool, evnode );
                }
                else{
                    sys_log(LL_ERROR, "[ %s:%d ] no memory, %s event ignored:%s, stamp:%ld", __FILE__, __LINE__, 
                        event_name, key.pkey, stamp );
                    freeReplyObject(reply);
                    return -1;
                }
            }
        }
    }

    sys_log(LL_DEBUG, "[ %s:%d ] %s events:%d, valid_order_count:%d", __FILE__, __LINE__, 
        event_name, reply->elements, valid_order_count );
    freeReplyObject(reply);

    return valid_order_count;
}

int update_process_info_to_redis(socks_worker_process_t *process)
{
    long now = time(NULL);
    
    if ((process->last_update_worker_stat_stamp + g_config.worker_stat_update_interval) > now){
        return 0;
    }
    process->last_update_worker_stat_stamp = now;
    
    if( (process->today_sum_flow_stamp+SECONDS_OF_ONE_DAY) < now ){
        process->today_sum_flow_stamp = get_mid_night_second(now);
        process->today_sum_flow_kbyte = 0;
    }

    int order_num = process->order_cache.size;
    int session_num = process->session_num;
    int new_session_num = process->new_session_cache.size;
    int closed_session_num = process->closed_sessions.size;
    int close_order_num = process->will_close_orders.size;
    int update_events_num = process->update_events.size;
    int overflow_events_num = process->overflow_events.size;
    int timer_num = process->order_timer.size;
    int rb_node_pool_num = process->rb_node_pool.size;
    int order_pool_num = process->order_pool.size;
    int invalid_order_num = process->invalid_orders.size;
    int cache_memory_size_in_KB = (sizeof(struct rb_node)*(rb_node_pool_num+order_pool_num+invalid_order_num) 
        + sizeof(socks_order_t)*order_pool_num)>>10;
    int total_memory_size_in_KB = (sizeof(struct rb_node)*(rb_node_pool_num+order_pool_num+order_num+
        session_num+close_order_num+update_events_num+overflow_events_num+timer_num+invalid_order_num+new_session_num) + 
        sizeof(socks_order_t)*(order_pool_num+order_num) + 
        (sizeof(socks_session_t)+3*sizeof(socks_connection_t))*(session_num+closed_session_num))>>10;

    char str_time[16] = {0};
    char cmd[2048] = {0};
    long report_sec = now - ( now % g_config.worker_stat_update_interval );
    struct tm *ptime = localtime( &report_sec );
    
    if( g_config.worker_stat_update_interval % 60 == 0 )
        strftime(str_time, sizeof(str_time), "%H%M", ptime);
    else
        strftime(str_time, sizeof(str_time), "%H%M%S", ptime);
    
    sprintf( cmd, "HMSET %s%s:%d:%s %s %d %s %d %s %d %s %ld %s %ld %s %d %s %d %s %d %s %d %s %d %s %d %s %d %s %d %s %d %s %d %s %d %s %d %s %d %s %d", 
            REDIS_KEY_PREFIX_STAT, process->config->listen_host, process->config->listen_port, str_time,
            REDIS_FIELD_STAT_ORDER, order_num,
            REDIS_FIELD_STAT_SESSION, session_num,
            REDIS_FIELD_STAT_CLOSED_SESSION, closed_session_num,
            REDIS_FIELD_STAT_TODAY_FLOWS, process->today_sum_flow_kbyte,
            REDIS_FIELD_STAT_DISK_FULL_STAMP, get_disk_full_stamp_of_log(),
            REDIS_FIELD_STAT_CLOSE_ORDER, close_order_num,
            REDIS_FIELD_STAT_INVALID_ORDER, invalid_order_num,
            REDIS_FIELD_STAT_UPDATE_EVENT, update_events_num,
            REDIS_FIELD_STAT_OVERFLOW_EVENT, overflow_events_num,
            REDIS_FIELD_STAT_TIMER, timer_num,
            REDIS_FIELD_STAT_NODE_POOL, rb_node_pool_num,
            REDIS_FIELD_STAT_ORDER_POOL, order_pool_num,
            REDIS_FIELD_STAT_NEW_SESSION, new_session_num,
            REDIS_FIELD_STAT_CACHE_MEMORY, cache_memory_size_in_KB,
            REDIS_FIELD_STAT_TOTAL_MEMORY, total_memory_size_in_KB,
            REDIS_FIELD_STAT_NODE_CALLOC, get_rb_node_calloc_count(),
            REDIS_FIELD_STAT_ORDER_CALLOC, get_order_calloc_count(),
            REDIS_FIELD_STAT_NODE_NO_FREE, get_rb_node_calloc_count()-get_rb_node_free_count(),
            REDIS_FIELD_STAT_ORDER_NO_FREE, get_order_calloc_count()-get_order_free_count()
        );

    sys_log(LL_DEBUG, "[ %s:%d ] process stat to redis: %s", __FILE__, __LINE__, cmd );

    int ret = redisAppendCommand( process->redis_connect, cmd);
    if( ret != REDIS_OK ){
        sys_log(LL_ERROR, "[ %s:%d ] append cmd to stat process info error:%s", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, NULL) );
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }

    redisReply * reply = NULL;
    ret = redisGetReply( process->redis_connect, (void **)&reply );
    if (ret != REDIS_OK || reply == NULL || reply->type != REDIS_REPLY_STATUS || strcmp(reply->str,"OK") )
    {
        sys_log(LL_ERROR, "[ %s:%d ] stat process info error:%s, process_id:%d, port:%d", __FILE__, __LINE__, 
            _get_redis_errmsg( process->redis_connect, reply), getpid(), process->config->listen_port);
        if( reply )
            freeReplyObject(reply);
        _try_reconnect_redis( &process->redis_connect, ret );
        return -1;
    }

    freeReplyObject(reply);
    return 0;
}

static char * _get_redis_errmsg( redisContext* redis_connect, redisReply * reply)
{
    if( redis_connect->err != 0 )
        return redis_connect->errstr;
    if( reply && reply->type == REDIS_REPLY_ERROR )
        return reply->str;
    return "unknown";
}


static int _try_reconnect_redis( redisContext** redis_connect, int redis_op_result)
{
    if( redis_op_result == REDIS_OK )
        return 0 ;
    if( (*redis_connect)->err == 0 )
        return 0;
    redisFree( *redis_connect );
    (*redis_connect) = redis_init();
    if( (*redis_connect) == NULL )
        return -1;
    return 0;
}


