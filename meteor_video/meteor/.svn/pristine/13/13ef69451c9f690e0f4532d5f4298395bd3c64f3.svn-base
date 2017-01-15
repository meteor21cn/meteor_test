#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "log.h"
#include "sockd_redis.h"

extern long domain_delete_stamp;
static int domain_calloc_count = 0;
static int domain_free_count = 0;

static int order_calloc_count = 0;
static int order_free_count = 0;

static int passwd_calloc_count = 0;
static int passwd_free_count = 0;

static socks_domain_t* _domain_calloc();
static socks_order_t * _order_calloc() ;
static int _calc_order_nosave_kbyte( socks_worker_process_t *process, socks_order_t *order );
static int _calc_session_delta_byte( socks_session_t *session );
static int _calc_session_nosaved_kbyte( socks_session_t *session );
static int _calc_session_total_kbyte( socks_session_t *session );
static int _save_closed_orders_to_redis( socks_worker_process_t *process );
static int _check_and_update_order( socks_worker_process_t *process );
static int _check_and_update_activity( socks_worker_process_t *process );
static void _delete_order_from_cache(socks_worker_process_t *process, socks_order_t *order);
static void _delete_domain_from_cache(socks_worker_process_t *process, socks_domain_t *domain);
static int _stat_and_chk_activity_flow_if_exist( socks_worker_process_t *process, socks_order_t *order, 
    unsigned int no_saved_kbyte, unsigned int session_no_saved_kbyte);
static int _calc_udp_remote_total_kbyte( socks_udp_connection_t * con, int pos );


extern socks_module_config_t g_config;

int domain_pool_init(socks_worker_process_t *process, int size)
{
    int i;
    socks_domain_t *domain;
    memset((void *)&process->domain_pool, 0, sizeof(process->domain_pool));
    rb_list_init( &process->domain_pool, 0 );

    if( size <=0 )
        return -1;
    
    domain = (socks_domain_t *)calloc( size, sizeof(socks_domain_t) );
    if( !domain  )
        return -1;
    
    process->domain_pool.pool = (void *)domain;
    for( i=0; i<size; i++ ){
        domain->pool = 1;
        rb_node_t *node = rb_list_pop( &process->rb_node_pool );
        if( !node ){
            break;
        }
        
        node->data = (void *)domain;
        rb_list_add( &process->domain_pool, node );
        domain++;

    }
    return 0;
}

int domain_pool_defrag( socks_worker_process_t *process, int size)
{
    struct rb_node *head, *next, *nright, *prev2, *next2;
    int i=0;
    socks_domain_t *domain;

    if( domain_calloc_count<=domain_free_count )
        return domain_calloc_count-domain_free_count;

    head = &(process->domain_pool.head);
    next = head->rb_right;
    while( next != head ){
        nright = next->rb_right;
        domain = (socks_domain_t *)next->data;
        if( !domain->pool ){
            if( i++ >size )
                break;
            prev2 = next->rb_left;
            next2 = next->rb_right;
            
            next2->rb_left = prev2;
            prev2->rb_right = next2;
            
            rb_list_add( &process->rb_node_pool, next );
            _delete_domain_from_cache( process, domain );
            domain_free_count++;
            free(domain);
            process->domain_pool.size--;
        }
        next = nright;
    }
    return i;
}

int domain_pool_add(socks_worker_process_t *process, socks_domain_t *domain )
{
    struct rb_node *node, *head, *next;
        
    head = &(process->domain_pool.head);
    next = head->rb_right;
    if( domain == next->data )
        return -1;
        
    node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        // no memory, failed, free order and defrag.
        if( !domain->pool )
            free(domain);
        domain_pool_defrag( process, g_config.pool_defrag_size );
        return -1;
    }
    node->data = (void *)domain;
    rb_list_add( &process->domain_pool, node );

    return 0;
}

static socks_domain_t * _domain_calloc()  
{  
    socks_domain_t *domain = (socks_domain_t *)calloc( 1, sizeof(socks_domain_t) );
    
    // for debug, look the pool is enough?
    domain_calloc_count++;
    sys_log(LL_DEBUG, "[ %s:%d ] domain_calloc_count: %d", __FILE__, __LINE__, domain_calloc_count );
    
    return domain;
} 

static void _delete_domain_from_cache(socks_worker_process_t *process, socks_domain_t *domain)
{
    rb_key_t key;
    struct rb_node *tmp = NULL;

    key.pkey = domain->domain;
    tmp = rb_tree_delete( &process->domain_cache, &key );
    if( tmp )
        rb_list_add( &process->rb_node_pool, tmp );
}

socks_domain_t *domain_pool_pop(socks_worker_process_t *process)
{
    struct rb_node *head, *next, *tmp;
    head = &(process->domain_pool.head);
    next = head->rb_right;
    
    // 如果链表已空，临时创建一个
    if( next == head ){
        return _domain_calloc();
    }

    tmp = rb_list_pop( &process->domain_pool );
    socks_domain_t *domain = (socks_domain_t *)tmp->data;
    rb_list_add( &process->rb_node_pool, tmp );
    if( domain ){
        _delete_domain_from_cache( process, domain );
    }
    
    return domain;
}

int order_pool_init(socks_worker_process_t *process, int size)
{
    int i;
    socks_order_t *order;
    memset((void *)&process->order_pool, 0, sizeof(process->order_pool));
    rb_list_init( &process->order_pool, 0 );

    if( size <=0 )
        return -1;
    
    order = (socks_order_t *)calloc( size, sizeof(socks_order_t) );
    if( !order  )
        return -1;
    
    process->order_pool.pool = (void *)order;
    for( i=0; i<size; i++ ){
        order->pool = 1;
        rb_node_t *node = rb_list_pop( &process->rb_node_pool );
        if( !node ){
            break;
        }
        
        node->data = (void *)order;
        rb_tree_init_for_ptr_key( &order->session_cache );

        rb_tree_init_for_str_key( &order->passwd_cache );
        
        rb_list_add( &process->order_pool, node );
        order++;

    }
    return 0;
}


// 销毁链表
int order_pool_exit(socks_worker_process_t *process)
{
    struct rb_node *head, *next, *tmp;
    socks_order_t *order;


    head = (&process->order_pool.head);
    next = head->rb_right;

    while( next != head ){
        tmp = next->rb_right;
        order = (socks_order_t *)next->data;

        if( order ){
            //passwd_pool_exit(process, order);
            struct rb_node *node;
            char *orderKey = order->order_key;
            node = rb_first( &order->passwd_cache );
            while( node ) {
                if(node->data) {
                    socks_passwd_t *passwd = (socks_passwd_t *)node->data;
                    passwd_pool_add(process, order, passwd);
                }

                rb_node_t *temp = node;
                rb_erase(temp, &order->passwd_cache);
                rb_list_add( &process->rb_node_pool, temp );
                node = rb_next(node);
            }

            _delete_order_from_cache( process, order );
            if( !order->pool ){
                order_free_count++;
                free(order);
            }   
        }
        if( !rb_is_pool(next) )
            free(next);
        next = tmp;
    }

    if( process->order_pool.pool )
        free(process->order_pool.pool);

    return 0;
}

// 从链表中删除临时分配的order,释放内存
int order_pool_defrag( socks_worker_process_t *process, int size)
{
    struct rb_node *head, *next, *nright, *prev2, *next2;
    int i=0;
    socks_order_t *order;

    if( order_calloc_count<=order_free_count )
        return order_calloc_count-order_free_count;

    head = &(process->order_pool.head);
    next = head->rb_right;
    while( next != head ){
        nright = next->rb_right;
        order = (socks_order_t *)next->data;
        if( !order->pool ){
            if( i++ >size )
                break;
            prev2 = next->rb_left;
            next2 = next->rb_right;
            
            next2->rb_left = prev2;
            prev2->rb_right = next2;
            
            rb_list_add( &process->rb_node_pool, next );
            _delete_order_from_cache( process, order );
            order_free_count++;
            free(order);
            process->order_pool.size--;
        }
        next = nright;
    }
    return i;
}

// Note: can not add any same node
int order_pool_add(socks_worker_process_t *process, socks_order_t *order )
{
    struct rb_node *node, *head, *next;
        
    head = &(process->order_pool.head);
    next = head->rb_right;
    if( order == next->data )
        return -1;
        
    node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        // no memory, failed, free order and defrag.
        if( !order->pool )
            free(order);
        order_pool_defrag( process, g_config.pool_defrag_size );
        return -1;
    }
    node->data = (void *)order;
    rb_list_add( &process->order_pool, node );

    return 0;
}

static socks_order_t * _order_calloc()  
{  
    socks_order_t *order = (socks_order_t *)calloc( 1, sizeof(socks_order_t) );
    rb_tree_init_for_ptr_key( &order->session_cache );
    
    // for debug, look the pool is enough?
    order_calloc_count++;
    sys_log(LL_DEBUG, "[ %s:%d ] order_calloc_count: %d", __FILE__, __LINE__, order_calloc_count );
    
    return order;
} 


socks_order_t *order_pool_pop(socks_worker_process_t *process)
{
    struct rb_node *head, *next, *tmp;
    head = &(process->order_pool.head);
    next = head->rb_right;
    
    // 如果链表已空，临时创建一个
    if( next == head ){
        return _order_calloc();
    }

    tmp = rb_list_pop( &process->order_pool );
    socks_order_t *order = (socks_order_t *)tmp->data;
    rb_list_add( &process->rb_node_pool, tmp );
    if( order ){
        _delete_order_from_cache( process, order );
    }
    
    return order;
}

static void _delete_order_from_cache(socks_worker_process_t *process, socks_order_t *order)
{
    rb_key_t key;
    struct rb_node *tmp = NULL;

    key.pkey = order->token;
    tmp = rb_tree_delete( &process->order_cache, &key );
    if( tmp )
        rb_list_add( &process->rb_node_pool, tmp );
    
    tmp = rb_tree_delete( &process->invalid_orders, &key );
    if( tmp )
        rb_list_add( &process->rb_node_pool, tmp );

}


// 整理过期的token缓存
int defrag_invalid_order_cache(socks_worker_process_t *process, long now_ms)
{
    struct rb_node *node, *next;
    int i=0;
    unsigned long stamp = 0;

    node = rb_first( &process->invalid_orders);
    while( node ) {
        next = rb_next(node);
        socks_order_t *order = (socks_order_t *)node->data;
        if( order ){
            if( order->last_update_stamp + g_config.pool_defrag_interval>now_ms ){
                node = next;
                continue;
            }
        }
        if( i++ >g_config.pool_defrag_size)
            break;
        
        rb_erase( node, &process->invalid_orders );
        rb_list_add( &process->rb_node_pool, node );
        
        node = next;
    }
    return i;

}

int add_order_to_timer_queue( socks_worker_process_t *process, socks_order_t *order )
{
    rb_node_t *node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for order_timer rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
        return -1;
    }
    node->key.lkey = order->last_chk_stamp;
    node->data = (void *)order;
    rb_tree_insert_node( &process->order_timer, node, 1 );
    return 0;
}

int add_new_session_to_cache( socks_worker_process_t *process, socks_session_t *session)
{
    rb_node_t *node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for new_session_cache rb_node, fd:%d", __FILE__, __LINE__, session->client->fd );
        return -1;
    }
    
    session->last_data_stamp = get_current_ms();
    node->key.pkey = (void *)session;
    node->data = (void *)session;
    if( rb_tree_insert_node( &process->new_session_cache, node, 0 )<0 ){
        rb_list_add( &process->rb_node_pool, node );
    }
    return 0;
}

int del_from_new_session_cache( socks_worker_process_t *process, socks_session_t *session)
{
    rb_key_t key;
    key.pkey = (void *)session;
    rb_node_t *node = rb_tree_delete( &process->new_session_cache, &key );
    if( !node ){
        return -1;
    }
    rb_list_add( &process->rb_node_pool, node );
    return 0;
}

void delete_domain_cache_all(socks_worker_process_t *process)
{
    time_t now = time(NULL);
    if(domain_delete_stamp == 0)
    {
        return ;
    }
    else if( (domain_delete_stamp+SECONDS_OF_ONE_DAY) < now ){
        domain_delete_stamp = get_mid_night_second(now);
        rb_node_t *node = rb_first(&process->domain_cache);
        for(; node; node = rb_next(node))
        {
            if (!node) {   
                break;  
            }
            if(node->data)  {
                socks_domain_t *domain = (socks_domain_t *)node->data;
                domain_pool_add(process, domain);
            }
            rb_node_t *temp = node;
            rb_erase(temp, &process->domain_cache);
            rb_list_add( &process->rb_node_pool, temp );
        }
    }
}

void close_timedout_new_session( socks_worker_process_t *process )
{
    long now = get_current_ms();
    socks_session_t *session;
    rb_node_t *node, *next;
    
    long expired = now - g_config.session_idle_timeout;
    
    node = rb_first( &process->new_session_cache );
    while( node ) {
        next = rb_next(node);
        session = (socks_session_t  *)node->data;
        if( session->order ){
            node = next;
            continue;
        }
        if( session->last_data_stamp > expired ){
            node = next;
            continue;
        }
        rb_erase( node, &process->new_session_cache );
        rb_list_add( &process->rb_node_pool, node );
        close_session( process, session );
        node = next;
    }

}

// when process exit
void new_session_cache_exit( socks_worker_process_t *process)
{
    socks_session_t *session;
    rb_node_t *node, *next;
    
    node = rb_first( &process->new_session_cache );
    while( node ) {
        next = rb_next(node);
        session = (socks_session_t  *)node->data;
        if( !session->order ){
            close_session( process, session );
        }
        
        rb_erase( node, &process->new_session_cache );
        if( !rb_is_pool(node) )
            free(node);
        node = next;
    }
}


// 将无效订单加入到无效订单缓存, 有效订单不能放入其中
int add_order_to_invalid_cache( socks_worker_process_t *process, socks_order_t *order )
{
    if( order->order_status == ORDER_STATUS_SUCCESS )
        return -1;
    
    if( process->invalid_orders.size >= MAX_INVALID_TOKENS )
        return -1;
        
    rb_node_t *node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for invalid_orders rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
        return -1;
    }
    node->key.pkey = order->token;
    node->data = (void *)order;
    if( rb_tree_insert_node( &process->invalid_orders, node, 0 ) <0 )
        rb_list_add( &process->rb_node_pool, node );
    
    return 0;
}


int add_order_to_will_close_queue( socks_worker_process_t *process, socks_order_t *order )
{
    rb_node_t *node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for will_close_orders rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
        return -1;
    }
    node->key.pkey = order->token;
    node->data = (void *)order;
    rb_tree_insert_node( &process->will_close_orders, node, 0 );
    return 0;
}


long get_balance_of_flow_pool( socks_worker_process_t *process, socks_order_t *order )
{
    if( order->activity )
        return order->activity->activity_balance;
    return FLOW_POOL_BALANCE_DEFAULT;
}


int do_stat_order_flow(socks_worker_process_t *process, socks_session_t *session, int recv_len, int up_direct, int is_data_flow)
{
    //sys_log(LL_DEBUG, "[ %s:%d ] %d: recv from, %s, bytes:%d", __FILE__, __LINE__, now, up_direct?"client":"remote", recv_len );

    if( !session )
        return -1;

    long now = get_current_ms();
    session->last_data_stamp = now;
    session->no_saved_byte_num += recv_len;

    if( is_data_flow ){  // 实际数据类流量
        if( up_direct ){
            session->up_byte_num += recv_len;
            if( !session->first_request_stamp ){
                session->first_request_stamp = now;
            }
        }
        else{
            session->down_byte_num += recv_len;
            if( !session->first_response_stamp ){
                session->first_response_stamp = now;
            }
        }
    }
    else{   // session控制类流量
        session->control_byte_num += recv_len;
    }

    socks_order_t *order = session->order;
    if( order && order->idle == 1 )
        order->idle = 0;
    
    // 无订单信息, 或订单更新时间少于1s, 或订单已用完，将不继续检测
    if( !order || order->order_status == ORDER_STATUS_NO_BALANCE ) {    
        return 0;
    }

    unsigned int no_saved_kbyte = session->no_saved_byte_num>>10;
    if (no_saved_kbyte == 0){
        return 0;
    }

    order->no_saved_kbyte += no_saved_kbyte;
    process->today_sum_flow_kbyte += no_saved_kbyte;
    session->no_saved_byte_num &= 1023;
    
    unsigned int session_no_saved_kbyte = _calc_session_nosaved_kbyte(session);
    sys_log(LL_DEBUG, "[ %s:%d ] order id:%s, balance: %d, no_saved_kbyte:%d", __FILE__, __LINE__, 
        order->order_id, order->order_balance, no_saved_kbyte );

    _stat_and_chk_activity_flow_if_exist( process, order, no_saved_kbyte, session_no_saved_kbyte );

    if( order->order_balance <= (order->no_saved_kbyte+session_no_saved_kbyte) ){
        order->order_status = ORDER_STATUS_NO_BALANCE;
        order->close_updated = 0;
        
        // 放入已关闭的order，等待提交到redis并释放内存
        if( add_order_to_will_close_queue( process, order )< 0 ){
            sys_log(LL_ERROR, "[ %s:%d ] put will_close_orders failed, order overflow:fd:%d, order_id:%s",
                __FILE__, __LINE__, session->client->fd, order->order_id ); 
        }
    }
    
    return 0;

}

static int _stat_and_chk_activity_flow_if_exist( socks_worker_process_t *process, socks_order_t *order, 
    unsigned int no_saved_kbyte, unsigned int session_no_saved_kbyte)
{
    if ( !order->activity ){
        return 0;
    }
    
    flow_pool_activity_t *activity = order->activity;
    
    if( no_saved_kbyte >0 ){
        activity->no_saved_kbyte += no_saved_kbyte;
        activity->today_used_flow += no_saved_kbyte;
        activity->activity_balance -= no_saved_kbyte;
    }
    
    int to_close_order = 0;
    if (activity->activity_balance <= session_no_saved_kbyte ){
        activity->activity_status = ACTIVITY_STATUS_NO_BALANCE;
        activity->close_updated = 0;
        to_close_order = 1;
    }

    if( activity->today_flow_limit >0 && (activity->today_used_flow+session_no_saved_kbyte)> activity->today_flow_limit )
        activity->today_over = 1;

    if (order->activity->today_over){
        to_close_order = 1;
    }

    if (activity->activity_status != ACTIVITY_STATUS_NORMAL){
        to_close_order = 1;
    }

    if (to_close_order){
        order->close_updated = 0;
        if( add_order_to_will_close_queue( process, order )< 0 ){
            sys_log(LL_ERROR, "[ %s:%d ] put will_close_orders failed, activity overflow:activity_id:%d, order_id:%s",
                __FILE__, __LINE__, activity->activity_id, order->order_id ); 
        }
    }
    
    return 0;   

}

// 当session关闭时，将session的流量更新到order中, 并记录流量话单
int update_order_when_session_close(socks_session_t *session )
{
    socks_order_t *order = session->order;
    
    if( !order ) {
        return -1;
    }

    _calc_session_total_kbyte(session);
    long session_no_saved_kbyte = _calc_session_nosaved_kbyte(session);
    order->no_saved_kbyte += session_no_saved_kbyte;
    if (order->activity){
        order->activity->no_saved_kbyte += session_no_saved_kbyte;
    }
    
    long request_delta_time = session->first_request_stamp?(session->first_request_stamp-session->connect_stamp):0;
    long response_delta_time = session->first_response_stamp?(session->first_response_stamp-session->connect_stamp):0;
    long last_delta_time = session->last_data_stamp?(session->last_data_stamp-session->connect_stamp):0;

    char *protocol_name = "-";
    char *client_hostname = "-";
    int client_port = 0;
    char *remote_hostname = "-";
    int remote_port = 0;

    if( session->protocol==SOCKS_PROTOCOL_TCP || session->protocol == HTTP_PROTOCOL){
        if( session->client!=NULL ){
            if(session->protocol==SOCKS_PROTOCOL_TCP)
                protocol_name = "tcp";
            else
                protocol_name = "http";
            client_port = ntohs(session->client->peer_host.port);
            if( strlen(session->client->peer_hostname)>0)
                client_hostname = session->client->peer_hostname;
        }

        if( session->remote !=NULL ){
            remote_port = ntohs(session->remote->peer_host.port) ;
            if( strlen(session->remote->peer_hostname)>0)
                remote_hostname = session->remote->peer_hostname;
        }
    }
    else {
        if( session->udp_client != NULL || session->udp_remote != NULL){
            protocol_name = "udp";
            socks_udp_connection_t * client = ( session->udp_remote != NULL ? session->udp_remote : session->udp_client);
            client_port = ntohs(client->peer_host.port) ;
            if( strlen(client->peer_hostname)>0)
                client_hostname = client->peer_hostname;
            
            int i;
            for ( i = 0; i <client->udp_remote_num; i++ ){
                remote_hostname = inet_ntoa(client->remote_addr[i].sin_addr);
                remote_port = ntohs(client->remote_addr[i].sin_port);
                
                flow_log("%s %s %ld %s %s %s:%d-%s:%d %d cs:%ld %ld %ld %ld cf:%d %d %d %d", 
                    protocol_name, order->order_id, order->flow_pool_activity_id, order->phone_id, 
                    session->app_pname, client_hostname, client_port, remote_hostname, remote_port, session->closed_by,
                    session->connect_stamp, request_delta_time, response_delta_time, last_delta_time, 
                    0, client->remote_up_byte_num[i],   client->remote_down_byte_num[i],
                    _calc_udp_remote_total_kbyte( client, i ) );
            }
            remote_hostname = "-total";
            remote_port = client->udp_remote_num;
        }
    }

    flow_log("%s %s %ld %s %s %s:%d-%s:%d %d cs:%ld %ld %ld %ld cf:%d %d %d %d", 
        protocol_name, order->order_id, order->flow_pool_activity_id, order->phone_id, 
        session->app_pname, client_hostname, client_port, remote_hostname, remote_port, session->closed_by,
        session->connect_stamp, request_delta_time, response_delta_time, last_delta_time, 
        session->control_byte_num, session->up_byte_num, session->down_byte_num, session->total_kbyte_num );

    return 0;
}

// 保存过期或溢出订单到redis,并触发相应redis事件
static int _save_closed_orders_to_redis( socks_worker_process_t *process )
{
    rb_node_t *node, *next, *tmp;
    socks_order_t *order;
    int i=0;

    node = rb_first( &process->will_close_orders );
    while( node ) {
        next = rb_next(node);
        order = (socks_order_t  *)node->data;
        i++;
        if( !order->close_updated ){

            // 关闭订单的所有session
            rb_node_t *snode, *snext;
            snode= rb_first( &order->session_cache );
            while( snode ) {
                snext = rb_next( snode );
                socks_session_t *session =(socks_session_t *)snode->data;
                close_session( process, session );
                snode = snext;
            }

            // save flow data to redis and add overflow event to redis
            if( order->no_saved_kbyte>0 ){
                update_order_to_redis( process, order );
                //更新活动的流量，如果活动存在的话
                _stat_and_chk_activity_flow_if_exist( process, order, 0, 0 );
            }
        }
        
        if( order->close_updated ){
            rb_erase( node, &process->will_close_orders );
            rb_list_add( &process->rb_node_pool, node );
            // 空闲的非冻结订单必须删除, 防止数据丢失
            if( (order->idle || order->order_status != ORDER_STATUS_SUCCESS) && !order->frozen ){
                rb_key_t key;
                key.pkey = order->token;
                tmp = rb_tree_delete( &process->order_cache, &key );
                if( tmp )
                    rb_list_add( &process->rb_node_pool, tmp );
                if (order->order_status != ORDER_STATUS_SUCCESS)
                    add_order_to_invalid_cache( process, order);
            }
            // 回收非冻结的订单，而已冻结的订单不能回收，否则起不到冻结作用
            if( !order->frozen )
                order_pool_add( process, order);
        }
        node = next;
            
    }
    return i;
}

int save_orders_when_process_exit( socks_worker_process_t *process )
{
    rb_node_t *node, *next;
    socks_order_t *order;

    sys_log( LL_DEBUG,"to delete orders:%d", __FILE__, __LINE__, process->order_cache.size );
    
    node = rb_first( &process->order_cache );
    while( node ) {
        next = rb_next(node);
        order = (socks_order_t  *)node->data;
        if( !order ){
            goto to_delete_node;
        }
        int nosave_kbyte = _calc_order_nosave_kbyte( process, order );
        if( nosave_kbyte > 0 ){
            // save flow data to redis and add overflow event to redis
            update_order_to_redis( process, order );
            _stat_and_chk_activity_flow_if_exist( process, order, 0, 0 );
        }

        if( !order->pool ){
            free(order);
        }
        
        to_delete_node:
            rb_erase( node, &process->order_cache );
            if( !rb_is_pool(node) ){
                free(node);
            }
            else
                node->data = NULL;
            node = next;
            
    }
    return 0;
}

// for debug
int calc_session_of_orders( socks_worker_process_t *process )
{
    rb_node_t *node, *next;
    socks_order_t *order;
    int sum = 0;
    
    sys_log( LL_ERROR,"cache orders:%d", __FILE__, __LINE__, process->order_cache.size );
    
    node = rb_first( &process->order_cache );
    while( node ) {
        next = rb_next(node);
        order = (socks_order_t  *)node->data;
        if( !order ){
            sys_log( LL_ERROR,"invalid node in order_cache:%s", __FILE__, __LINE__, node->key.pkey );
            continue;
        }
        sum += order->session_cache.size;
        node = next;
    }
    return sum;
}


int save_activity_when_process_exit( socks_worker_process_t *process )
{
    rb_node_t *node, *next;
    flow_pool_activity_t *activity;

    sys_log( LL_DEBUG,"to delete activity:%d", __FILE__, __LINE__, process->order_cache.size );
    
    node = rb_first( &process->activity_cache );
    while( node ) {
        next = rb_next(node);
        activity = (flow_pool_activity_t  *)node->data;
        int nosave_kbyte = activity->no_saved_kbyte;
        if( nosave_kbyte > 0 ){
            // save flow data to redis and add overflow event to redis
            update_activity_to_redis( process, activity );
        }
        rb_erase( node, &process->activity_cache );
        if( !rb_is_pool(node) ){
            free(node);
        }
        node = next;
            
    }
    return 0;
}


// 检查订单有效期，其他主机的redis事件, session是否空闲太久，流量是否溢出，key的有效期,长时间无流量发生
static int _check_and_update_order( socks_worker_process_t *process )
{
    long now = get_current_ms();
    socks_order_t *order;
    rb_node_t *node, *next, *evnode, *close_node;
    rb_key_t key;

    int timer = TIMER_DEFAULT;
    node = rb_first( &process->order_timer );
    while( node ) {
        next = rb_next(node);
        order = (socks_order_t  *)node->data;
        
        // 未到检查时间间隔
        timer = (node->key.lkey+g_config.order_check_interval)- now;
        if( timer >0 ){
            break;
        }
        
        rb_erase( node, &process->order_timer );
        
        // 由于order_timer中存在重复订单的可能，如果最后检查时间是当前时间，说明本轮已经处理过该订单了,忽略这个node
        if( order->last_chk_stamp == now ){
            rb_list_add( &process->rb_node_pool, node );
            node = next;
            continue;
        }
        order->last_chk_stamp = now;
        
        // 订单过期，加入到待关闭的订单中
        if( order->order_endtime < now ){
            if( order->order_status != ORDER_STATUS_EXPIRED && order->close_updated==0 ){
                order->order_status = ORDER_STATUS_EXPIRED;
                node->key.pkey = order->token;
                rb_tree_insert_node( &process->will_close_orders, node, 0 );
            }
            else{
                rb_list_add( &process->rb_node_pool, node );
            }   
            node = next;
            continue;
        }

        int need_update = 0;
        int need_close = 0;

        int nosaved_kbyte = _calc_order_nosave_kbyte( process, order);
        if( nosaved_kbyte>0 && order->order_balance <= nosaved_kbyte ){
            // 订单溢出
            order->order_status = ORDER_STATUS_NO_BALANCE;
            order->close_updated = 0;
            node->key.pkey = order->token;
            rb_tree_insert_node( &process->will_close_orders, node, 0 );
            node = next;
            continue;
        }

        // 是否其他主机有更新事件
        key.pkey = order->token;
        evnode = rb_tree_search( &process->update_events, &key );
        if( evnode ){
            need_update = 1;
            rb_erase( evnode, &process->update_events );
            rb_list_add( &process->rb_node_pool, evnode );
        }
        else if( order->last_update_stamp + g_config.order_update_interval < now ){ // 订单更新间隔时间到了
            if( nosaved_kbyte > 0 )
                need_update = 1;
        }
        // 订单长时间无流量, 须更新并关闭order
        if( order->last_data_stamp + g_config.order_idle_timeout< now ){
            need_close = 1;
            order->idle = 1;
        }
        // 订单key过期, 须更新并关闭order
        if( order->order_key_endtime < now ){
            need_close = 1;
            order->idle = 1;
        }

        if( need_update ){
            if( order->no_saved_kbyte >0 ){
                update_order_to_redis( process, order );
                if( order->order_balance <= 0 ){
                    need_close = 1;
                }
                else{
                    rb_list_add( &process->rb_node_pool, node );
                }
            }
            else{
                order->last_update_stamp = now;
                node->key.lkey = order->last_chk_stamp;
                rb_tree_insert_node( &process->order_timer, node, 1 );
                //add_order_to_timer_queue( process, order);
                //rb_list_add( &process->rb_node_pool, node );
            }
        }

        else if( need_close ){
            order->close_updated = 1;
            node->key.pkey = order->token;
            rb_tree_insert_node( &process->will_close_orders, node, 0 );
        }

        
        if ( !need_update && !need_close ){
            node->key.lkey = order->last_chk_stamp;
            rb_tree_insert_node( &process->order_timer, node, 1 );
        }
            

        node = next;
    }
    
    sys_log(LL_DEBUG,"[ %s:%d ] the _check_and_update_order timer:%d", __FILE__, __LINE__ ,timer);
    return timer;
}

static int _check_and_update_activity( socks_worker_process_t *process )
{
    long now = get_current_ms();
    flow_pool_activity_t * activity;
    rb_node_t *node, *next, *acnode, *close_node;
    rb_key_t key;

    node = rb_first(&process->activity_cache);
    while (node)
    {
        next = rb_next(node);
        
        activity = (flow_pool_activity_t *)node->data;
        if( (activity->last_update_stamp + g_config.activity_check_interval) > now ){
            node = next;
            continue;
        }

        if( activity->activity_endtime < now ){
            if( activity->close_updated==0 ){
                activity->activity_status = ACTIVITY_STATUS_EXPIRED;
                update_activity_to_redis(process, activity);
            }   
            node = next;
            continue;
        }

        if( activity->activity_balance <= 0 ){
            if( activity->close_updated==0 ){
                activity->activity_status = ACTIVITY_STATUS_NO_BALANCE;
                update_activity_to_redis(process, activity);
            }   
            node = next;
            continue;
        }
        if(  activity->today_over==1 ){
            if( activity->close_updated== 0 ){
                activity->close_updated = 1 ;
                update_activity_to_redis(process, activity);
            }   
            node = next;
            continue;
        }
        if( activity->last_update_stamp + g_config.activity_update_interval < now ){
            if( activity->no_saved_kbyte > 0 ){
                update_activity_to_redis( process, activity );
                if( activity->activity_balance <= 0 ){
                    activity->activity_status = ACTIVITY_STATUS_NO_BALANCE;
                    activity->close_updated = 0;
                }
            }
        }
        
        node = next;
    }
}

int handle_order_timer( socks_worker_process_t *process )
{
    long now = get_current_ms();
    socks_order_t *order;
    flow_pool_activity_t * activity;
    rb_node_t *node, *next ;

// 为了性能已经去掉了，放到当错误发生时才检查redis的连接状态
/*  if( check_redis_connect( &process->redis_connect )< 0 ){
        sys_log(LL_ERROR, "[ %s:%d ] redis connection not work. %s:%d", __FILE__, __LINE__, 
            g_config.redis_host, g_config.redis_port); 
        return -1;
    }
*/  
    delete_domain_cache_all(process);
    // 检查超时的异常连接(未经过鉴权步骤的)
    close_timedout_new_session(  process );

    // 其他主机是否有溢出事件
    if( process->last_check_order_event_stamp + g_config.order_event_check_interval < now ){
        get_order_events_from_redis(process);
        
        node = rb_first( &process->overflow_events );
        while( node ) {
            next = rb_next(node);
            order = (socks_order_t  *)node->data;
            rb_erase( node, &process->overflow_events );
            if( order->order_status != ORDER_STATUS_NO_BALANCE && !order->close_updated ){
                order->order_status = ORDER_STATUS_NO_BALANCE;
                node->key.pkey = order->token;
                rb_tree_insert_node( &process->will_close_orders, node, 0 );
            }
            node = next;
        }
    }

    //update process info to redis
    int ret = update_process_info_to_redis(process);
    if (ret < 0){
        sys_log(LL_ERROR, "[ %s:%d ] update process info to redis failed!", __FILE__, __LINE__);
    }

    _check_and_update_activity(process);

    // 处理定时任务
    int timer = TIMER_DEFAULT; 
    node = rb_first( &process->order_timer );
    if(node ){
        timer = node->key.lkey+g_config.order_check_interval - now;
        if( timer < 0 ){
            timer = _check_and_update_order ( process );
        }
    }

    int ret1 = _save_closed_orders_to_redis(process);
    int ret2 = free_closed_session_resource( process, 0 );  // 100ms
    //sys_log(LL_DEBUG, "[ %s:%d ] closed_orders:%d, closed_session:%d", __FILE__, __LINE__, ret1, ret2 );

    if( process->last_defrag_pool_stamp + g_config.pool_defrag_interval < now ){
        ret1 = order_pool_defrag( process, g_config.pool_defrag_size );
        ret2 = rb_list_defrag( &process->rb_node_pool, g_config.pool_defrag_size );
        int ret3 = defrag_invalid_order_cache( process, now );
        int ret4 = domain_pool_defrag(process, g_config.pool_defrag_size);
        if( ret1<0 || ret2<0 || ret4 < 0)
            sys_log(LL_ERROR, "[ %s:%d ] WRONG!! order_pool_defrag:%d, rb_list_defrag:%d, defrag_invalid_order_cache:%d",
            __FILE__, __LINE__, ret1, ret2, ret3 );
        else
            sys_log(LL_DEBUG, "[ %s:%d ] order_pool_defrag:%d, rb_list_defrag:%d, defrag_invalid_order_cache:%d", 
            __FILE__, __LINE__, ret1, ret2, ret3 );
            
        process->last_defrag_pool_stamp = now;
    }

    return timer;
    
}

// 估算tcp协议的流量的误差
static int _calc_session_delta_byte( socks_session_t *session )
{
    int delta = 0;
    if( session->protocol == SOCKS_PROTOCOL_TCP ){
        if( session->up_byte_num >0 )
            delta += ceil(((double)session->up_byte_num) /MTU_SIZE)* ETHERNET_IP_TCP_HEADER_SIZE;
        if( session->down_byte_num >0 )
            delta += ceil(((double)session->down_byte_num) /MTU_SIZE)* ETHERNET_IP_TCP_HEADER_SIZE ;
    }
    return delta;
}

// 估算session中未保存的流量，kb为单位
static int _calc_session_nosaved_kbyte( socks_session_t *session )
{
    int tmp = session->no_saved_byte_num + _calc_session_delta_byte(session);
    int no_saved_kbyte = (tmp>>10) + ((tmp&1023)?1:0);  // kb, 不足1kb以1kb计算
    return no_saved_kbyte;
}

static int _calc_session_total_kbyte( socks_session_t *session )
{
    int tmp = session->up_byte_num + session->down_byte_num + session->control_byte_num 
        + _calc_session_delta_byte(session);
    session->total_kbyte_num = (tmp>>10) + ((tmp&1023)?1:0);    // kb
    return session->total_kbyte_num;
}

static int _calc_udp_remote_total_kbyte( socks_udp_connection_t * con, int pos )
{
    int tmp = con->remote_up_byte_num[pos] + con->remote_down_byte_num[pos];
    tmp = (tmp>>10) + ((tmp&1023)?1:0); // kb
    return tmp;
}

// 估算order中未保存的流量，kb为单位
static int _calc_order_nosave_kbyte( socks_worker_process_t *process, socks_order_t *order )
{
    rb_node_t *node, *next;
    int nosaved_kbyte = 0;
    
    long now = get_current_ms();
    node = rb_first( &order->session_cache );
    while( node ) {
        next = rb_next(node);
        
        socks_session_t *session =(socks_session_t *)node->data;
        if( !session->closed ){
            //检查是否空闲太久,如果是就关闭session
            if( (session->last_data_stamp + g_config.session_idle_timeout) < now ){
                close_session( process, session );
            }
            else
                nosaved_kbyte +=_calc_session_nosaved_kbyte(session);
        }
        if( order->last_data_stamp < session->last_data_stamp )
            order->last_data_stamp = session->last_data_stamp;
        node = next;
    }
    
    return nosaved_kbyte + order->no_saved_kbyte;
}

int get_order_calloc_count()
{
    return order_calloc_count;
}


int get_order_free_count()
{
    return order_free_count;
}


int passwd_pool_init(socks_worker_process_t *process, int size)
{
    int i;
    socks_passwd_t *passwd;
    memset((void *)&process->passwd_pool, 0, sizeof(process->passwd_pool));
    rb_list_init( &process->passwd_pool, 0 );

    if( size <=0 )
        return -1;
    
    passwd = (socks_passwd_t *)calloc( size, sizeof(socks_passwd_t) );
    if( !passwd  )
        return -1;
    
    process->passwd_pool.pool = (void *)passwd;
    for( i=0; i<size; i++ ){
        passwd->pool = 1;
        rb_node_t *node = rb_list_pop( &process->rb_node_pool );
        if( !node ){
            break;
        }
        
        node->data = (void *)passwd;
        rb_list_add( &process->passwd_pool, node );
        passwd++;

    }
    return 0;
}

int passwd_pool_add(socks_worker_process_t *process, socks_order_t *order, socks_passwd_t *passwd)
{
    struct rb_node *node, *head, *next;
        
    head = &(process->passwd_pool.head);
    next = head->rb_right;
    if( passwd == next->data )
        return -1;
        
    node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        // no memory, failed, free passwd and defrag.
        if( !passwd->pool )
            free(passwd);
        passwd_pool_defrag( process, order, g_config.pool_defrag_size );
        return -1;
    }
    //node->key.pkey = passwd->domain;
    node->data = (void *)passwd;
    rb_list_add( &process->passwd_pool, node );

    return 0;
}


int passwd_pool_exit(socks_worker_process_t *process)
{
    struct rb_node *head, *next, *tmp;
    socks_passwd_t *passwd;

    head = (&process->passwd_pool.head);
    next = head->rb_right;

    while( next != head ){
        tmp = next->rb_right;
        passwd = (socks_passwd_t *)next->data;
        if( passwd ){
            //delete_passwd_from_cache( process, order, passwd );
            if( !passwd->pool ){
                passwd_free_count++;
                free(passwd);
                passwd = NULL;
            }   
        }
        if( !rb_is_pool(next) )
            free(next);
        next = tmp;
    }

    if( process->passwd_pool.pool )
        free(process->passwd_pool.pool);

    return 0;
}

int passwd_pool_defrag( socks_worker_process_t *process, socks_order_t *order, int size)
{
    struct rb_node *head, *next, *nright, *prev2, *next2;
    int i=0;
    socks_passwd_t *passwd;

    if( passwd_calloc_count<=passwd_free_count )
        return passwd_calloc_count-passwd_free_count;

    head = &(process->passwd_pool.head);
    next = head->rb_right;
    while( next != head ){
        nright = next->rb_right;
        passwd = (socks_passwd_t *)next->data;
        if( !passwd->pool ){
            if( i++ >size )
                break;
            prev2 = next->rb_left;
            next2 = next->rb_right;
            
            next2->rb_left = prev2;
            prev2->rb_right = next2;
            
            rb_list_add( &process->rb_node_pool, next );
            delete_passwd_from_cache( process, order, passwd );
            passwd_free_count++;
            free(passwd);
            process->passwd_pool.size--;
        }
        next = nright;
    }
    return i;
}



static socks_passwd_t * _passwd_calloc()  
{  
    socks_passwd_t *passwd = (socks_passwd_t *)calloc( 1, sizeof(socks_passwd_t) );
    
    // for debug, look the pool is enough?
    passwd_calloc_count++;
    sys_log(LL_DEBUG, "[ %s:%d ] passwd_calloc_count: %d", __FILE__, __LINE__, passwd_calloc_count );
    
    return passwd;
} 


socks_passwd_t *passwd_pool_pop(socks_worker_process_t *process, socks_order_t *order)
{
    struct rb_node *head, *next, *tmp;
    head = &(process->passwd_pool.head);
    next = head->rb_right;
    
    if( next == head ){
        return _passwd_calloc();
    }

    tmp = rb_list_pop( &process->passwd_pool );
    socks_passwd_t *passwd = (socks_passwd_t *)tmp->data;
    rb_list_add( &process->rb_node_pool, tmp );
    if( passwd ){
        delete_passwd_from_cache( process, order, passwd );
    }
    
    return passwd;
}