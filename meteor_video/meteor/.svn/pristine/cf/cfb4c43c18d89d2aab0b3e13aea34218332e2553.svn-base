#ifndef ORDER_H_
#define ORDER_H_

#include "meteor.h"
#include "sockd.h"
#include "sockd_rbtree.h"

#define ORDER_STATUS_NO_PAY     0x01        //no pay
#define ORDER_STATUS_NO_FINISH  0x02        //ordering
#define ORDER_STATUS_SUCCESS    0x03        //order success
#define ORDER_STATUS_FAIL       0x04        //order fail
#define ORDER_STATUS_EXPIRED    0x05        //order expired
#define ORDER_STATUS_NO_BALANCE 0x06        //order no balance
#define ORDER_STATUS_CANCEL     0x07        //order cancelled
#define ORDER_STATUS_CLOSE      0x08        //order closed

#define ACTIVITY_STATUS_NORMAL      0x03        //activity normal
#define ACTIVITY_STATUS_EXPIRED     0x15        //activity expired
#define ACTIVITY_STATUS_NO_DAILY    0x16        //activity TODAY no balance
#define ACTIVITY_STATUS_NO_BALANCE  0x18        //activity no balance

#define ORDER_TOKEN_LEN         32
#define ORDER_ORDER_ID_LEN      32
#define ORDER_PHONE_ID_LEN      16
#define ORDER_KEY_LEN           64      
#define ORDER_APPS_LEN          512

#define FLOW_POOL_BALANCE_DEFAULT           999999999
#define TIMER_DEFAULT           1000

struct socks_order_s {
    unsigned char token[ORDER_TOKEN_LEN];
    unsigned char order_id[ORDER_ORDER_ID_LEN];

    long order_endtime;             // 订单有效期,以ms为单位

    unsigned char phone_id[ORDER_PHONE_ID_LEN];
    unsigned char order_apps[ORDER_APPS_LEN];
    
    unsigned char order_key[ORDER_KEY_LEN];
    long order_key_endtime;         // 订单动态key的有效期，以ms为单位

    int order_balance;              // 订单余额，以kb为单位
    uint32_t today_used_flow;       // 订单当天的消耗额，以kb为单位
    long today_used_flow_stamp;     // 订单当天流量消耗数据的更新时戳，单位秒, 应从redis返回
    unsigned int no_saved_kbyte;    // 未保存到redis的流量,以kb为单位
    long last_data_stamp;           // last stamp of data send or recv
    long last_chk_stamp;            // last check time when timer_handle, 以ms为单位
    long last_update_stamp;         // last update time to redis, 以ms为单位
    long redis_event_stamp;         // 从redis返回的事件的时戳，单位ms
    long frozen_stamp;              // 冻结时间
    
    long flow_pool_activity_id;     // 公司流量池合同的活动ID,
    flow_pool_activity_t *activity; // 公司流量池合同的活动统计数据,  

    session_cache_t session_cache;  // 并行session，<session,session>

    passwd_cache_t  passwd_cache;       //  md5 cache

    unsigned int order_status:8;
    unsigned int auth_fail_times:4;
    unsigned int frozen:1;          // 是否被冻结
    unsigned int idle:1;            // 是否空闲状态，被关闭
    unsigned int close_updated:1;   // 记录订单溢出或过期后是否已经更新到redis
    unsigned int pool:1;            // 订单是否存放在内存池中
}__attribute__((aligned(sizeof(long))));

struct flow_pool_activity_s {
    long activity_id;               // 池合同活动ID
    long activity_starttime;        // 订单有效期,以ms为单位
    long activity_endtime;          // 订单有效期,以ms为单位
    long activity_balance;          // 公司流量池活动余额，以kb为单位
    unsigned int no_saved_kbyte;    // 未保存到redis的流量,以kb为单位
    int  today_users;               // 活动当天的用户数，(实际上是订单数)
    int  today_user_limit;          // 活动当天的人数上限，(实际上是订单数), 如果<=0,表示不限
    long today_flow_limit;          // 活动当天的消耗额上限，以kb为单位, 如果<=0,表示不限
    long today_used_flow;           // 活动当天的消耗额，以kb为单位
    long today_used_flow_stamp;     // 活动当天流量消耗数据的更新时戳，单位秒, 应从redis返回
    long last_update_stamp;         // last update time to redis, 以ms为单位
    long last_data_stamp;
    int activity_status:6;          // 合同活动状态
    unsigned int today_over:1;      // 记录活动是否超出当天的人数限额或流量限额
    unsigned int close_updated:1;   // 记录订单溢出或过期后是否已经更新到redis
}__attribute__((aligned(sizeof(long))));

int domain_pool_init(socks_worker_process_t *process, int size);

int domain_pool_defrag(socks_worker_process_t *process, int size);

int domain_pool_add(socks_worker_process_t *process, socks_domain_t *order );

socks_domain_t *domain_pool_pop(socks_worker_process_t *process);

int order_pool_init(socks_worker_process_t *process, int size);

int order_pool_exit(socks_worker_process_t *process);

int order_pool_defrag( socks_worker_process_t *process, int size);

int order_pool_add(socks_worker_process_t *process, socks_order_t *order );

socks_order_t *order_pool_pop(socks_worker_process_t *process);

int do_stat_order_flow(socks_worker_process_t *process, socks_session_t *session, int recv_len, 
    int up_direct, int is_data_flow);

int add_order_to_timer_queue( socks_worker_process_t *process, socks_order_t *order );

int add_new_session_to_cache( socks_worker_process_t *process, socks_session_t *session);
int del_from_new_session_cache( socks_worker_process_t *process, socks_session_t *session);
void close_timedout_new_session( socks_worker_process_t *process );
void new_session_cache_exit( socks_worker_process_t *process);


int add_order_to_invalid_cache( socks_worker_process_t *process, socks_order_t *order );

int add_order_to_will_close_queue( socks_worker_process_t *process, socks_order_t *order );

int handle_order_timer( socks_worker_process_t *process );

int update_order_when_session_close(socks_session_t *session );

int save_orders_when_process_exit( socks_worker_process_t *process );

int save_activity_when_process_exit( socks_worker_process_t *process );

long get_balance_of_flow_pool( socks_worker_process_t *process, socks_order_t * order);

int defrag_invalid_order_cache(socks_worker_process_t *process, long now_ms);

int get_order_calloc_count();
int get_order_free_count();



int passwd_pool_init(socks_worker_process_t *process, int size);
int passwd_pool_add(socks_worker_process_t *process, socks_order_t *order, socks_passwd_t *passwd);
int passwd_pool_exit(socks_worker_process_t *process);
int passwd_pool_defrag( socks_worker_process_t *process, socks_order_t *order, int size);
socks_passwd_t *passwd_pool_pop(socks_worker_process_t *process, socks_order_t *order);

#endif //ORDER_H_
