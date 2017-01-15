#ifndef _SOCKD_REDIS_H
#define _SOCKD_REDIS_H


#include <hiredis/hiredis.h>
#include "meteor.h"
#include "sockd.h"

#define REDIS_KEY_PREFIX_ORDER                      "hash.order.token:"
#define REDIS_KEY_PREFIX_ACTIVITY                   "hash.activity.id:"
#define REDIS_KEY_PREFIX_ACTIVITY_TODAY_USERS       "set.today.users.activity.id:"

#define REDIS_KEY_ORDER_EXPIRED_EVENT       "sortedSet.event:expired"
#define REDIS_KEY_ORDER_OVERFLOW_EVENT      "sortedSet.event:overflow"
#define REDIS_KEY_ORDER_UPDATE_EVENT        "sortedSet.event:update"

#define REDIS_FIELD_ORDER_BALANCE       "orderBalance"
#define REDIS_FIELD_TODAY_USED_FLOW     "todayUsedFlow"
#define REDIS_FIELD_TODAY_USED_STAMP    "todayUsedFlowTime"
#define REDIS_FIELD_ORDER_STATUS        "orderStatus"
#define REDIS_FIELD_ORDER_END_TIME      "orderEndTime"
#define REDIS_FIELD_ORDER_ID            "orderId"
#define REDIS_FIELD_PHONE_ID            "phoneId"
#define REDIS_FIELD_ORDER_KEY           "orderKey"
#define REDIS_FIELD_ORDER_KEY_END_TIME  "orderKeyEndTime"
#define REDIS_FIELD_ORDER_APPS          "orderApps"

#define REDIS_FIELD_ACTIVITY_ID         "activityId"
#define REDIS_FIELD_ACTIVITY_START_TIME "activityStartTime"
#define REDIS_FIELD_ACTIVITY_END_TIME   "activityEndTime"
#define REDIS_FIELD_ACTIVITY_STATUS     "activityStatus"
#define REDIS_FIELD_ACTIVITY_BALANCE    "activityBalance"
#define REDIS_FIELD_TODAY_USERS         "todayUsers"
#define REDIS_FIELD_TODAY_FLOW_LIMIT    "todayFlowLimit"
#define REDIS_FIELD_TODAY_USER_LIMIT    "todayUserLimit"

#define REDIS_KEY_PREFIX_STAT           "hash.stat."
#define REDIS_FIELD_STAT_ORDER          "orders"
#define REDIS_FIELD_STAT_SESSION        "sessions"
#define REDIS_FIELD_STAT_NEW_SESSION    "newSessions"
#define REDIS_FIELD_STAT_CLOSED_SESSION "closedSessions"
#define REDIS_FIELD_STAT_TODAY_FLOWS    "todayFlows"
#define REDIS_FIELD_STAT_DISK_FULL_STAMP    "diskFullStamp"
#define REDIS_FIELD_STAT_CLOSE_ORDER    "closeOrders"
#define REDIS_FIELD_STAT_INVALID_ORDER  "invalidOrders"
#define REDIS_FIELD_STAT_UPDATE_EVENT   "updateEvents"
#define REDIS_FIELD_STAT_OVERFLOW_EVENT "overflowEvents"
#define REDIS_FIELD_STAT_TIMER          "timers"
#define REDIS_FIELD_STAT_NODE_POOL      "nodePools"
#define REDIS_FIELD_STAT_ORDER_POOL     "orderPools"
#define REDIS_FIELD_STAT_CACHE_MEMORY   "cacheMemory"
#define REDIS_FIELD_STAT_TOTAL_MEMORY   "totalMemory"
#define REDIS_FIELD_STAT_NODE_CALLOC    "nodeCallocs"
#define REDIS_FIELD_STAT_ORDER_CALLOC   "orderCallocs"
#define REDIS_FIELD_STAT_NODE_NO_FREE   "nodeNoFrees"
#define REDIS_FIELD_STAT_ORDER_NO_FREE  "orderNoFrees"

#define ORDER_KEY_ENDTIME_INCREASEMENT  5000


#define REDIS_EXPIRED_EVENT             1
#define REDIS_OVERFLOW_EVENT            2
#define REDIS_UPDATE_EVENT              3

#define REDIS_EXPIRED_ACTIVITY          1
#define REDIS_OVERFLOW_ACTIVITY         2
#define REDIS_UPDATE_ACTIVITY           3
#define REDIS_OVERDAILY_ACTIVITY        4


extern socks_module_config_t g_config;

redisContext * redis_init();

int check_redis_connect(redisContext** redis_connect);

int get_order_data_from_redis(redisContext * redis_connect, socks_order_t *order, unsigned char * token );
int get_activity_data_from_redis(redisContext * redis_connect, flow_pool_activity_t *activity );

int add_to_activity_today_userset(redisContext * redis_connect, socks_order_t *order );

int update_order_to_redis( socks_worker_process_t *process, socks_order_t *order );
int update_activity_to_redis( socks_worker_process_t *process, flow_pool_activity_t *activity );

int get_order_events_from_redis( socks_worker_process_t *process );

int update_process_info_to_redis(socks_worker_process_t *process);

#endif //_SOCKD_REDIS_H
