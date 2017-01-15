#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "sockd_auth.h"
#include "sockd_redis.h"
#include "meteor_auth.h"

extern socks_module_config_t g_config;

int _init_activity_if_exist(  socks_worker_process_t *process, socks_order_t *order, long nowms )
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
		if( _add_to_activity_cache(process, activity)<0 ){
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

int _add_to_order_cache( socks_worker_process_t *process, socks_order_t *order )
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

int _add_to_activity_cache( socks_worker_process_t *process, flow_pool_activity_t *activity )
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


int _add_to_session_cache( socks_worker_process_t *process, socks_order_t *order, socks_session_t *session )
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



