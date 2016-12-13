//     
// meteor server(socks5 flow gateway) using epoll in linux    
//     
// by jimmy zhou    
// 
#ifndef SOCKD_H_
#define SOCKD_H_

#include <sys/types.h>
#include <sys/socket.h>    
#include <sys/epoll.h>    
#include <sys/ioctl.h>
#include <sys/timeb.h>
#include <netinet/in.h>    
#include <arpa/inet.h>
#include <net/if.h>
#include <math.h>
#include <fcntl.h>    
#include <unistd.h>    
#include <stdio.h>    
#include <errno.h>  
#include <stdlib.h>  
#include <netdb.h>  
#include <string.h> 
#include <signal.h>
#include <hiredis/hiredis.h>
#include <setjmp.h>

#include "meteor.h"
#include "sockd_rbtree.h"

#define MAX_DOMAIN 4000
#define ETHERNET_IP_TCP_HEADER_SIZE 54		// 14+20+20
#define ETHERNET_IP_UDP_HEADER_SIZE 42		// 14+20+8
#define IP_TCP_HEADER_SIZE 			40		// 20+20
#define IP_UDP_HEADER_SIZE 			28		// 20+8
#define MTU_SIZE					1500	// OR 576 ?

#define MAX_WORKERS 		16  
#define MAX_SESSIONS		5120
#define MAX_EVENTS 			5120  
#define MAX_INVALID_TOKENS	1024  

#define RECV_BUF_SIZE 	4096
#define UDP_RECV_BUF_SIZE 1024

#define WORKER_NAME_LEN	32  
#define USER_NAME_LEN	32  
#define HOST_NAME_LEN	128  
#define FILE_NAME_LEN	512  
#define DOMAIN_LEN		256  

#define SESSION_TOKEN_MIN_LEN 		1
#define SESSION_TOKEN_MAX_LEN 		64
#define SESSION_APP_PNAME_MAX_LEN	128
#define SESSION_PASSWD_MAX_LEN		64
#define SESSION_UDP_REMOTE_NUM		8

#define UDP_LISTEN_PORT_MAX_NUM		2


#define SOCKS_VERSION_5		0x05


#define SOCKS_PROTOCOL_TCP	0x01
#define SOCKS_PROTOCOL_UDP	0x00

#define SOCKS_ATYPE_IPV4 	0x01
#define SOCKS_ATYPE_DOMAIN 	0x03
#define SOCKS_ATYPE_IPV6 	0x04

#define SOCKS_COMMAND_CONNECT 		0x01
#define SOCKS_COMMAND_UDP_ASSOCIATE	0x03
#define SOCKS_COMMAND_UDP_CONNECT	0x04


#define SOCKS_STAGE_INIT 			0x01
#define SOCKS_STAGE_NEGOTIATION 	0x02
#define SOCKS_STAGE_AUTH 			0x03
#define SOCKS_STAGE_COMMAND 		0x04
#define SOCKS_STAGE_CONNECT_REMOTE 	0x05
#define SOCKS_STAGE_TCP_DATA 		0x06
#define SOCKS_STAGE_UDP_CLIENT		0x07
#define SOCKS_STAGE_UDP_DATA		0x08
#define SOCKS_STAGE_CLOSE 			0x00

#define HTTP_STAGE_CONNECT			0x09
#define HTTP_STAGE_TCP_DATA			0x0a

#define SOCKS_CLOSE_BY_CLIENT		0x01
#define SOCKS_CLOSE_BY_SOCKD		0x02
#define SOCKS_CLOSE_BY_REMOTE		0x03

#define SOCKS_CMD_SUCCESS 		0x00		//success
#define SOCKS_CMD_ERR_FAIL 		0x01		//general SOCKS server failure
#define SOCKS_CMD_ERR_NO_ALLOW 	0x02		//connection not allowed by ruleset
#define SOCKS_CMD_ERR_NET 		0x03		//Network unreachable
#define SOCKS_CMD_ERR_HOST 		0x04		//Host unreachable
#define SOCKS_CMD_ERR_REFUSE 	0x05		//Connection refused
#define SOCKS_CMD_ERR_EXPIRE 	0x06		//TTL expired
#define SOCKS_CMD_ERR_COMMAND	0x07		//Command not supported
#define SOCKS_CMD_ERR_ATYPE 	0x08		//Address type not supported
#define SOCKS_CMD_ERR_AUTH_1ST	0x09		//first auth fail
#define SOCKS_CMD_ERR_AUTH_2ND 	0x0a		//password auth fail


#define DEBUG_LINE() printf("[%s:%s] line=%d\r\n",__FILE__, __func__, __LINE__)
#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)

struct socks_string_s{
    size_t      len;
    u_char     *data;
};

#define socks_string_set(buf) ( (socks_string_t){ ((size_t)*buf)&0xff, (u_char*)buf+1 } )

union socks_addr_u {
   unsigned char      domain[DOMAIN_LEN];
   struct in_addr     ipv4;
   struct {
      struct in6_addr  ip;
      uint32_t         scopeid;
   } ipv6;
};

struct socks_host_s {
   unsigned char  atype;
   socks_addr_t   addr;
   in_port_t      port;
};

struct socks_command_s
{
	unsigned char	version;
	unsigned char	cmd;
	unsigned char	reserved;
	socks_host_t	host;
} ;

struct socks_command_reply_s
{
	unsigned char	version;
	unsigned char	status;
	unsigned char	reserved;
	socks_host_t	host;
	long	session;
};

struct socks_udp_listen_s
{
	int fd;
	int port;
};

struct socks_domain_s
{
	char domain[256];
    socks_addr_t ip_addr[10];
	size_t size;
	unsigned int pool:1;
};

struct socks_session_s
{
	socks_connection_t *client; 		//client: data connection(tcp), tcp controller(udp)
	socks_connection_t *remote; 		//remote: tcp or udp socket
	socks_udp_connection_t *udp_client; 	//client: udp socket
	socks_udp_connection_t *udp_remote; 	//remote: udp socket
	http_info_t *http_info;

	unsigned char token[SESSION_TOKEN_MAX_LEN];
	unsigned char app_pname[SESSION_APP_PNAME_MAX_LEN];
	unsigned char passwd[SESSION_PASSWD_MAX_LEN];
	
	socks_order_t *order;

	long connect_stamp;  		// stamp of connected
	long close_stamp;  			// stamp of closed
	long first_request_stamp; 	// stamp of first request from client
	long first_response_stamp; 	// stamp of first reponse from remote
	long begin_data_stamp; 		// command end and start translate data stamp
	long last_data_stamp; 		// last stamp of data send or recv

	unsigned int control_byte_num; 	// �������������ģ�Ӧ����3�����֣�4�η��֣�Э�̣���Ȩ������Ƚ������������ֽ�Ϊ��λ
	unsigned int up_byte_num;		// �����������ֽ�Ϊ��λ
	unsigned int down_byte_num;		// �����������ֽ�Ϊ��λ
	unsigned int total_kbyte_num;	// ��������������kbΪ��λ
	unsigned int no_saved_byte_num;	// δ���浽order������,��byteΪ��λ, ���µ�order���������

	unsigned int stage:4;
	unsigned int protocol:1;	// 1:tcp 0:udp
	unsigned int closed:1;
	unsigned int closed_by:2;	// 1:client, 2:sockd, 3:remote
} __attribute__((aligned(sizeof(long))));

// socks_connection_s �� socks_udp_connection_s ��ͷ���ṹӦ�����ܱ���һ��
struct socks_connection_s
{    
	int fd;    
	int events;
	void (*call_back)(socks_worker_process_t *process, int fd, int events, void *arg);    

	unsigned int eof:1;
	unsigned int closed:1;
	//for debug
	unsigned int event_count:6;
	unsigned long conn_stamp;

	socks_session_t *session;  
	unsigned char auth_method;
	
	socks_host_t peer_host;
	unsigned char peer_hostname[HOST_NAME_LEN];

	unsigned char local_hostname[HOST_NAME_LEN];
	unsigned int local_port;

	ssize_t data_length;  // recv data length
	ssize_t parsed_length; // rewrite_url parsed
	ssize_t sent_length;  // sent data length
	unsigned char buf[RECV_BUF_SIZE];   // recv data buffer 

	socks_connection_t *peer_conn;
	
} __attribute__((aligned(sizeof(long))));


struct socks_udp_connection_s
{    
	int fd;    
	int events;
	void (*call_back)(socks_worker_process_t *process, int fd, int events, void *arg);

	unsigned int eof:1;
	unsigned int closed:1;
	//for debug
	unsigned int event_count:6;
	unsigned long conn_stamp;

	socks_session_t *session;  
	unsigned char auth_method;

	socks_host_t peer_host;
	unsigned char peer_hostname[HOST_NAME_LEN];

	unsigned char local_hostname[HOST_NAME_LEN];
	unsigned int local_port;

	ssize_t data_length;  // recv data length
	ssize_t sent_length;  // sent data length
	unsigned char buf[UDP_RECV_BUF_SIZE];   // recv data buffer

	socks_udp_connection_t *peer_conn;

	unsigned int udp_remote_num;  // 0-7
	struct sockaddr_in  remote_addr[SESSION_UDP_REMOTE_NUM];
	int  remote_up_byte_num[SESSION_UDP_REMOTE_NUM];
	int remote_down_byte_num[SESSION_UDP_REMOTE_NUM];

} __attribute__((aligned(sizeof(long))));


struct socks_worker_process_s
{
	int epoll_fd;
	int listen_fd;
	socks_udp_listen_t udp_listen[UDP_LISTEN_PORT_MAX_NUM];
	int udp_listen_fd_num;
	int udp_listen_fd_pos;
	
	socks_worker_config_t *config;
	redisContext *redis_connect;

	activity_cache_t activity_cache;	// �����ػ���棬<activity_id,activity>
	order_cache_t order_cache;			// �������棬��������رգ�����1���ӣ������������һ��ʱ��û�������������.<order_token,order>
	order_cache_t overflow_events;		// ��redis��ȡ��������¼�, <order_id,order>
	order_cache_t update_events;		// ��redis��ȡ���ĸ����¼�, <order_id,order>
	order_cache_t will_close_orders; 	// ���ر�(��������)��order��δ�ͷ��ڴ棬 <order_id,order>
	order_cache_t invalid_orders;	// ��Ч��token���ѹرյĶ���������һ��ʱ�䣬�ж�����֤����ʱ����redisѹ��, <order_token,order>
	domain_cache_t domain_cache;      //������������IP��ַ<domain, ip>

	session_timer_t closed_sessions;	// �Ѿ��رյ�session��δ�ͷ��ڴ棬 <close_stamp,session>
	session_cache_t new_session_cache;	// �޶�����session���رն�ʱ��, <session, session>
	udp_addr_session_map_cache_t  udp_session_cache; //<ipport session>
	
	order_timer_t order_timer;			// �������¶�ʱ��, <last_update_stamp, order>

	rb_node_cache_t rb_node_pool;		// ������ڵ㻺��
	rb_node_cache_t order_pool;			// �����ڴ�أ����closed_ordersʹ��
	rb_node_cache_t udp_port_pool;
	rb_node_cache_t domain_pool;

	int session_num;
	long today_sum_flow_kbyte;				//today total used flow
	long today_sum_flow_stamp;				//today total used flow stamp
	
	long last_check_order_event_stamp;		// ������redis�����¼���ʱ��
	long last_defrag_pool_stamp;			// ��������ڴ�ص�ʱ��
	long last_update_worker_stat_stamp;	// last update process stat info stamp

} __attribute__((aligned(sizeof(long))));

struct socks_worker_config_s
{
	unsigned char worker_name[WORKER_NAME_LEN];
	
	// config of listen socket
	char outer_host[HOST_NAME_LEN];	// ����remote�ĳ���ip
	struct in_addr outer_addr_cache;
	char listen_host[HOST_NAME_LEN];
	int listen_port;
	int udp_listen_port;
	int listen_backlog;
	int max_sessions;
	
	int recv_buf_size;
	int send_buf_size;
	
	unsigned int reuseaddr;
	unsigned int keepalive;
	unsigned int udp_port_start;
	unsigned int udp_port_end;
} __attribute__((aligned(sizeof(long))));

struct socks_module_config_s
{
	unsigned char redis_host[HOST_NAME_LEN];
	unsigned int redis_port;

	int order_check_interval;			// �������ļ��ʱ�䣬��λms
	int activity_check_interval;		// ����ļ��ʱ�䣬��λms
	int order_update_interval;			// ����ˢ�µ�redis�ļ��ʱ�䣬��λms
	int activity_update_interval;		// �ˢ�µ�redis�ļ��ʱ�䣬��λms
	int order_idle_timeout;				// order�������Ŀ��г�ʱʱ�䣬��λms
	int session_idle_timeout;			// session�������Ŀ��г�ʱʱ�䣬��λms
	int order_frozen_timeout;			// order���ᳬʱʱ�䣬��λms
	int order_event_check_interval;		// ���redis�����¼��ļ��ʱ�䣬��λms
	int pool_defrag_interval;			// �����ڴ�صļ��ʱ�䣬��λms
	int worker_stat_update_interval;	// process stat info update frequence ms

	int pool_defrag_size;				// ÿ�������ڴ�ص�������

	unsigned int daemon_mode;
	
	unsigned int sys_log_mode;	
	unsigned int sys_log_level;	

	int sys_log_rotate_interval;		// ��λ s
	unsigned char sys_log_file_name[FILE_NAME_LEN];
	
	int flow_log_rotate_interval;		// ��λ s
	unsigned char flow_log_file_name[FILE_NAME_LEN];

	unsigned char pid_file_name[FILE_NAME_LEN];
	unsigned char working_dir[FILE_NAME_LEN];
	
	unsigned char user_name[USER_NAME_LEN];
	int user_id;
	
	int workers;
	int worker_max_sessions;
	socks_worker_config_t worker_config[MAX_WORKERS];
	
} __attribute__((aligned(sizeof(long))));

int get_udp_listen( socks_worker_process_t *process, socks_udp_listen_t * udp_listen);

int is_fd_in_udp_listen_fd(socks_worker_process_t *process, int fd);

void _accept_connect_cb(socks_worker_process_t *process, int listen_fd, int events);

void _negotiation_cb (socks_worker_process_t *process, int client_fd, int events, void *arg);

void _auth_cb ( socks_worker_process_t *process, int client_fd, int events, void *arg);

void _command_cb (socks_worker_process_t *process, int client_fd, int events, void *arg);

int send_cmd_reply( socks_worker_process_t *process, socks_connection_t *con, socks_command_reply_t *reply );

void _register_session_event(int epoll_fd, socks_connection_t *con, int fd, int events, 
			void (*call_back)(socks_worker_process_t *,int, int, void*));

unsigned char * copy_buf_to_socks_host(socks_host_t *host, unsigned char *buf);

unsigned char * copy_socks_host_to_buf( socks_host_t *host, unsigned char *buf);

struct sockaddr_in *convert_to_sockaddr_in( socks_host_t *host, struct sockaddr_in *addr );

socks_host_t *convert_to_socks_host_t( socks_host_t *host, struct sockaddr_in *addr );

unsigned char *copy_host_to_hostname ( socks_host_t *host, unsigned char *hostname );

int convert_domain_to_ipaddr(socks_worker_process_t *process, socks_addr_t *addr);

unsigned char *copy_sockaddr_to_hostname ( struct in_addr *sin_addr, unsigned char *hostname );

void start_worker_process( socks_worker_config_t *worker_config );

void worker_process_exit( socks_worker_process_t *process );


#endif //SOCKD_H_
