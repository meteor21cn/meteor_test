#ifndef CLIENT_H_
#define CLIENT_H_

//     
//  client for testing meteor(socks5 flow gateway) using epoll in linux    
//     
// by jimmy zhou    
//  

#include <sys/types.h>
#include <sys/socket.h>    
#include <sys/epoll.h>    
#include <sys/ioctl.h>
#include <sys/timeb.h>
#include <sys/time.h>
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
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>

#include "sockd_rbtree.h"

#if 1
#define DEBUG_LINE() printf("[%s:%s] line=%d\r\n",__FILE__, __func__, __LINE__)
//#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_ERR(fmt, args...) printf("\033[46;31m\033[0m "#fmt" errno=%d, %m\r\n", ##args, errno, errno)
//#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)
#define DEBUG_INFO(fmt, args...) printf("\033[33m\033[0m "#fmt"\r\n", ##args)
#endif

#if 0
#define DEBUG_LINE() 
//#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_ERR(fmt, args...) 
//#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)
#define DEBUG_INFO(fmt, args...) 
#endif

#define MAX_SOCKS_SESSION	50000
#define MAX_EVENTS 			4096  
#define RECV_BUF_SIZE		4096  

#define USER_NAME_LEN	64  
#define HOST_NAME_LEN	128  
#define FILE_NAME_LEN	512  
#define DOMAIN_LEN		256  

#define SOCKS_VERSION_5		0x05

#define SOCKS_AUTH_NONE				0x00
#define SOCKS_AUTH_USER_PASSWORD	0x02
#define SOCKS_AUTH_FLOW_PACKAGE		0x81

#define SOCKS_AUTH_ERR_ORDER_STATUS	0xfe    //order status not available

#define SOCKS_PROTOCOL_TCP	0x01
#define SOCKS_PROTOCOL_UDP	0x00

#define SOCKS_ATYPE_IPV4 	0x01
#define SOCKS_ATYPE_DOMAIN 	0x03
#define SOCKS_ATYPE_IPV6 	0x04

#define SOCKS_CMD_RANDOM 		0x00

#define SOCKS_CMD_CONNECT 			    0x01
#define SOCKS_CMD_UDP_ASSOCIATE			0x03
#define SOCKS_CMD_UDP_ASSOCIATE_PORT 	0x04

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

#define AGENT_MODE_TCP 		0x01
#define AGENT_MODE_HTTP 	0x03

#define HTTP_REVERSE_PROXY 		0x01
#define HTTP_FORWARD_PROXY 		0x03

#define HTTP_AT_FLAG		0x00
#define HTTP_DOMAIN_FLAG 	0x00
#define HTTP_AUTH_MODE 		0x01

#define FILE_PATH_LENGTH 100

typedef struct socks_client_process_s socks_client_process_t;

typedef struct socks_client_connection_s socks_client_connection_t;

typedef struct socks_command_reply_s socks_command_reply_t;

typedef struct socks_udp_header_s socks_udp_header_t;

typedef struct socks_string_s socks_string_t;

typedef union  socks_addr_u socks_addr_t;
typedef struct socks_host_s socks_host_t;

typedef struct rb_list rb_node_cache_t;
typedef struct rb_root connect_timer_t;
typedef struct rb_node rb_node_t;

struct socks_client_connection_s
{    
	int  tcp_fd;    
	int  tcp_local_port;
	
	int  udp_fd;         
	int  udp_local_port; 
	
	int  udp_retry_count;
	long udp_send_stamp;	
	int  udp_sockd_addr_len;    
	struct sockaddr_in udp_sockd_addr;

	int events;
	void (*call_back)(socks_client_process_t *process, int fd, int events, void *arg);    

	unsigned char auth_method;
	char  token[USER_NAME_LEN];

	
	unsigned char buf[RECV_BUF_SIZE];   // recv data buffer    
	ssize_t data_length;  // recv data length
	ssize_t sent_length;  // sent data length
	ssize_t recv_data_size;
	int recv_count;
	int send_count;
	
    long connect_stamp;
    long first_request_stamp;


	int  first_cost_ms; // 首次返回response的耗时
	int  cost_ms;
	int  conn_ms;
	
	int  udp_to_remote_port; 
	int udp_to_remote_ip;
	
	unsigned int eof:4;
	unsigned int closed:1;
	unsigned int cmd:3;
	unsigned int atype;

	unsigned int proxy_mode;
	unsigned int http_mode;
	int   http_will_recv_len;
	int http_resend_times;

} __attribute__((aligned(sizeof(long))));


struct socks_string_s{
    size_t      len;
    u_char     *data;
};

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

struct socks_command_reply_s
{
	unsigned char	version;
	unsigned char	status;
	unsigned char	reserved;
    socks_host_t	host;
};

struct socks_udp_header_s
{
	unsigned char	reserved[2];
	unsigned char	frag;
	socks_host_t	host;
} ;

struct socks_client_process_s
{

	int epoll_fd;
	rb_node_cache_t rb_node_pool;
	char  local_ip[64];
	
	char  sockd_ip[64];
	int   sockd_port;
	
	int   connect_max;  // allowed total Concurrency connections
	int   connect_num;  // current total connection number
	int   connect_step;
	long  connect_interval;
	long  connect_last_stamp;

	
	int  max_token; 
	int  min_token;
	char domain[USER_NAME_LEN];
	
	//for dante
	char *user;
	char *passwd;
	
	//for meteor
	char  token[USER_NAME_LEN];
	char *app;
	char *orderkey;

	int   closed_num;
	socks_client_connection_t *closed_connection[MAX_SOCKS_SESSION];
	
	unsigned int cmd;

	char  tcp_remote_ip[64];
	int   tcp_remote_port;
	int   tcp_will_recv_len;
	char  tcp_file_name[128];
	int   tcp_max_cost_ms;
	int   tcp_min_cost_ms;
	int   tcp_success_num;
	long  tcp_success_cost_ms;
	int   tcp_fail_num;

	char  udp_remote_ip[8][64];
	int   udp_remote_port[8];
	int   udp_remote_addr_len;
	struct sockaddr_in udp_remote_addr;
	socks_udp_header_t udp_remote_header;
	int   udp_remote_num;
	
	int   udp_will_recv_len;
	char *udp_test_data;
	connect_timer_t udp_connect_timer;
	long  udp_chk_stamp;
	long  udp_chk_interval;
	int   udp_max_cost_ms;
	int   udp_min_cost_ms;
	int   udp_success_num;
	long  udp_success_cost_ms;
	int   udp_fail_num;
	int   udp_lost_num;	
	unsigned int atype;
	//http

	unsigned int proxy_mode;
	unsigned int http_mode;
	int   http_remote_port;
	int   http_max_cost_ms;
	int   http_min_cost_ms;
	int   http_success_num;
	long  http_success_cost_ms;
	int   http_fail_num;
} ;

int _init_client_socket( socks_client_process_t *process) ;
int _test_tcp_connect_result( int fd );
void _connect_socks_host_complete_cb(  socks_client_process_t *process, int fd, int events, void *arg) ;
void _negotiation_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _auth_cb( socks_client_process_t *process, int client_fd, int events, void *arg);
void _command_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _tcp_request_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _recv_tcp_response_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _udp_request_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _recv_udp_response_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _send_command( socks_client_process_t *process, int client_fd, int events, socks_client_connection_t *con) ;
void _send_httpreq_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
void _recv_http_response_cb( socks_client_process_t *process, int client_fd, int events, void *arg) ;
long get_current_ms();
void _close_conenect( socks_client_process_t *process, socks_client_connection_t *con, int force );

#endif
