
#include <sys/types.h>
#include <sys/timeb.h>
#include <sys/socket.h>    
#include <sys/epoll.h>    
#include <netinet/in.h>    
#include <arpa/inet.h>    
#include <fcntl.h>    
#include <unistd.h>    
#include <stdio.h>    
#include <errno.h>  
#include <stdlib.h>  
#include <netdb.h>  
#include <string.h> 
#include <signal.h>


#define MAX_EVENTS 		5000  
#define RECV_BUF_SIZE 	2048  


#define DEBUG_LINE() printf("[%s:%s] line=%d\r\n",__FILE__, __func__, __LINE__)
#define DEBUG_ERR(fmt, args...) printf("\033[46;31m[%s:%d]\033[0m "#fmt" errno=%d, %m\r\n", __func__, __LINE__, ##args, errno, errno)
#define DEBUG_INFO(fmt, args...) printf("\033[33m[%s:%d]\033[0m "#fmt"\r\n", __func__, __LINE__, ##args)

typedef struct worker_process_s worker_process_t;
typedef struct udp_connection_s udp_connection_t;

struct worker_process_s
{
	int epoll_fd;
	
	int listen_port;
	int recv_buf_size;
	int send_buf_size;
	int reuseaddr;
	int keepalive;
	
	int recv_num;
	int sent_num;
	int recv_byte_num;
	int sent_byte_num;
} ;

struct udp_connection_s
{    
	int fd;    
	int events;

	struct sockaddr_in addr;

	unsigned char local_hostname[128];
	unsigned int local_port;

	unsigned char buf[RECV_BUF_SIZE];   // recv data buffer    
	ssize_t data_length;  // recv data length
	ssize_t sent_length;  // sent data length
    
	unsigned short eof;
	unsigned short closed;
} ;

long _get_current_ms()
{
	struct timeb tb;
	ftime(&tb);
	return (long)((tb.time*1000L)+tb.millitm);
}

void _register_session_event(int epoll_fd, int fd, int events, void *arg )    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = arg;    
    epv.events = events;  
	
	int op = EPOLL_CTL_ADD;
	if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
		DEBUG_ERR("epoll add failed, fd:%d, evnets:%d", fd, events);    
	else	
		DEBUG_INFO("epoll add ok, fd:%d, evnets:%d", fd, events);	
} 

udp_connection_t * _init_upd_bind( int epoll_fd, int port )
{
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;	 
	sin.sin_addr.s_addr = INADDR_ANY;	 
	sin.sin_port = htons( port );  


	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if ( fd < 0) {
		DEBUG_ERR( "create udp error, fd:%d", fd );
		return NULL;
	}
	
	int flags = fcntl( fd, F_GETFL, 0);
	if (flags < 0) {
		DEBUG_ERR( "get socket flags error, fd:%d", fd );
		return NULL;
	}

	if (fcntl( fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		DEBUG_ERR( "set socket nonblock error, fd:%d", fd );
		return NULL;
	}
	
	int value = 1;
	if (setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(int)) == -1)
	{
		DEBUG_ERR("set udp SO_REUSEADDR fail, fd:%d",  fd );
	}

	if( bind( fd, (  struct sockaddr*)&sin, sizeof(sin)) == -1 ){
		DEBUG_ERR("bind udp failed, port:%d, fd=%d", port, fd); 
		return NULL;
	}
	
    printf("udp server running:port:%d, fd:%d\n", port, fd ); 
	udp_connection_t *conn = (udp_connection_t *)malloc(sizeof(udp_connection_t));
	memset(conn, 0, sizeof(udp_connection_t));
	conn->fd = fd;
	conn->local_port = port;

	_register_session_event( epoll_fd, fd, EPOLLIN|EPOLLHUP|EPOLLERR, conn );
	return conn;

}

int main(int argc, char **argv)    
{
	worker_process_t process;
	memset( &process, 0, sizeof( process ) );

	process.listen_port = 8082;
	if(argc == 2){    
        process.listen_port = atoi(argv[1]);    
    }

	// create epoll    
    process.epoll_fd = epoll_create(MAX_EVENTS);    
    if(process.epoll_fd <= 0) {
		DEBUG_ERR("create epoll failed.%d\n", process.epoll_fd );  
		exit(-1);
    }
	
	udp_connection_t *udp = _init_upd_bind( process.epoll_fd, process.listen_port);

    // event loop    
    struct epoll_event events[MAX_EVENTS];   
	u_char buf[RECV_BUF_SIZE];
	
	int checkPos = 0;	 
	long start = _get_current_ms();
	int i = 0;
	//struct sockaddr_in addr;	
	int addr_len = sizeof(struct sockaddr_in);
	while(1){	 
		// wait for events to happen	
		int fds = epoll_wait(process.epoll_fd, events, MAX_EVENTS, 2000);	
		if(fds < 0){	
			printf("epoll_wait error, exit\n");    
			break;	  
		}
		
		for( i = 0; i < fds; i++){
			udp_connection_t *conn = (udp_connection_t *)events[i].data.ptr;
			//DEBUG_INFO("fds:%d, event:0x%4x", fds, events[i].events );
			if(events[i].events&(EPOLLIN) )	
			{	 

				int len = recvfrom( conn->fd, conn->buf,RECV_BUF_SIZE, 0 , (struct sockaddr *)&conn->addr ,&addr_len); 

				if( len <= 0 ){ //recvfrom error
					DEBUG_ERR("recv udp from: %s:%d error, fd:%d, len:%d", inet_ntoa(conn->addr.sin_addr), ntohs(conn->addr.sin_port), conn->fd, len);
					continue;
				}
				//DEBUG_INFO("recv udp from: %s:%d, fd:%d, len:%d", inet_ntoa(conn->addr.sin_addr), ntohs(conn->addr.sin_port), conn->fd, len);
				process.recv_num++;
				process.recv_byte_num += len;
				conn->data_length = len;
				//if( (events[i].events&EPOLLOUT) || (conn->events&EPOLLOUT) )
				//{
					//DEBUG_INFO("recv and send udp from: %s:%d, fd:%d, len:%d", inet_ntoa(conn->addr.sin_addr), ntohs(conn->addr.sin_port), conn->fd, len);
					//usleep(100);
					len = sendto( conn->fd ,conn->buf, conn->data_length, 0, (struct sockaddr *)&conn->addr,addr_len);
					if( len< 0 ){
						DEBUG_ERR( "udp send back error: %s:%d, fd: %d", inet_ntoa(conn->addr.sin_addr), ntohs(conn->addr.sin_port), conn->fd );
						continue;
					}
					process.sent_num++;
					process.sent_byte_num += len;
					conn->data_length = 0;
					conn->events ^= EPOLLOUT;
				//}
			}
#if 0			
			if( events[i].events&EPOLLOUT )
			{
				if( conn->data_length>0 ){
					//DEBUG_INFO("send udp back: %s:%d, fd:%d, len:%d", inet_ntoa(conn->addr.sin_addr), ntohs(conn->addr.sin_port), 
					//	conn->fd, conn->data_length );
					int len = sendto( conn->fd ,conn->buf, conn->data_length, 0, (struct sockaddr *)&conn->addr,addr_len);
					if( len< 0 ){
						DEBUG_ERR( "udp send back error: %s:%d, fd: %d", inet_ntoa(conn->addr.sin_addr), ntohs(conn->addr.sin_port), conn->fd );
						continue;
					}
					process.sent_num++;
					process.sent_byte_num += len;
					conn->data_length = 0;
					conn->events ^= EPOLLOUT;
				}
				else
					conn->events = events[i].events;
			}
#endif			
			if(events[i].events&(EPOLLERR|EPOLLHUP) )	{
				DEBUG_ERR( "udp error: %s:%d, fd: %d", inet_ntoa(conn->addr.sin_addr), ntohs(conn->addr.sin_port), conn->fd );
				continue;
			}
			
		}
		if( process.recv_num % 1000 == 1 ){
			long end = _get_current_ms();
			DEBUG_INFO("server %ld, cost:%d ms, recv_num: %d, sent_num: %d, recv_byte_num:%d, sent_byte_num:%d", start, end-start,
				process.recv_num, process.sent_num, process.recv_byte_num, process.sent_byte_num);
			start = end;
		}
	}

	close( process.epoll_fd );
	close( udp->fd);
	free( udp );

	return 0;	 

}



