﻿//     
//  client for testing meteor(socks5 flow gateway) using epoll in linux    
//     
// by jimmy zhou    
//  

#include "client.h"
#include "sockd_rbtree.h"
#include "md5c.h"
#include "client_process.h"

socks_client_process_t client_workers[32];

int process_type;
int daemon_mode;

extern sig_atomic_t  to_reap;
extern sig_atomic_t  to_terminate;
extern sig_atomic_t  to_quit;
extern sig_atomic_t  to_reload;


void  set_user_token( socks_client_process_t *process, socks_client_connection_t *con )
{
	int token_num = process->max_token - process->min_token;
	if( token_num <= 1 ){
		sprintf( con->token, "%03d", process->min_token );
		return;
	}
	int user_id = process->min_token+ (int)(1+(rand())/(RAND_MAX/token_num + 1));
	memset( con->token, 0, USER_NAME_LEN );
	sprintf( con->token, "%03d", user_id );
	//printf( "token : %s\n", con->token );
	return ;
}

struct sockaddr_in *convert_to_sockaddr_in( socks_host_t *host, struct sockaddr_in *addr )
{
	memset( addr, 0, sizeof(struct sockaddr_in) );
	addr->sin_family = AF_INET;  
	addr->sin_port = host->port; 
	memcpy( &addr->sin_addr, &host->addr.ipv4, sizeof(host->addr.ipv4) );
	//addr->sin_addr = host->addr.ipv4;  
	return addr;
}
/*
socks_host_t *convert_to_socks_host_t(socks_client_process_t *process, socks_host_t *host, struct sockaddr_in *addr )
{

	host->atype = atype;
	memcpy( &host->addr.ipv4, &addr->sin_addr, sizeof(addr->sin_addr) );
	host->port = addr->sin_port;
	if(atype == SOCKS_ATYPE_DOMAIN)
	{
		memcpy( &host->addr.domain, &process->domain, sizeof(process->domain) );
		host->port = addr->sin_port;
	}
	return host;
}*/

socks_host_t *convert_to_socks_host_t( socks_host_t *host, struct sockaddr_in *addr )
{

	host->atype = SOCKS_ATYPE_IPV4;
	memcpy( &host->addr.ipv4, &addr->sin_addr, sizeof(addr->sin_addr) );
	host->port = addr->sin_port;
	return host;
}


unsigned char *copy_host_to_hostname ( socks_host_t *host, unsigned char *hostname )
{
	char *hosta = inet_ntoa( host->addr.ipv4 );
	size_t hosta_len = strlen(hosta);
	memcpy( hostname, hosta, hosta_len );
	hostname[hosta_len]= '\0';
	return hostname;
}

unsigned char *copy_sockaddr_to_hostname ( struct in_addr *sin_addr, unsigned char *hostname )
{
	unsigned char * host = inet_ntoa(*sin_addr);
	size_t host_len = strlen(host);
	memcpy( hostname, host, host_len );
	hostname[host_len]= '\0';
	return hostname;
}


unsigned char * copy_socks_host_to_buf( socks_host_t *host, unsigned char *buf)
{
	/* ATYP */
	memcpy(buf, &host->atype, sizeof(host->atype));
	buf += sizeof(host->atype);

	switch (host->atype) {
	case SOCKS_ATYPE_IPV4:
		memcpy(buf, &host->addr.ipv4.s_addr, sizeof(host->addr.ipv4.s_addr));
		buf += sizeof(host->addr.ipv4.s_addr);
		break;

	case SOCKS_ATYPE_IPV6:
		memcpy(buf, &host->addr.ipv6.ip, sizeof(host->addr.ipv6.ip));
		buf += sizeof(host->addr.ipv6.ip);
		break;

	case SOCKS_ATYPE_DOMAIN:
		/* first byte gives length of rest. */
		*buf = (unsigned char)strlen(host->addr.domain);

		memcpy(buf + 1, host->addr.domain, (size_t)*buf);
		buf += *buf + 1;
		break;
	}

	/* DST.PORT */
	memcpy(buf, &host->port, sizeof(host->port));
	buf += sizeof(host->port);
	return (unsigned char *)buf;
}

unsigned char * copy_buf_to_socks_host(socks_host_t *host, unsigned char *buf)
{
	memcpy(&host->atype, buf, sizeof(host->atype));
	buf += sizeof(host->atype);
	host->atype = 1;

	switch (host->atype) {
		case SOCKS_ATYPE_IPV4:
			memcpy(&host->addr.ipv4, buf, sizeof(host->addr.ipv4)); // FIXME:XXXX
			buf += sizeof(host->addr.ipv4);
			break;

		case SOCKS_ATYPE_DOMAIN: {
			size_t domainlen = ((size_t)*buf )&0xff;
			buf += sizeof(*buf);
			memcpy(host->addr.domain, buf, domainlen);
			host->addr.domain[domainlen] = '\0';
			buf += domainlen;
			break;
		}

		case SOCKS_ATYPE_IPV6:
			memcpy(&host->addr.ipv6.ip, buf, sizeof(host->addr.ipv6.ip));
			buf += sizeof(host->addr.ipv6.ip);
			host->addr.ipv6.scopeid = 0;
			break;
	}
	
	memcpy(&host->port, buf, sizeof(host->port));
	buf += sizeof(host->port);
	return (unsigned char *)buf;
}

unsigned char *_get_udp_header( unsigned char *data,  socks_udp_header_t *header)
{
	memset(header, 0, sizeof(*header));
	memcpy(&header->reserved, data, sizeof(header->reserved));
	data += sizeof(header->reserved);

	memcpy(&header->frag, data, sizeof(header->frag));
	data += sizeof(header->frag);

	return (unsigned char *)copy_buf_to_socks_host(&header->host, ( unsigned char *)data );
}

static int _chk_udp_header( unsigned char *data )
{
	if( data[0]!=0 || data[1]!=0 || data[2] !=0 )
		return -1;
	if( data[3] != SOCKS_ATYPE_IPV4 && data[3] != SOCKS_ATYPE_IPV6 && data[3] != SOCKS_ATYPE_DOMAIN )
		return -1;
	return 0;
}

unsigned char * _copy_udp_header_to_buf( socks_udp_header_t *header, unsigned char *buf)
{
    /* reserved */
	memcpy(buf, &header->reserved, sizeof(header->reserved));
	buf += sizeof(header->reserved);
	memcpy(buf, &header->frag, sizeof(header->frag));
	
	buf += sizeof(header->frag);

	return (unsigned char *)copy_socks_host_to_buf( &header->host, buf );
}


// set event    
void _register_session_event(int epoll_fd, socks_client_connection_t *con, int fd, int events, 
			void (*call_back)(socks_client_process_t *,int, int, void*))    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = con;    
	epv.events = events;  
	con->call_back = call_back;    

	int op = EPOLL_CTL_ADD;
	if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
		DEBUG_ERR( "[ %s:%d ] epoll add failed, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
	//else	
	//	DEBUG_INFO( "[ %s:%d ] epoll add ok, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);	
} 

void _change_session_event(int epoll_fd, socks_client_connection_t *con, int fd, int events, 
		void (*call_back)(socks_client_process_t *,int, int, void*))    
{    
	struct epoll_event epv = {0, {0}};
	epv.data.ptr = con;    
	epv.events = events;  
	con->call_back = call_back;    

	int op = EPOLL_CTL_MOD;
	if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
		DEBUG_ERR( "[ %s:%d ] epoll change failed, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
	//else    
		//DEBUG_INFO( "[ %s:%d ] epoll change ok, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
} 

  
void _close_conenect( socks_client_process_t *process, socks_client_connection_t *con, int force )    
{    
	if( con->closed)
		return;
	
	con->closed = 1;

	struct epoll_event epv = {0, {0}};
	epv.data.ptr = con;  
	int op = EPOLL_CTL_DEL;

	if( con->udp_fd >0 )
	{
		if( epoll_ctl( process->epoll_fd, op, con->udp_fd, &epv) < 0)
			DEBUG_ERR( "[ %s:%d ] epoll del udp_fd failed, udp_fd:%d", __FILE__, __LINE__, con->udp_fd );

		if( close(con->udp_fd ) < 0 ){
			DEBUG_ERR( "[ %s:%d ] close socket udp_fd failed, fd:%d", __FILE__, __LINE__, con->udp_fd);
		}
	}

	if( con->tcp_fd >0 )
	{
		if( epoll_ctl( process->epoll_fd, op, con->tcp_fd, &epv) < 0)
			DEBUG_ERR( "[ %s:%d ] epoll del tcp_fd failed, udp_fd:%d", __FILE__, __LINE__, con->tcp_fd );

		if( force ){
			struct linger ling = {0, 0};
			if( setsockopt( con->tcp_fd, SOL_SOCKET, SO_LINGER, (void*)&ling, sizeof(ling) ) == -1 ){
				DEBUG_ERR( "[ %s:%d ] setsockopt(linger) failed, fd:%d", __FILE__, __LINE__, con->tcp_fd );	
			}
		}
		
		if( close(con->tcp_fd ) < 0 ){
			DEBUG_ERR( "[ %s:%d ] close socket tcp_fd failed, fd:%d", __FILE__, __LINE__, con->tcp_fd);
		}
		
		DEBUG_INFO( "[ %s:%d ] connect closed. token:%s, tcp_fd:%d, udp_fd:%d, cmd:%d, recv_count:%d, send_count:%d, conn_ms:%d, cost_ms:%d, first_cost_ms:%d, recv_data_size:%d",
			__FILE__, __LINE__, con->token, con->tcp_fd, con->udp_fd, con->cmd, con->recv_count, con->send_count, con->conn_ms, con->cost_ms, con->first_cost_ms, con->recv_data_size );	
		
		con->tcp_fd = 0;
	}  

	process->connect_num--;
	process->closed_connection[process->closed_num++] = con;
	if(con->proxy_mode == AGENT_MODE_HTTP)
	{
		int total = process->http_success_num+process->http_fail_num;
		int suc_pp = total? (process->http_success_num*100/total):0;
		DEBUG_INFO( "[ %s:%d ] sockd_port:%d, connect_max:%d, closed_num:%d, connect_num:%d, http sum: will_recv_len:%d, max_cost_ms:%d, min_cost_ms:%d, avg_cost_ms:%d, succcess:%d, fail:%d, total:%d, suc:%d%%", 
			__FILE__, __LINE__, process->sockd_port, process->connect_max, process->closed_num, process->connect_num,	
			con->http_will_recv_len, process->http_max_cost_ms, process->http_min_cost_ms, 
			process->http_success_num>0?(process->http_success_cost_ms/process->http_success_num):0,
			process->http_success_num, process->http_fail_num, total, suc_pp );
		return;
	}
	if( process->cmd == SOCKS_CMD_CONNECT ){
		int total = process->tcp_success_num+process->tcp_fail_num;
		int suc_pp = total? (process->tcp_success_num*100/total):0;
		DEBUG_INFO( "[ %s:%d ] sockd_port:%d, connect_max:%d, closed_num:%d, connect_num:%d, TCP sum: will_recv_len:%d, max_cost_ms:%d, min_cost_ms:%d, avg_cost_ms:%d, succcess:%d, fail:%d, total:%d, suc:%d%%", 
			__FILE__, __LINE__, process->sockd_port, process->connect_max, process->closed_num, process->connect_num,	
			process->tcp_will_recv_len, process->tcp_max_cost_ms, process->tcp_min_cost_ms, 
			process->tcp_success_num>0?(process->tcp_success_cost_ms/process->tcp_success_num):0,
			process->tcp_success_num, process->tcp_fail_num, total, suc_pp );
	}
	else{
		int total = process->udp_success_num+process->udp_fail_num+process->udp_lost_num;
		int suc_pp = total? (process->udp_success_num*100/total):0;
		DEBUG_INFO( "[ %s:%d ] sockd_port:%d, connect_max:%d, closed_num:%d, connect_num:%d, UDP sum: rb_nodes:%d, timer:%d, will_recv_len:%d, retry:%d. max_cost_ms:%d, min_cost_ms:%d, avg_cost_ms:%d, succcess:%d, fail:%d, lost:%d, total:%d, suc:%d%%", 
			__FILE__, __LINE__, process->sockd_port, process->connect_max, process->closed_num, process->connect_num,	
			process->rb_node_pool.size, process->udp_connect_timer.size, 
			process->udp_will_recv_len,  con->udp_retry_count, process->udp_max_cost_ms, process->udp_min_cost_ms, 
			process->udp_success_num>0?(process->udp_success_cost_ms/process->udp_success_num):0,
			process->udp_success_num, process->udp_fail_num, process->udp_lost_num, total, suc_pp );
	}
	
} 

   
int _chk_udp_connect_timer( socks_client_process_t *process )
{
	long now = get_current_ms();
	rb_node_t *node,*next,*delete_node;
	node = rb_first( &(process->udp_connect_timer));
	while( node ) {
		next = rb_next(node);
		socks_client_connection_t *con = (socks_client_connection_t *)(node->data);
		if(!con || con->closed ){
			rb_erase( node, &(process->udp_connect_timer));
			rb_list_add( &process->rb_node_pool, node );
			node = next;
			continue;
		}
		
		if( now - con->udp_send_stamp < process->udp_chk_interval){
			break;
		}

		// retry to send back;
		con->udp_retry_count++;
		int sent_len = sendto( con->udp_fd, con->buf, con->data_length, 0, (struct sockaddr *)&(con->udp_sockd_addr),
			con->udp_sockd_addr_len );
		if( sent_len != con->data_length ){
			DEBUG_ERR( "[ %s:%d ] send back failed, fd:%d, recv_len:%d, sent_len:%d, cost_ms:%d, conn_ms:%d", __FILE__, __LINE__, 
				con->udp_fd, con->data_length, sent_len, con->cost_ms, con->conn_ms );

			goto to_close;
		}
		con->udp_send_stamp = now;
			
		if( con->udp_retry_count >5 ){
			process->udp_lost_num++;
			goto to_close;
		}
		
		goto to_continue;
		
		to_close:
			rb_erase( node, &(process->udp_connect_timer));
			rb_list_add( &process->rb_node_pool, node );
			_close_conenect( process, con, 1);
			
		to_continue:
			node = next;
			
	}
	
	return 0;

}

int _recv_data ( socks_client_connection_t *con, int size )
{
	int total = 0;	

	// see http://www.cnblogs.com/jingzhishen/p/3616156.html

	if( con->data_length >= RECV_BUF_SIZE ){
		DEBUG_INFO( "[ %s:%d ] buf full,no recv, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
			con->tcp_fd, con->data_length, con->sent_length,  size, total );
		return 0;
	}
	do{
		int will_read = size;
		if( con->data_length+size >RECV_BUF_SIZE ){
			will_read = RECV_BUF_SIZE - con->data_length;
		}
		if( will_read <=0 ){
			DEBUG_ERR( "[ %s:%d ] recv size error, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
				con->tcp_fd, con->data_length, con->sent_length,  size, total );
			return 0;
		}
		
		int len = recv(con->tcp_fd, &con->buf[con->data_length], will_read, MSG_DONTWAIT ); //MSG_WAITALL
		if (len > 0)
		{
			con->data_length += len;
			total += len;
			return total;
		}
		else if( len < 0 )
		{
			int err = errno;
			if (err == EAGAIN)
			{	
				DEBUG_ERR( "[ %s:%d ] recv data EAGAIN : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, con->tcp_fd, 
					con->data_length, con->sent_length, size, total );
				break;
			}

			else if (err == EINTR )
			{
				DEBUG_ERR( "[ %s:%d ] recv data EINTR : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, con->tcp_fd, 
					con->data_length, con->sent_length, size, total );
				continue;
			}
			else
			{
				time_t now = time(NULL);
				struct tm *ptime = localtime(&now);
				char now_str[64];
				strftime(now_str, sizeof(now_str), "%Y-%m-%d %H:%M:%S", ptime);

				DEBUG_ERR( "[ %s:%d ] %s recv error. port:%d, fd:%d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, now_str, 
					con->tcp_local_port, con->tcp_fd, con->data_length, con->sent_length, size, total );
				return -1;
			}
		}
		else if( len == 0 ){ // ɧ¹�º¯˽՚µȴ�Ԋ֊��¶Ёˣ¬Ňô̼·µ»ְ¡£
			DEBUG_INFO( "[ %s:%d ] recv eof. fd:%d, dlen:%d, slen:%d, expect:%d, recv:%d, recv_data_size:%d", __FILE__, __LINE__, con->tcp_fd, 
				con->data_length, con->sent_length, size, total, con->recv_data_size );
			con->eof = 1;
			//break;
			return -1;
		}

	}
	while( 1 );
	
	return total;

}

int _recv_data_until_length( socks_client_connection_t *con, int length )
{
	while( con->data_length < length)
	{
		int len = _recv_data ( con, length-con->data_length );
		if( len<=0 )
			break;
	}
	return con->data_length;
}

void _clean_recv_buf( socks_client_connection_t *con )
{
	memset( con->buf, 0, RECV_BUF_SIZE );
	con->data_length = 0;
	con->sent_length = 0;
}

int _send_data( socks_client_connection_t *con, int send_fd )
{
	int total = 0;	
	// will send size 
	int size = con->data_length-con->sent_length;
	if( size <=0 | size+con->sent_length>RECV_BUF_SIZE|| con->sent_length < 0 || 
		con->sent_length >=RECV_BUF_SIZE || con->data_length<=0 || con->data_length>RECV_BUF_SIZE ){
		DEBUG_ERR( "[ %s:%d ] buf error, fd:%d, send_fd: %d, dlen:%d, slen:%d", __FILE__, __LINE__, con->tcp_fd, send_fd, 
			con->data_length, con->sent_length );
		return -1;
	}
	
	do{
		int len = send(send_fd, &con->buf[con->sent_length], size, MSG_DONTWAIT ); //MSG_WAITALL
		if (len > 0)
		{
			con->sent_length += len;
			total += len;
			return total;
		}
		else if( len == 0 ){ 
			DEBUG_ERR( "[ %s:%d ] net disconnected when send data. fd: %d, dlen:%d, slen:%d, size:%d", __FILE__, __LINE__, 
				send_fd, con->data_length, con->sent_length, size );
			return -1;
		}
		else{

			if (errno == EAGAIN)
			{
				DEBUG_ERR( "[ %s:%d ] send data EAGAIN, fd: %d, dlen:%d, size:%d", __FILE__, __LINE__, 
					send_fd, con->data_length, size );
				break;
			}

			if (errno == EINTR)
			{
				DEBUG_ERR( "[ %s:%d ] send data EINTR, fd: %d", __FILE__, __LINE__, send_fd );
				continue;
			}
			DEBUG_ERR( "[ %s:%d ] send data error, fd: %d", __FILE__, __LINE__, send_fd );
			return -1;
		}
		
	}
	while( 1 );
	
	return con->sent_length;

}

ssize_t _send_data_until_length( socks_client_connection_t *con, int send_fd, ssize_t length )
{
	con->data_length = length;
	con->sent_length = 0;
	return _send_data(con, send_fd );
}

// get current time, in ms
long get_current_ms()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((long)tv.tv_sec)*1000+((long)tv.tv_usec)/1000;
}


// call back for negotiation    
void _negotiation_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;

	int len;
	//send auth method negotiation
	unsigned char methods[3] = { SOCKS_AUTH_FLOW_PACKAGE, SOCKS_AUTH_USER_PASSWORD, SOCKS_AUTH_NONE };

	_clean_recv_buf( con );

	con->buf[0]=SOCKS_VERSION_5;
	con->buf[1]=3;
	
	memcpy(con->buf+2,methods,3);
	con->data_length = 5;
	len=_send_data_until_length( con, client_fd, con->data_length);
	if(len<con->data_length)
	{
		DEBUG_INFO( "[ %s:%d ] auth method send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
		_close_conenect( process, con, 1);
		return;
	}
	if( len == con->data_length )
		_clean_recv_buf(con);
	_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _auth_cb );
			
}


// auth callback, support SOCKS_AUTH_USER_PASSWORD, SOCKS_AUTH_FLOW_PACKAGE
void _auth_cb( socks_client_process_t *process, int client_fd, int events, void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	int cmd = process->cmd;
	if( cmd == 0 ){
		if( rand() & SOCKS_CMD_CONNECT )
			cmd = SOCKS_CMD_CONNECT;
		else
			cmd = SOCKS_CMD_UDP_ASSOCIATE;
	}
	con->cmd = cmd;

	int atype = process->atype;
	if( atype == 0 ){
		if( rand() & SOCKS_ATYPE_IPV4 )
			atype = SOCKS_ATYPE_IPV4;
		else
			atype = SOCKS_ATYPE_DOMAIN;
	}
	con->atype = atype;
	int len;    
	int will_read = 2;
	len = _recv_data_until_length ( con, will_read );
	if( len < 0 || con->eof ){
		//net disconnected. close session
		DEBUG_ERR( "[ %s:%d ] disconnected when recv negotiation result, len: %d", __FILE__, __LINE__, len );
		_close_conenect( process, con, 1);
		return;
	}
	if( con->data_length < will_read)
		return;

	if( con->buf[0] != SOCKS_VERSION_5){
		DEBUG_INFO( "[ %s:%d ] error version: %d",  __FILE__, __LINE__, con->buf[0] );
		_close_conenect( process, con, 1);
		return ;
	}
	con->auth_method = con->buf[1];
	//DEBUG_INFO( "[ %s:%d ] auth method : %x", __FILE__, __LINE__, con->buf[1]  );

	if(con->auth_method==SOCKS_AUTH_NONE)
	{
		_send_command( process, client_fd, events, con );
		return;
	}

	_clean_recv_buf(con);

	int i=0;
	con->buf[i++]=0x01;
	/*if(con->auth_method==SOCKS_AUTH_USER_PASSWORD)
	{
		int ulen = strlen( process->user);
		con->buf[i++]=ulen;
		memcpy( &con->buf[i], process->user, ulen);
		i+=ulen;
		int plen = strlen( process->passwd);
		con->buf[i++]=plen;
		memcpy( &con->buf[i], process->passwd, plen);
		con->data_length = i+plen;
	}*/
	//else
	//{
		set_user_token( process, con ); 
		
		char tmp[512];
		char passwd_bytes[16]={0};
		char passwd_hex_str[33]={0};
		memset(tmp, 0, sizeof(tmp) );
		sprintf( tmp, "%s|%s", con->token, process->app );
		
		int ulen = strlen( tmp);
		con->buf[i++]=ulen;
		memcpy( &con->buf[i], tmp, ulen);
		i+=ulen;
		
		memset(tmp, 0, sizeof(tmp) );
		memset(passwd_bytes, 0, sizeof(passwd_bytes) );
		memset(passwd_hex_str, 0, sizeof(passwd_hex_str) );

		char *ip_for_password= process->tcp_remote_ip;

		if(con->atype == 3)
		{
			ip_for_password = process->domain;
			sprintf( tmp, "%s|%s|%s", con->token, process->orderkey, ip_for_password);
		}
		else
		{
			switch(con->cmd)
			{
				case SOCKS_CMD_CONNECT:
					sprintf( tmp, "%s|%s|%s", con->token, process->orderkey, ip_for_password);
					break;
				case SOCKS_CMD_UDP_ASSOCIATE:
					sprintf( tmp, "%s|%s|%s", con->token, process->orderkey, process->local_ip);
					break;
				case SOCKS_CMD_UDP_ASSOCIATE_PORT:
					sprintf( tmp, "%s|%s|%s", con->token, process->orderkey, process->local_ip);
					break;
			}
		}
	    MD5_CTX md5;
	    MD5Init(&md5);
	    MD5Update(&md5, tmp, strlen((char *)tmp));
	    MD5Final(&md5, passwd_bytes);
	    MDString2Hex(passwd_bytes,passwd_hex_str);

		int plen = strlen( passwd_hex_str);
		con->buf[i++]=plen;
		memcpy( &con->buf[i], passwd_hex_str, plen);
		con->data_length = i+plen;
		//DEBUG_INFO( "[ %s:%d ]UserName/PassWord req: %s,%s",  __FILE__, __LINE__, &con->buf[2], passwd_hex_str );
		 
	//}

	len=_send_data_until_length(con,client_fd,con->data_length);
	//DEBUG_INFO( "[ %s:%d ]UserName/PassWord req: %s  slen:%d",  __FILE__, __LINE__,  &con->buf[2], len);
	if( len < con->data_length ){
		DEBUG_INFO( "[ %s:%d ] auth send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
		_close_conenect( process, con, 1);
		return;
	}
	_clean_recv_buf(con);
	_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _command_cb );
				
}

// command callback
void _command_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;

	if(con->auth_method!=SOCKS_AUTH_NONE)
	{
		//if( !(events & EPOLLIN) )
		//	return;

		int len;    
		int will_read = 19;
		if(con->auth_method==SOCKS_AUTH_USER_PASSWORD)
		{
			will_read = 2;
		}

		len = _recv_data_until_length ( con, will_read );
		//DEBUG_INFO( "[ %s:%d ]0x%x method, auth recv, len:%d",  __FILE__, __LINE__, con->auth_method, len);

		if( len < 0 || con->eof ){
			//net disconnected. close session
			DEBUG_ERR( "[ %s:%d ] disconnected when recv auth result, token:%s, len: %d", __FILE__, __LINE__, con->token, len );
			_close_conenect( process, con, 1);
			return;
		}
		if( con->data_length < will_read)
			return;

		if( con->buf[0] != 0x01 ){
			DEBUG_INFO( "[ %s:%d ] error version: %d",	__FILE__, __LINE__, con->buf[0] );
			_close_conenect( process, con, 1);
			return ;
		}
		unsigned int status =con->buf[1];
		//DEBUG_INFO( "[ %s:%d ]auth status : %x", __FILE__, __LINE__, status  );
		if( status != 0 ){
			DEBUG_ERR( "[ %s:%d ] auth fail, token:%s, status: 0x%x, orderstatus:%d", __FILE__, __LINE__, con->token, status, con->buf[2] );
			_close_conenect( process, con, 1);
			return ;
		}	

	}

	_send_command( process, client_fd, events, con );

				
}

void _send_command (  socks_client_process_t *process, int client_fd, int events, socks_client_connection_t *con)    
{    
	_clean_recv_buf(con);
	
	con->buf[0] = SOCKS_VERSION_5;
	con->buf[1] = con->cmd;
	con->buf[2] = 0x00;
	con->buf[3] = con->atype;
	
	socks_host_t host;
	memset( &host, 0, sizeof(host) );
	host.atype = con->atype;	//ipv4
	if( con->cmd == SOCKS_CMD_CONNECT ){

		if(host.atype == SOCKS_ATYPE_IPV4)
		{
			inet_aton( process->tcp_remote_ip, &host.addr.ipv4);  
			//host.port= htons(process->tcp_remote_port);  
		}
		else if(host.atype == SOCKS_ATYPE_DOMAIN)
		{
			//host.addr.domain =
			memcpy(&host.addr.domain, process->domain, sizeof(process->domain));
		}
		host.port= htons(process->tcp_remote_port); 
	}
	if(con->cmd == SOCKS_CMD_UDP_ASSOCIATE || con->cmd == SOCKS_CMD_UDP_ASSOCIATE_PORT){
		//udp fd
		int client_udp_fd = socket(AF_INET,SOCK_DGRAM,0);
		if( client_udp_fd <= 0 ){
			DEBUG_ERR( "create SOCK_DGRAM failed. %d: %s", errno, strerror(errno) );
			return;
		}
		
		//set non-blocking  
		
		int flags = fcntl( client_udp_fd, F_GETFL, 0);
		if (flags < 0) {
			//DEBUG_ERR( "get socket flags error : %d, %s", errno, strerror(errno) );
			close( client_udp_fd );
			return ;
		}		
		 //set nonblocking  
		int iret = 0;  
		if((iret = fcntl(client_udp_fd, F_SETFL, flags|O_NONBLOCK)) < 0)  
		{  
			//DEBUG_ERR("fcntl nonblocking failed: %d, %s",errno, strerror(errno));  
			close(client_udp_fd);
			return;
		}

		int value = 1;
		if (setsockopt( client_udp_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(int)) == -1)
		{
			DEBUG_ERR("set udp SO_REUSEADDR fail, fd:%d",  client_udp_fd );
		}
		
		con->udp_fd = client_udp_fd;
		struct sockaddr_in client_udp_addr;
		bzero(&client_udp_addr,sizeof(client_udp_addr)); 
		client_udp_addr.sin_family = AF_INET;
		client_udp_addr.sin_addr.s_addr = INADDR_ANY;	 
		client_udp_addr.sin_port = 0;  
		if( bind( client_udp_fd, (struct sockaddr*)&client_udp_addr, sizeof(client_udp_addr))<0)
		{
			DEBUG_ERR( "[ %s:%d ] bind udp_fd fail", __FILE__, __LINE__ );
			return;
		}
		socklen_t addrsize = sizeof(client_udp_addr);	
		getsockname( client_udp_fd, (struct sockaddr*)&client_udp_addr, &addrsize);
		con->udp_local_port = ntohs(client_udp_addr.sin_port);
		inet_aton( process->local_ip, &client_udp_addr.sin_addr );

		//liul
		if(con->atype == SOCKS_ATYPE_IPV4)
		{
			convert_to_socks_host_t( &host, &client_udp_addr );
		}
		else if(con->atype == SOCKS_ATYPE_DOMAIN)
		{
			memcpy(&host.addr.domain, process->domain, sizeof(process->domain));
			host.port= client_udp_addr.sin_port; 
		}
		host.atype=con->atype;
	}
	unsigned char *pos = copy_socks_host_to_buf( &host,&con->buf[3] );
	con->data_length = pos - &con->buf[0];
		
	int len=_send_data_until_length(con,client_fd,con->data_length);
	DEBUG_INFO( "[ %s:%d ]cmd req: 0x%x  slen:%d  con->buf:%d cmd:%d,atype:%d",__FILE__, __LINE__, con->buf[2], len ,strlen(con->buf),con->cmd,con->atype);
	
	if( len < con->data_length ){
		DEBUG_INFO( "[ %s:%d ] cmd send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
		_close_conenect( process, con, 1);
		return;
	}
	
	_clean_recv_buf(con);
	if( con->cmd == SOCKS_CMD_CONNECT ){
		_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _tcp_request_cb );
	}
	
	if( con->cmd == SOCKS_CMD_UDP_ASSOCIATE || con->cmd == SOCKS_CMD_UDP_ASSOCIATE_PORT){
		_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _udp_request_cb );
	}

				
}

// command callback
void _tcp_request_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	socks_command_reply_t reply;
	
	memset( &reply, 0, sizeof(reply) );
	
	int will_read =  10; // just test for ipv4
	int len = _recv_data_until_length ( con, will_read );
	if( len < 0 || con->eof ){
		//net disconnected. close session
		DEBUG_ERR( "[ %s:%d ] disconnected when recv cmd reply, fd:%d", __FILE__, __LINE__, client_fd );
		_close_conenect( process, con, 1);
		return;
	}
	if( len< will_read)
	{
		DEBUG_INFO( "[ %s:%d ] recv cmd reply, len: %d, will:%d, fd:%d", __FILE__, __LINE__, len, will_read, client_fd );
		return;
	}

	if( con->buf[0] != SOCKS_VERSION_5){
		DEBUG_ERR( "[ %s:%d ]  error socks version: %d, fd:%d", __FILE__, __LINE__,  con->buf[0], client_fd );
		_close_conenect( process, con, 1);
		return ;
	}
	memcpy( &reply, con->buf, 3 );
	copy_buf_to_socks_host( &reply.host ,&con->buf[3]);

	_clean_recv_buf(con);
	char *file_name=process->tcp_file_name;
	if(con->atype == SOCKS_ATYPE_DOMAIN)
		file_name=process->domain;
	sprintf( con->buf, "GET /%s HTTP/1.1\r\nHOST: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0\r\n\r\n",
		file_name, process->tcp_remote_ip );
	
	con->data_length = strlen( con->buf );
	con->first_request_stamp = get_current_ms();
	len=_send_data_until_length(con,client_fd,con->data_length);
	//DEBUG_INFO( "[ %s:%d ]send cmd req, slen:%d", __FILE__, __LINE__,  len );
	if( len < con->data_length ){
		DEBUG_INFO( "[ %s:%d ] req send failed, slen:%d, dlen:%d", __FILE__, __LINE__, len, con->data_length );
		_close_conenect( process, con, 1);
		return ;
	}
	con->send_count++;
	_clean_recv_buf(con);
	_change_session_event( process->epoll_fd, con, client_fd,EPOLLIN|EPOLLHUP|EPOLLERR, _recv_tcp_response_cb );			
}

// command callback
void _udp_request_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	int will_read =  10; // just test for ipv4

	if(con->cmd == SOCKS_CMD_UDP_ASSOCIATE_PORT)
	{
		will_read =  18; // just test for domain
	}

	int len = _recv_data_until_length ( con, will_read );
	if( len < 0 || con->eof ){
		//net disconnected. close session
		DEBUG_ERR( "[ %s:%d ] disconnected when recv cmd reply, fd:%d", __FILE__, __LINE__, client_fd );
		_close_conenect( process, con, 1);
		return;
	}
	if( len< will_read)
	{
		DEBUG_INFO( "[ %s:%d ] recv cmd reply, len: %d, will:%d, fd:%d", __FILE__, __LINE__, len, will_read, client_fd );
		return;
	}

	if( con->buf[0] != SOCKS_VERSION_5){
		DEBUG_ERR( "[ %s:%d ]  error socks version: %d, fd:%d", __FILE__, __LINE__,  con->buf[0], client_fd );
		_close_conenect( process, con, 1);
		return ;
	}

	_register_session_event( process->epoll_fd, con, con->udp_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _recv_udp_response_cb );

	socks_command_reply_t reply;
	memset( &reply, 0, sizeof(reply) );
	memcpy( &reply, con->buf, 3 );
	copy_buf_to_socks_host( &reply.host ,&con->buf[3] );
	if( reply.status != SOCKS_CMD_SUCCESS ){
		DEBUG_ERR( "[ %s:%d ] udp cmd failed, %s:%d, reply status:0x%x", __FILE__, __LINE__, 
			process->udp_remote_ip, process->udp_remote_port, reply.status );
		_close_conenect( process, con, 1);
		return;
	}

	convert_to_sockaddr_in( &reply.host, &con->udp_sockd_addr );
	con->udp_sockd_addr_len = sizeof(con->udp_sockd_addr);

	//liul
	if(con->cmd == SOCKS_CMD_UDP_ASSOCIATE_PORT)
	{
		memcpy( &con->udp_to_remote_ip, &con->buf[10], 4 );
		memcpy( &con->udp_to_remote_port, &con->buf[14], 4 );
	}

	_clean_recv_buf(con);

	//liul
	reply.host.atype = con->atype;
	process->udp_remote_header.host.atype=con->atype;
	if(con->atype == SOCKS_ATYPE_DOMAIN)
	{
		memcpy( (void *)&process->udp_remote_header.host.addr.domain, &process->domain, strlen(process->domain) );
	}
	u_char *p = _copy_udp_header_to_buf( &process->udp_remote_header, con->buf );

	if(con->cmd == SOCKS_CMD_UDP_ASSOCIATE_PORT)
	{
		memcpy( (void *)p, &con->udp_to_remote_ip, 4 );
		memcpy( (void *)p+4, &con->udp_to_remote_port, 4 );
		p+=8;
		// udp message
		//memcpy( (void *)p, process->udp_test_data, strlen( process->udp_test_data ) );
	}	
		// udp message
	memcpy( p, process->udp_test_data, strlen( process->udp_test_data ) );		

	p += strlen(process->udp_test_data);
	con->data_length = p - con->buf;
	len=sendto( con->udp_fd, con->buf, con->data_length, 0, (struct sockaddr *)&con->udp_sockd_addr, 
		con->udp_sockd_addr_len );
	if( len < con->data_length ){
		DEBUG_ERR( "[ %s:%d ] send udp to %s:%d failed. len:%d", __FILE__, __LINE__, process->udp_remote_ip, process->udp_remote_port, len );
		_close_conenect( process, con, 1);
		return;
	}
	
	con->first_request_stamp = get_current_ms();
	con->udp_send_stamp = con->first_request_stamp;	
	con->first_cost_ms = -1;
	con->send_count++;
	DEBUG_INFO( "[ %s:%d ] send udp to %s:%d len:%d", __FILE__, __LINE__, process->udp_remote_ip, process->udp_remote_port, len );

	rb_node_t *node = rb_list_pop( &process->rb_node_pool );
	node->key.lkey=con->udp_fd;
	node->data = con;
	rb_tree_insert_node( &process->udp_connect_timer, node, 0 );
	
}

void _recv_udp_response_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	_clean_recv_buf(con);
	long now = get_current_ms();
	
	int will_read =  RECV_BUF_SIZE; 
	int recv_len = recvfrom(con->udp_fd, con->buf, RECV_BUF_SIZE,0, (struct sockaddr *)&(con->udp_sockd_addr),
		&(con->udp_sockd_addr_len) );
	rb_key_t key;
	key.lkey = (long)con->udp_fd;
	rb_node_t * node = NULL;

	if( recv_len > 0 ){
		con->recv_data_size += recv_len;
		con->data_length = recv_len;
		con->recv_count++;
		
		if( con->first_cost_ms <0 ){
			con->first_cost_ms = ( now - con->first_request_stamp );
		}

		con->cost_ms = (now - con->first_request_stamp);
		con->conn_ms = (now - con->connect_stamp );

		if(con->recv_data_size < process->udp_will_recv_len )
		{
			/*//_clean_recv_buf(con);
			//int i = rand()%process->udp_remote_num;
			//init_udp_remote_addr( process, i);
			//u_char *p = _copy_udp_header_to_buf( &process->udp_remote_header, con->buf );
			
			// udp message
			//memcpy( p, process->udp_test_data, strlen( process->udp_test_data ) );
			//p += strlen(process->udp_test_data);*/

			con->data_length = strlen(con->buf);
			int sent_len = sendto( con->udp_fd, con->buf, recv_len, 0, (struct sockaddr *)&(con->udp_sockd_addr),con->udp_sockd_addr_len );
			if( sent_len < con->data_length ){
				DEBUG_ERR( "[ %s:%d ] send back failed, udp_fd:%d, recv_len:%d, sent_len:%d, cost_ms:%d, conn_ms:%d", __FILE__, __LINE__, 
					con->udp_fd, con->data_length, sent_len, con->cost_ms, con->conn_ms );
				process->udp_fail_num++;
				goto to_close;
			}
			con->udp_send_stamp = now;
			con->send_count++;
			return;
		}
		
		// sucessfully 
		goto to_stat;
	}
		
	if( recv_len < 0 || con->eof ){
		DEBUG_ERR( "[ %s:%d ] recv terminated, udp_fd:%d, recv_data_size:%d, first_cost_ms:%d, cost_ms:%d, conn_ms:%d", __FILE__, __LINE__, 
			con->udp_fd, con->recv_data_size, con->first_cost_ms, con->cost_ms, con->conn_ms );
		goto to_stat;
	}
	return; 
	
	to_stat:
		con->cost_ms = (now - con->first_request_stamp);
		con->conn_ms = (now - con->connect_stamp );
		if( con->recv_data_size > process->udp_will_recv_len ){
			process->udp_success_num++;
			process->udp_success_cost_ms += con->cost_ms;
			if( con->cost_ms > process->udp_max_cost_ms )
				process->udp_max_cost_ms = con->cost_ms;
			if( con->cost_ms < process->udp_min_cost_ms )
				process->udp_min_cost_ms = con->cost_ms;
		}
		else{
			process->udp_fail_num++;
		}
		
	to_close:
		node = rb_tree_delete( &process->udp_connect_timer, &key);
		_close_conenect( process, con, 1);
		if( node ){
			rb_list_add( &process->rb_node_pool, node);
		}
					
}




// command callback
void _recv_tcp_response_cb (  socks_client_process_t *process, int client_fd, int events,   void *arg)    
{    
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	_clean_recv_buf(con);
	printf("------************************************************************************----\n");
	long now = get_current_ms();	
	int will_read =  RECV_BUF_SIZE; 
	int len = _recv_data ( con, will_read );
	if( len > 0 ){
		con->recv_data_size += len;
		con->recv_count++;
		
		if( con->first_cost_ms <=0 ){
			con->first_cost_ms = (now-con->first_request_stamp);
		}
		if( con->recv_data_size >= process->tcp_will_recv_len ){
                        process->tcp_success_num++;
                        process->tcp_success_cost_ms += con->cost_ms;
                        if( con->cost_ms > process->tcp_max_cost_ms )
                                process->tcp_max_cost_ms = con->cost_ms;
                        if( con->cost_ms < process->tcp_min_cost_ms )
                                process->tcp_min_cost_ms = con->cost_ms;
			 _close_conenect( process, con, 1);
                }
	//	_close_conenect( process, con, 1);
		
	}
	if( len < 0 || con->eof ){
		con->cost_ms = (now-con->first_request_stamp);
		con->conn_ms = (now-con->connect_stamp);
		if( con->recv_data_size >= process->tcp_will_recv_len ){
			process->tcp_success_num++;
			process->tcp_success_cost_ms += con->cost_ms;
			if( con->cost_ms > process->tcp_max_cost_ms )
				process->tcp_max_cost_ms = con->cost_ms;
			if( con->cost_ms < process->tcp_min_cost_ms )
				process->tcp_min_cost_ms = con->cost_ms;
		}
		else{
			process->tcp_fail_num++;
		}
		//net disconnected. close session
		DEBUG_INFO( "[ %s:%d ] recv data finished, fd:%d, recv_data_size:%d, first_cost_ms:%d, cost_ms:%d, conn_ms:%d", __FILE__, __LINE__, 
			client_fd, con->recv_data_size, con->first_cost_ms, con->cost_ms, con->conn_ms );

		_close_conenect( process, con, 1);
		return;
	}
				
}


//http
//http
long GetHttpFileLen(char *http_response,int *response_file_len)
{
    char * search_char = "Content-Length: ";
    char * result_char = strstr(http_response,search_char);
    char * blank="\r\n\r\n";
    char * result_head_over = strstr(http_response,blank);
    *response_file_len = strlen(result_head_over+4);
    printf("http_response:\n%s\n", http_response);
    printf("result_head_over:%s\n", result_head_over+4);
    printf("response_file_len:%d\n", *response_file_len);
    if(result_char==NULL)
        return 0;
    result_char+=strlen(search_char);
    char filelenchar[30];
    int i=0;
    
    while(*result_char!='\0')
    {
        if(*result_char=='\n' || *result_char=='\r')
            break;
        filelenchar[i++] = *result_char++;
    }
    if(i >= 30)
        return -1;
    filelenchar[i]='\0';
    long result=0;
    int j=0;
    while(filelenchar[j]!='\0')
    {
        result=result*10+filelenchar[j++]-48;
    }
    return result;
}

void _send_httpreq_cb( socks_client_process_t *process, int client_fd, int events, void *arg)
{	
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	printf("**********************************_send_httpreq_cb***********************************\n");
	int http_mode = process->http_mode;
	if( http_mode == 0 ){
		if( rand() & HTTP_REVERSE_PROXY )
			http_mode = HTTP_REVERSE_PROXY;
		else
			http_mode = HTTP_FORWARD_PROXY;
	}
	con->http_mode = http_mode;

		set_user_token( process, con ); 
		
	char tmp[512];
	char passwd_bytes[16]={0};
	char passwd_hex_str[33]={0};
	memset(tmp, 0, sizeof(tmp) );
	sprintf( tmp, "%s.%s", con->token, process->app );
	
	
	memset(tmp, 0, sizeof(tmp) );
	memset(passwd_bytes, 0, sizeof(passwd_bytes) );
	memset(passwd_hex_str, 0, sizeof(passwd_hex_str) );

	sprintf( tmp, "%s|%s|%s", con->token, process->orderkey, process->tcp_remote_ip);

    MD5_CTX md5;
    MD5Init(&md5);
    MD5Update(&md5, tmp, strlen((char *)tmp));
    MD5Final(&md5, passwd_bytes);
    MDString2Hex(passwd_bytes,passwd_hex_str);
	
    memset(tmp, 0, sizeof(tmp) );
    sprintf( tmp, "%s|%s|%s", con->token, process->app,passwd_hex_str);
    char  meteor_req[256];
    char  meteor_url[256];
    int http_at_flag=2;
    int http_domain_flag=1;
    int http_auth_mode=HTTP_AUTH_MODE;

    sprintf(meteor_req,"meteorq|%d|%d|%d|%s",http_at_flag,http_domain_flag,http_auth_mode,tmp);
    sprintf(meteor_url,"%s:%d/%s/%s",process->sockd_ip,process->sockd_port,meteor_req,process->tcp_remote_ip);

    _clean_recv_buf(con);
	if(con->http_mode == HTTP_REVERSE_PROXY)
	{
		sprintf( con->buf, "GET http://%s/%s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0\r\n\r\n",
			meteor_url,process->tcp_file_name,process->tcp_remote_ip );
	}
	else
	{
		sprintf( con->buf, "GET http://%s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0\r\nX-Meteorq: %d|%s\r\n\r\n",
			process->tcp_remote_ip, process->tcp_remote_ip,http_auth_mode,tmp);
	}
	con->data_length = strlen( con->buf );
	con->first_request_stamp = get_current_ms();
	int len=_send_data_until_length(con,client_fd,con->data_length);
	printf("sendlen:%d\n",len);
	printf("con->buf:%s\n",con->buf);
	_clean_recv_buf(con);
	_change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _recv_http_response_cb );

}

void _recv_http_response_cb(socks_client_process_t *process, int client_fd, int events, void *arg)
{
	socks_client_connection_t *con = (socks_client_connection_t*)arg;
	_clean_recv_buf(con);
	int will_read ;
	if(con->http_will_recv_len<0)
	{
		will_read =  RECV_BUF_SIZE;
		int len = _recv_data ( con, will_read );
		DEBUG_ERR( "[ %s:%d ] ,recvlen:%d", __FILE__, __LINE__, len );
		if(len>0)
		{
			int filelen_head=0;
			con->http_will_recv_len = GetHttpFileLen(con->buf,&filelen_head);
			con->recv_data_size += filelen_head;
		}
		if(con->http_will_recv_len < 0)
		{
			DEBUG_ERR( "[ %s:%d ] GetHttpFileLen fail, http_will_recv_len:%d,recvlen:%d", __FILE__, __LINE__, con->http_will_recv_len,len);
			//_close_conenect( process, con, 1);
			con->http_will_recv_len = process->tcp_will_recv_len;
		}
		if( con->recv_data_size >= con->http_will_recv_len ){
	        process->http_success_num++;
	        process->http_success_cost_ms += con->cost_ms;
	        if( con->cost_ms > process->http_max_cost_ms )
                process->http_max_cost_ms = con->cost_ms;
        	if( con->cost_ms < process->http_min_cost_ms )
                process->http_min_cost_ms; 
            goto http_close;
            }
		return;
	}
	else
	{
		will_read =  con->http_will_recv_len - con->recv_data_size < RECV_BUF_SIZE?con->http_will_recv_len - con->recv_data_size:RECV_BUF_SIZE;
	}
	if(will_read <= 0)
	{
		DEBUG_ERR( "[ %s:%d ] ,will_read:%d", __FILE__, __LINE__, will_read );
		goto http_close;
	}
	int len = _recv_data ( con, will_read );

	long now = get_current_ms();	 

	if( len > 0 ){
		con->recv_data_size += len;
		con->recv_count++;
		
		if( con->first_cost_ms <=0 ){
			con->first_cost_ms = (now-con->first_request_stamp);
		}
		if( con->recv_data_size >= con->http_will_recv_len ){
	        process->http_success_num++;
	        process->http_success_cost_ms += con->cost_ms;
	        if( con->cost_ms > process->http_max_cost_ms )
                process->http_max_cost_ms = con->cost_ms;
        	if( con->cost_ms < process->http_min_cost_ms )
                process->http_min_cost_ms; 
            goto http_close;
            }
	}
	if( len < 0 || con->eof ){
		con->cost_ms = (now-con->first_request_stamp);
		con->conn_ms = (now-con->connect_stamp);
		if( con->recv_data_size >= con->http_will_recv_len ){
			process->http_success_num++;
			process->http_success_cost_ms += con->cost_ms;
			if( con->cost_ms > process->http_max_cost_ms )
				process->http_max_cost_ms = con->cost_ms;
			if( con->cost_ms < process->http_min_cost_ms )
				process->http_min_cost_ms = con->cost_ms;
		}
		else{
			process->http_fail_num++;
		}
		//net disconnected. close session
		goto http_close;
	}
	else
	{
		return;
	}

	http_close:
			DEBUG_INFO( "[ %s:%d ] recv data finished, fd:%d, recv_data_size:%d,http_will_recv_len:%d,first_cost_ms:%d, cost_ms:%d, conn_ms:%d", __FILE__, __LINE__, 
				client_fd, con->recv_data_size, con->http_will_recv_len,con->first_cost_ms, con->cost_ms, con->conn_ms);
		    if(con->http_resend_times >=2)
            {
            	 _close_conenect( process, con, 1);
            }
            else
            {
            	con->http_resend_times++;
            	con->http_will_recv_len = -1;
            	con->recv_data_size = 0;
            	DEBUG_ERR( "[ %s:%d ] ,con->http_resend_times:%d", __FILE__, __LINE__, con->http_resend_times );
            	_change_session_event( process->epoll_fd, con, client_fd, EPOLLOUT|EPOLLHUP|EPOLLERR, _send_httpreq_cb );
            }
         	return;

}

int _init_client_socket( socks_client_process_t *process)    
{    
	int fd = socket(AF_INET, SOCK_STREAM, 0); 
	if( fd == -1 ){
		DEBUG_ERR( "[ %s:%d ] open socket fail, fd:%d", __FILE__, __LINE__, fd );
		return -1;
	}
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;	 
	inet_aton( process->sockd_ip, &sin.sin_addr);  
	sin.sin_port = htons(process->sockd_port);  

	int reuseaddr = 1;
	if (setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (void *) &reuseaddr, sizeof(int)) == -1){
		DEBUG_ERR( "[ %s:%d ] get SO_REUSEADDR fail, fd=%d\n", __FILE__, __LINE__, fd); 
	}

    int flags = fcntl( fd, F_GETFL, 0);
    if (flags < 0) {
		DEBUG_ERR( "[ %s:%d ] get socket flags error, fd=%d\n", __FILE__, __LINE__, fd); 
		return -1;
    }

	if( fcntl(fd, F_SETFL, flags |O_NONBLOCK) < 0 ){ // set non-blocking    
		DEBUG_ERR( "[ %s:%d ] set O_NONBLOCK failed, fd=%d\n", __FILE__, __LINE__, fd); 
		return -1;
	}

	socks_client_connection_t *con = (socks_client_connection_t *)malloc(sizeof(socks_client_connection_t));
	if( con == NULL ){
		DEBUG_ERR( "[ %s:%d ] malloc error,fd: %d", __FILE__, __LINE__, fd );
		return -1;
	}
	memset( con, 0, sizeof(socks_client_connection_t) );
	con->connect_stamp = get_current_ms();
	con->tcp_fd = fd;
	con->http_will_recv_len	= -1;
	con->http_resend_times = 0;

	//http or tcp agent
	int agent = process->proxy_mode;
	if( agent == 0 ){
		if( rand() & AGENT_MODE_TCP )
			agent = AGENT_MODE_TCP;
		else
			agent = AGENT_MODE_HTTP;
	}
	con->proxy_mode = agent;
	int ret = connect( fd, (struct sockaddr*) &sin, sizeof (struct sockaddr));
	process->connect_num++;
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			DEBUG_ERR( "[ %s:%d ] connect sockd error, fd:%d, %s:%d", __FILE__, __LINE__, fd,  
				process->sockd_ip, process->sockd_port );
			_close_conenect( process, con, 1 );
			return -2;
		}
	}
	else if(ret == 0 ){
		if(con->proxy_mode == AGENT_MODE_TCP)
		_change_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLHUP|EPOLLERR, _negotiation_cb );
		else
		_change_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLHUP|EPOLLERR, _send_httpreq_cb );
		return fd;
	}
	
	_register_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _connect_socks_host_complete_cb );
	return fd;
	
} 

int _test_tcp_connect_result( int fd )
{
    int err = 0;
    socklen_t len = sizeof(int);

    /*
     * BSDs and Linux return 0 and set a pending error in err
     * Solaris returns -1 and sets errno
    */
    if (getsockopt( fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1)
    {
        err = errno;
    }

    return err;
}


void _connect_socks_host_complete_cb(  socks_client_process_t *process, int fd, int events, void *arg)   
{

    socks_client_connection_t *con = (socks_client_connection_t*)arg;
	int error = _test_tcp_connect_result( fd );
	if( error ){
		DEBUG_ERR( "[ %s:%d ] connect sockd error:%s, fd:%d, %s:%d, events:0x%x", __FILE__, __LINE__, 
			strerror(error), fd,  process->sockd_ip, process->sockd_port, events );
		if (error != EINPROGRESS) {
			_close_conenect(  process, con, 1 );
			return ;
		}
		return;
	}

	// connect successfully  
    if( events & (EPOLLOUT ) ){  
		struct sockaddr_in local_addr; 
		socklen_t len = sizeof(local_addr);
		getsockname( fd, (struct sockaddr*)&local_addr, &len);
		con->tcp_local_port = ntohs(local_addr.sin_port);
		_clean_recv_buf( con );
	        if(con->proxy_mode == AGENT_MODE_TCP)
                _change_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLHUP|EPOLLERR, _negotiation_cb );
                else
                _change_session_event( process->epoll_fd, con, fd, EPOLLOUT|EPOLLHUP|EPOLLERR, _send_httpreq_cb );	
    } 

}

void init_udp_remote_addr(socks_client_process_t *process, int i)
{
	inet_aton( process->udp_remote_ip[i], &process->udp_remote_addr.sin_addr );
	process->udp_remote_addr.sin_port = htons( process->udp_remote_port[i] );
	process->udp_remote_addr_len = sizeof(process->udp_remote_addr);
	memset( &process->udp_remote_header, 0 ,sizeof(socks_udp_header_t) );
	convert_to_socks_host_t(&process->udp_remote_header.host, &process->udp_remote_addr );
}

void init_client_process( socks_client_process_t *process ) 
{
	memset( process, 0, sizeof( socks_client_process_t ) );
	
	long now = get_current_ms();
	process->connect_last_stamp = now;
	process->udp_chk_stamp = now;

	strcpy(process->local_ip, "172.18.12.246");

	process->connect_max     = 4000;
	process->connect_step	 = 20;
	process->connect_interval   = 4*1000;	// 5s
	
	strcpy(process->sockd_ip, "172.18.12.174");
	process->sockd_port	= 1080; 

	// for dante test
	process->user		= "root";					
	process->passwd		= "12345";					// for dante test

	// for meteor test
	process->min_token	= 10000;					    
	process->max_token	= 10000;					    // for meteor test
	strcpy(process->token, "003" );					// for meteor test
	process->app 		= "com.tencent.mobileqq";	// for meteor test
	process->orderkey	= "123456";					// for meteor test

	process->cmd			= 1;
	process->atype			= 1;
	process->proxy_mode		= 1;
	process->http_mode 		= 1;
	strcpy(process->domain, "172.18.13.51:80" );	
	
	// for tcp test
	strcpy(process->tcp_remote_ip, "172.18.13.51");
	process->tcp_remote_port	= 80; 
	process->tcp_will_recv_len	= 890;
	strcpy(process->tcp_file_name, "003.jpg");
	process->tcp_min_cost_ms    = 999999999;

	// for udp test
	strcpy(process->udp_remote_ip[0], "172.18.13.51");
	process->udp_remote_port[0] 	= 8082;
	process->udp_remote_num = 1;
	init_udp_remote_addr( process, 0);
	
	process->udp_will_recv_len	= 4000;
	process->udp_chk_interval	= 2*1000;
	process->udp_min_cost_ms    = 999999999;
	
	process->udp_test_data = "udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!"
		"udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!"
		"udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!"
		"udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!"
		"udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!udptest!!!";

}

int start_client_process( socks_client_process_t *process)
{
	
	rb_list_init( &process->rb_node_pool, process->connect_max ); 
	rb_tree_init_for_long_key( &process->udp_connect_timer );

	// create epoll    
	process->epoll_fd = epoll_create(MAX_EVENTS);    
	if(process->epoll_fd <= 0) {
		DEBUG_ERR( "[ %s:%d ] create epoll failed:%d, %m\n", __FILE__, __LINE__, errno, errno );  
		return -1;
	}
	
	/*
	char title[32];
	sprintf( title, "client:worker-%d", process->sockd_port);
    meteor_set_process_title(title);
	*/
	
	int i=0;
	for( i=0; i< process->connect_step; i++ ){
		_init_client_socket( process );
	}
	
	printf("connect_num running: %s:%d, clients:%d\n", process->sockd_ip, process->sockd_port, process->connect_num );  
	
	// event loop    
	struct epoll_event events[MAX_EVENTS];    
	
	int timer = 1000;    
	while(1){    

		if ( to_terminate || to_quit ) {
			printf( "worker process %d exiting", process->sockd_port );
			break;
		}

		// wait for events to happen 
		int fds = epoll_wait(process->epoll_fd, events, MAX_EVENTS, timer);    
		if(fds < 0){    
			if( errno == EINTR ){
				printf( "epoll_wait interrupted, continue.");  
				continue;
			}
			printf("epoll_wait exit, %s\n", strerror(errno) );    
			break;    
		}
		
		for( i = 0; i < fds; i++){
			if(events[i].events&(EPOLLIN|EPOLLOUT) )    
			{    
				socks_client_connection_t *con = (socks_client_connection_t*)events[i].data.ptr; 
				if( !con || con->closed )
					continue;
				con->call_back( process, con->tcp_fd, events[i].events, con );  
			}
			else if((events[i].events&(EPOLLERR|EPOLLHUP) ))     
			{    
				socks_client_connection_t *con = (socks_client_connection_t*)events[i].data.ptr;  
				if( !con || con->closed)
					continue;
				DEBUG_ERR( "[ %s:%d ] epoll error events: %d, fd:%d", __FILE__, __LINE__, events[i].events, con->tcp_fd );
				_close_conenect( process, con, 1);
			} 
		}
/*
		DEBUG_INFO( "connect_max:%d, closed_num:%d, connect_num:%d, requested:%ld", 
			process->connect_max, process->closed_num, process->connect_num, 
			process->tcp_success_num+process->tcp_fail_num+process->udp_success_num+process->udp_fail_num+process->udp_lost_num );
*/
		// free connection resource
		for( i=0; i< process->closed_num; i++ ){
			if(process->closed_connection[i])
			{
				free( process->closed_connection[i] );
				process->closed_connection[i]=NULL;
			}		
		}
		process->closed_num = 0;

		long now = get_current_ms();
		// try to new connection
		if( process->connect_last_stamp + process->connect_interval < now ){ // process->connect_num <=0 || 
			process->connect_last_stamp = now;
			int to_init = process->connect_max-process->connect_num;
			if( to_init> process->connect_step)
				to_init = process->connect_step;

			for( i=0; i< to_init; i++ ){
				if( _init_client_socket( process )<0 )
					break;
			}
		}

		if( process->udp_chk_stamp + process->udp_chk_interval < now ){
			process->udp_chk_stamp = now;
			_chk_udp_connect_timer(process);
		}
		
	}
	
	rb_tree_destory( &process->udp_connect_timer, NULL );
	rb_list_exit( &process->rb_node_pool );
	
	exit(0);

}

static int get_options(int argc, char *const *argv)
{
    char  *p;
    int   i;
	int sockd_ports[8] ={0,0,0,0,0,0,0,0};
	int min_tokens [8] ={0,0,0,0,0,0,0,0};
	int max_tokens [8] ={0,0,0,0,0,0,0,0};
	char udp_remote_ip[8][64];
	int udp_remote_port[8] ={0,0,0,0,0,0,0,0};
	int udp_will_recv_len[8] ={0,0,0,0,0,0,0,0};
	int udp_chk_interval[8] ={0,0,0,0,0,0,0,0};
	int sockd_port_slot = 0;
	int udp_remote_num = 0;
	
	socks_client_process_t *client = &client_workers[0];
    
    for (i = 1; i < argc; i++) {

        p = (char *) argv[i];

        if (*p++ != '-') {
            fprintf(stderr, "invalid option: \"%s\"\n", argv[i]);
            return -1;
        }

        while (*p) {

            switch (*p++) {

            case '?':
            case 'h':
                return -1;
 
			case 'd':
				daemon_mode = 1;
				break;
			 
			case 'w':
				process_type= PROCESS_WORKER;
				break;

            case 's':
				if (*p) {
                    strcpy(client->sockd_ip, p);
                    goto next;
                }
				if (argv[++i]) {
					strcpy(client->sockd_ip, argv[i]);
                    goto next;
                }
				
                fprintf(stderr, "option \"-s\" requires sockd_ip\n");
                return -1;
  
            case 'p':
				if(sockd_port_slot>=8)
					goto fail_p;
				
                if (*p) {
                    sockd_ports[sockd_port_slot] = atoi(p);
                    goto next_p1;
                }
				if (argv[++i]) {
					sockd_ports[sockd_port_slot] = atoi(argv[i]);
                    goto next_p1;
                }
				goto fail_p;
				
				next_p1:
					if (argv[++i] && argv[i][0] != '-' ) {
						min_tokens[sockd_port_slot] = atoi(argv[i]);
						goto next_p2;
					}
					goto fail_p;
					
				next_p2:
					if (argv[++i] && argv[i][0] != '-' ) {
						max_tokens[sockd_port_slot] = atoi(argv[i]);
						sockd_port_slot++;
						goto next;
					}
					
				fail_p:
	                fprintf(stderr, "option \"-p\" requires sockd_port min_token max_token\n");
					return -1;

			case 'n':
				if (*p) {
					client->cmd = atoi(p);
					goto next;
				}
				if (argv[++i]) {
					client->cmd = atoi(argv[i]);
					goto next;
				}
				
				fprintf(stderr, "option \"-n\" requires cmd: 0, 1, 3\n");
				return -1;
			
		        case 'a':
                                if (*p) {
                                        client->atype = atoi(p);
                                        goto next;
                                }
                                if (argv[++i]) {
                                        client->atype = atoi(argv[i]);
                                        goto next;
                                }

                                fprintf(stderr, "option \"-a\" requires atype: 0, 1, 3\n");
                                return -1;			
		        case 'x':
                                if (*p) {
                                        client->proxy_mode = atoi(p);
                                        goto next_x1;
                                }
                                if (argv[++i]) {
                                        client->proxy_mode = atoi(argv[i]);
                                        goto next_x1;
                                }
				goto fail_x;

                            next_x1:
                            	if (argv[++i] && argv[i][0] != '-' ) {
										client->http_mode = atoi(argv[i]);
										goto next;
								}
										goto fail_x;

                            fail_x:
                                fprintf(stderr, "option \"-x\" requires proxy_mode http_mode: 0, 1, 3\n");
                                return -1;
			case 'o':
  
            case 't':
                if (*p) {
                    strcpy(client->tcp_remote_ip, p);
                    goto next_t1;
                }
                if (argv[++i]) {
                    strcpy(client->tcp_remote_ip, argv[i]);
                    goto next_t1;
                }
				goto fail_t;
				
 				next_t1:
					if (argv[++i] && argv[i][0] != '-' ) {
						client->tcp_remote_port = atoi(argv[i]);
						goto next_t2;
					}
					goto fail_t;
					
				next_t2:
					if (argv[++i] && argv[i][0] != '-' ) {
						client->tcp_will_recv_len = atoi(argv[i]);
						goto next_t3;
					}
					goto fail_t;
						
				next_t3:
					if (argv[++i] && argv[i][0] != '-' ) {
						strcpy(client->tcp_file_name, argv[i]);
						goto next;
					}
							
				fail_t:
					fprintf(stderr, "option \"-t\" requires tcp_remote_ip tcp_remote_port tcp_will_recv_len tcp_file_name\n");
					return -1;               
                     
            case 'c':
				if (*p) {
					client->connect_max= atoi(p);
					goto next_c1;
				}
				if (argv[++i]) {
					client->connect_max = atoi(argv[i]);
					goto next_c1;
				}
				goto fail_c;
				
				next_c1:
					if (argv[++i] && argv[i][0] != '-' ) {
						client->connect_step= atoi(argv[i]);
						goto next_c2;
					}
					goto fail_c;
					
				next_c2:
					if (argv[++i] && argv[i][0] != '-' ) {
						client->connect_interval= atoi(argv[i])*1000;
						goto next;
					}
					
				fail_c:
					fprintf(stderr, "option \"-c\" requires connect_max connect_step connect_interval\n");
					return -1;
        
            case 'u':
                if (*p) {
                    strcpy(udp_remote_ip[udp_remote_num], p);
                    goto next_t1;
                }
                if (argv[++i]) {
                    strcpy(udp_remote_ip[udp_remote_num], argv[i]);
                    goto next_u1;
                }
				goto fail_u;
				
 				next_u1:
					if (argv[++i] && argv[i][0] != '-' ) {
						udp_remote_port[udp_remote_num] = atoi(argv[i]);
						goto next_u2;
					}
					goto fail_u;
					
				next_u2:
					//init_udp_remote_addr( client, 0);
					if (argv[++i] && argv[i][0] != '-' ) {
						udp_will_recv_len[udp_remote_num] = atoi(argv[i]);
						goto next_u3;
					}
					goto fail_u;
						
				next_u3:
					if (argv[++i] && argv[i][0] != '-' ) {
						udp_chk_interval[udp_remote_num] = atoi(argv[i])*1000;
						udp_remote_num++;
						goto next;
					}
							
				fail_u:
					fprintf(stderr, "option \"-u\" requires udp_remote_ip udp_remote_port udp_will_recv_len udp_chk_interval\n");
					return -1;               

            default:
                fprintf(stderr, "invalid option: \"%c\"\n", *(p - 1));
                return -1;
            }
        }
    
        next:
            continue;
    }
	
	i=1;
	if( sockd_port_slot>0){
		client->sockd_port = sockd_ports[0];
		client->min_token  = min_tokens[0];
		client->max_token  = max_tokens[0];
	}
	while( i< sockd_port_slot ){
		memcpy(&client_workers[i], client, sizeof(socks_client_process_t) );
		client_workers[i].sockd_port = sockd_ports[i];
		client_workers[i].min_token  = min_tokens[i];
		client_workers[i].max_token  = max_tokens[i];
		i++;
	}

	i = 0;
	while(i< sockd_port_slot){
		int j = 0;
		while(j < udp_remote_num){
			strcpy(client_workers[i].udp_remote_ip[j], udp_remote_ip[j]);
			client_workers[i].udp_remote_port[j] = udp_remote_port[j];
			client_workers[i].udp_will_recv_len = udp_will_recv_len[j];
			client_workers[i].udp_chk_interval = udp_chk_interval[j];
			client_workers[i].udp_remote_num = udp_remote_num;
			init_udp_remote_addr( client, j);
			j++;
		}
		i++;
	}

    return sockd_port_slot;
}


int main( int argc, char *argv[] )
{

	// init client process info
	
	srand(time(NULL));
	
	char * usage =	"meteor client for function and performance testing. \n"
		"usage: client [-?hspnctu] [arg] [arg] [arg] [arg]\n\n"
		"options:\n\n"
		"  -?,-h print the help info\n"
		"     -d run as daemon mode\n"
		"     -w will start worker process mode\n"
		"     -s <sockd_ip>\n"
		"     -p <sockd_port min_token max_token>, may be more than one\n"
		"     -n <cmd>, cmd is 0,1,3, if 0 will rand in (1,3)\n"
		"     -c <connect_max new_connect_step new_connect_interval>\n"
		"     -t <tcp_remote_ip tcp_remote_port tcp_will_recv_len tcp_file_name>\n"
		"     -u <udp_remote_ip udp_remote_port udp_will_recv_len udp_chk_interval>\n"
		"     -a <atype>, atype is 0,1,3, if 0 will rand in (1,3)\n"
		"     -x <proxy_mode http_mode>, proxy_mode http_mode are 0,1,3, if 0 will rand in (1,3),\n";

	
	init_client_process( &client_workers[0] );

	int worker_num = 0;
    if( (worker_num = get_options(argc, argv))< 0 ){
        fprintf( stderr, "%s\n", usage );
        exit(0);
    }
	
	if( worker_num == 0)
		worker_num = 1;
	
	if( process_type == PROCESS_WORKER ){
		start_client_process(  &client_workers[0] );
		return;
	}
	
    socks_init_signals();
	
	if( daemon_mode ){
		if (meteor_daemon() != 0 ) {
	        return 1;
	    }
	}

    // start master process
    process_type = PROCESS_MASTER;
	
    sigset_t set;
	block_process_signal_mask( &set );
    sigemptyset(&set);

    // set master process title
    meteor_set_master_process_title(argc,argv);

	int i = 0;
    for ( ; i < worker_num ; i++) {
        spawn_process( i, PROCESS_RESPAWN );
    }

    int live = 1;

    while(1)
    {
        sigsuspend(&set);
 
        if (to_reap) {
            to_reap = 0;
            printf( "reap children" );
            live = reap_children();
        }

        if (!live && (to_terminate || to_quit)) {
            exit(0);
        }

        if (to_terminate) {
            //send_signal_to_worker_process(SIGKILL);
            printf( "client worker processes will terminate...");
            send_signal_to_worker_process(SIGTERM);
            //to_terminate = 0;
            continue;
        }    

        if (to_quit) {
            printf( "client worker processes will gracefully quit... ");
            send_signal_to_worker_process(SIGQUIT);
            continue;
        }
               
    }
	
}

 

