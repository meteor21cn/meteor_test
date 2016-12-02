#include "http_proxy.h"
#include "sockd_tcp.h"
#include "http_auth.h"

static int _get_http_addr( http_info_t *http_info, struct sockaddr_in *sin );
static int _conver_domain_to_addr( char * domain, struct sockaddr_in * addr_in);
static int _chk_header_recv_complete(socks_connection_t *con);
static int _chk_header_recv_legal(http_request_t *request);
static int _connect_http_remote_host_ipv4(socks_worker_process_t *process, socks_connection_t *con );
static int _send_http_request( socks_worker_process_t *process, socks_connection_t * client, socks_connection_t *remote);
static int _send_http_response(socks_worker_process_t *process, socks_connection_t *con, http_proxy_response_t *response, int proxy_mode);
static int _rewrite_request_header(socks_worker_process_t *process, socks_connection_t *con, http_info_t *http_info);
static int _copy_remote_data_to_rewrite_buf(socks_connection_t *con, http_response_t * response);
static int _send_rewrite_buf_data( socks_connection_t * con ,http_response_t * response, int send_fd );
static void _do_http_connect( socks_worker_process_t *process, socks_connection_t *con,  struct sockaddr_in * addr_in );
static void _http_client_data_transform_cb(  socks_worker_process_t *process, int fd, int events, void *arg);
static void _http_remote_data_transform_cb(  socks_worker_process_t *process, int fd, int events, void *arg);
static void _connect_http_remote_host_complete_cb(  socks_worker_process_t *process, int remote_fd, int events, void *arg);

static int _rewrite_request_header(socks_worker_process_t *process, socks_connection_t *con, http_info_t *http_info)
{
	if(! http_info->request.proxy_mode){
		//forword mode
		//TODO: do some test
		int old_header_len = con->data_length;
		memset(con->buf, 0, RECV_BUF_SIZE);
		//http_info->request.x_meteorq_start = strstr(http_info->request.head_in, HTTP_REQUSET_FIELD_XMETEORQ);
		//http_info->request.x_meteorq_end = strstr(http_info->request.x_meteorq_start, CRLF);

		int len = http_info->request.x_meteorq_start - http_info->request.head_in;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] get  x_meteorq_start failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(con->buf, http_info->request.head_in, len);

		unsigned char x_meteor[512];
		sprintf(x_meteor, "%s %s.%d.%d.%s.%s.%s",
			HTTP_REQUSET_FIELD_XMETEOR,
			process->config->listen_host, process->config->listen_port,
			http_info->request.auth_mode, con->session->token,
			con->session->app_pname, con->session->passwd);

		memcpy(con->buf + len, x_meteor, strlen(x_meteor));
		len += strlen(x_meteor);

		memcpy(con->buf + len , http_info->request.x_meteorq_end + 1, 
			old_header_len - (http_info->request.x_meteorq_end - http_info->request.head_in));

	}
	else{
		//reverse mode
		int old_header_len = con->data_length;
		memset(con->buf, 0, RECV_BUF_SIZE);
		unsigned char * header_end = strstr(http_info->request.head_in, CRLFCRLF);
		if (header_end == NULL){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		int len = 0;
		int add_len = 0;
		add_len = http_info->request.host_start - http_info->request.head_in;
		if (add_len<0 || !http_info->request.host_start ){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(con->buf, http_info->request.head_in, add_len);
		len += add_len;

		
		// change HOST: area
		unsigned char* host_pos = http_info->request.header_host_start ;
		unsigned char* host_end = http_info->request.header_host_end + 2;
		if (!host_pos){
			return -1;
		}
		add_len =  host_pos - http_info->request.real_uri_start;
		if (add_len<0 || !http_info->request.real_uri_start){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(con->buf + len, http_info->request.real_uri_start, add_len);
		len += add_len;

		add_len = http_info->request.dest_host_end - http_info->request.dest_host_start + 1;
		if (add_len<0 || ! http_info->request.dest_host_end ||  !http_info->request.dest_host_start){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(con->buf + len, http_info->request.dest_host_start, add_len);
		len += add_len;

		add_len = header_end+2 - host_end;
		if (add_len<0 || !host_end){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(con->buf + len, host_end , add_len);
		len  += add_len;

		unsigned char x_meteor[512];
		sprintf(x_meteor, "%s %s.%d.%d.%s.%s.%s",
			HTTP_REQUSET_FIELD_XMETEOR,
			process->config->listen_host, process->config->listen_port,
			http_info->request.auth_mode, con->session->token,
			con->session->app_pname, con->session->passwd);

		memcpy(con->buf + len, x_meteor, strlen(x_meteor));
		len += strlen(x_meteor);

		add_len = old_header_len - (header_end -  http_info->request.head_in);
		if (add_len<0){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(con->buf + len, header_end, add_len);
	}

	return 0;
}

static int _chk_header_recv_complete(socks_connection_t *con)
{
	if (strstr(con->buf, CRLF) == NULL)
		return -1;
	if (strstr(con->buf, CRLFCRLF) == NULL)
		return -1;

	return 0;
}

static int _chk_header_recv_legal(http_request_t *request)
{
	if (request->http_version != HTTP_VERSION_10 && request->http_version != HTTP_VERSION_11){
		return -1;
	}
	if (!request->proxy_mode ){
		//forword mode

	}
	else{
		//reverse mode
	}

	return 0;
}

static int _get_http_addr( http_info_t * http_info, struct sockaddr_in *sin )
{
	unsigned char header_addr[512];
	memset(header_addr, 0, sizeof(header_addr));
	int len;
	
	if (! http_info->request.proxy_mode){
		//forword mode
		len = http_info->request.host_end - http_info->request.host_start + 1;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] get  header line addr failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(header_addr, http_info->request.host_start, len);
	}
	else{
		//reverse mode
		len = http_info->request.dest_host_end - http_info->request.dest_host_start + 1;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] get  header line addr failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(header_addr, http_info->request.dest_host_start, len);
	}

	unsigned char * host_pos = header_addr;

	unsigned char * host_end_pos = header_addr + len;

	/*unsigned char * host_pos = strstr(http_info->request.head_in, "Host: ") + 6;

	unsigned char * host_end_pos = strstr(host_pos, CRLF);*/

	//find port
	unsigned char * port_pos = strstr( host_pos, ":");
	int has_port = 0;
	if (port_pos != NULL && port_pos<host_end_pos){
		has_port = 1;
	}

	int host_len, port_len;
	if (has_port){
		host_len = port_pos - host_pos;
		port_len = host_end_pos - port_pos - 1;
	}
	else{
		host_len = host_end_pos - host_pos;
		port_len = 2;
	}

	unsigned char hostname[host_len + 1];
	memcpy( hostname, host_pos, host_len);
	hostname[host_len] = '\0';

	int port = HTTP_DEFINE_PORT;
	if (has_port){
		char host_port[port_len + 1];
		memcpy(host_port, port_pos + 1, port_len);
		host_port[port_len] = '\0';
		port = atoi(host_port);
	}
	sys_log(LL_DEBUG, "[ %s:%d ] http host %s:%d", __FILE__, __LINE__ , hostname, port);

	sin->sin_port = htons(port);
	int ret = _conver_domain_to_addr( hostname, sin);
	if (ret<0){
		return -1;
	}

	sys_log(LL_DEBUG, "[ %s:%d ] http host %s:%d", __FILE__, __LINE__ , inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
	return 0;
}

static int _conver_domain_to_addr( char * domain, struct sockaddr_in * addr_in)
{
	extern int h_errno;
	struct hostent *h;
	h=gethostbyname(domain);
	if(h==NULL)
	{	
		sys_log(LL_ERROR,  "[ %s:%d ] gethostbyname failed ! errinfo: %s", __FILE__, __LINE__, hstrerror(h_errno));
		return -1;
	}
	else
	{
		memcpy(&addr_in->sin_addr.s_addr,h->h_addr,4);
	}
	return 0;
}

static int _copy_remote_data_to_rewrite_buf(socks_connection_t *con, http_response_t * response)
{
	int recv_len = con->data_length - con->sent_length;
	int will_read = HTTP_REWRITE_BUF_SIZE - response->data_length;
	if( will_read > recv_len)
		will_read = recv_len;

	memcpy(response->rewrite_buf + response->data_length, con->buf + con->sent_length, will_read);
	response->data_length += will_read;
	con->sent_length += will_read;

	return response->data_length;
}

static int _send_rewrite_buf_data( socks_connection_t * con ,http_response_t * response, int send_fd )
{
	int total = 0;	
	// will send size 
	int size = response->data_length-response->sent_length;
	if( size <=0 | size+response->sent_length>HTTP_REWRITE_BUF_SIZE|| response->sent_length < 0 || 
		response->sent_length >=HTTP_REWRITE_BUF_SIZE || response->data_length<0 
		|| response->data_length>HTTP_REWRITE_BUF_SIZE ){
		sys_log(LL_ERROR, "[ %s:%d ] buf error, fd:%d, send_fd: %d, dlen:%d, slen:%d", __FILE__, __LINE__, con->fd, send_fd, 
			response->data_length, response->sent_length );
		func_stack_dump( 0 );
		return -1;
	}
	
	do{
		int len = send(send_fd, &response->rewrite_buf[response->sent_length], size, MSG_DONTWAIT ); //MSG_WAITALL
		if (len > 0)
		{
			response->sent_length += len;
			total += len;
			return total;
		}
		else if( len == 0 ){ 
			sys_log(LL_ERROR, "[ %s:%d ] net disconnected when send data. fd: %d, dlen:%d, slen:%d, size:%d", __FILE__, __LINE__, 
				send_fd, response->data_length, response->sent_length, size );
			return -1;
		}
		else{
			int err = errno;
			if (err == EAGAIN)
			{
				sys_log(LL_DEBUG, "[ %s:%d ] send EAGAIN, fd: %d, dlen:%d, size:%d, %s", __FILE__, __LINE__, 
					send_fd, response->data_length, size, strerror(errno)  );
				break;
			}

			if (err == EINTR)
			{
				sys_log(LL_DEBUG, "[ %s:%d ] send EINTR, fd: %d, %s", __FILE__, __LINE__, send_fd, strerror(err)  );
				continue;
			}
			/*if (err == EPIPE)
			{
				sys_log(LL_ERROR, "[ %s:%d ] send EPIPE, fd: %d, %s", __FILE__, __LINE__, send_fd, strerror(err)  );
				func_stack_dump( err);
				return -1;
			}*/
			sys_log(LL_ERROR, "[ %s:%d ] send error:%d, %s, fd: %d", __FILE__, __LINE__, err, strerror(err), send_fd );
			//func_stack_dump( err);
			return -1;
		}
		
	}
	while( 1 );
	
	return response->sent_length;

}
static void _clean_rewrite_buf( http_response_t *response )
{
	memset( response->rewrite_buf, 0, HTTP_REWRITE_BUF_SIZE );
	response->data_length = 0;
	response->sent_length = 0;
}

static void _do_http_connect( socks_worker_process_t *process, socks_connection_t *con,  struct sockaddr_in * addr_in )
{
	socks_connection_t *remote = (socks_connection_t *)malloc(sizeof(socks_connection_t));
	if( remote == NULL ){
		sys_log(LL_ERROR, "[ %s:%d ] malloc remote error,fd: %d", __FILE__, __LINE__, con->fd );
		close_session( process, con->session);
		return;
	}
	memset( (void *)remote, 0,	sizeof(socks_connection_t) );
	con->session->remote = remote;
	remote->session = con->session;

	copy_sockaddr_to_hostname( &addr_in->sin_addr, remote->peer_hostname);
	//FIXME
	remote->peer_host.atype = SOCKS_ATYPE_IPV4;
	memcpy( &remote->peer_host.addr.ipv4 , &addr_in->sin_addr, sizeof(addr_in->sin_addr) );
	memcpy( &remote->peer_host.port , &addr_in->sin_port, sizeof(addr_in->sin_port) );

	remote->peer_conn = con;
	con->peer_conn = remote;
	
	sys_log(LL_DEBUG, "[ %s:%d ] connect command: %s:%d", __FILE__, __LINE__, remote->peer_hostname, ntohs(remote->peer_host.port));
	
	int ret = _connect_http_remote_host_ipv4( process, con ); 
	if( ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] connect remote: %s:%d failed !", __FILE__, __LINE__, remote->peer_hostname, ntohs(remote->peer_host.port));
		con->session->http_info->proxy_response.status = HTTP_CONNECT_ERR;
		_send_http_response(process, con, &con->session->http_info->proxy_response, con->session->http_info->request.proxy_mode);
		close_session(process, con->session);
		return;
	}

	return;
}

// while data from client or remote host, then transform to the orther peer
static void _http_client_data_transform_cb(  socks_worker_process_t *process, int fd, int events, void *arg)
{
	// about recv and send, see http://www.cnblogs.com/blankqdb/archive/2012/08/30/2663859.html
	socks_connection_t *con = (socks_connection_t*)arg;

	if( con->session->stage != HTTP_STAGE_TCP_DATA ){
		sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d", __FILE__, __LINE__, con->session->stage, fd );
		close_session( process, con->session);
		return;
	}

	if( con->closed ){
		sys_log(LL_DEBUG, "[ %s:%d ] client closed by %d, fd:%d, dlen:%d, slen:%d, ", __FILE__, __LINE__, 
			con->session->closed_by, fd, con->data_length, con->sent_length);
		return;
	}
	
	if( events & EPOLLIN)
	{
		int len = _recv_data( con, RECV_BUF_SIZE-con->data_length );
		//sys_log(LL_DEBUG, "[ %s:%d ] just only %s recv, fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
		//	up_direct?"client":"remote", con->fd, con->data_length, con->sent_length );
		if( len <0 || con->eof == 1) 
		{
			int level = (con->eof == 1? LL_DEBUG: LL_ERROR);
			sys_log(level, "[ %s:%d ] client recv eof:%d, fd:%d, dlen:%d, slen:%d, len: %d, errno:%d, %s", __FILE__, __LINE__, 
				con->eof, con->fd, con->data_length, con->sent_length, len, errno, strerror(errno) );
			if( con->eof )
				close_session( process, con->session);
			return;
		}

		//stat up flow
		if( len > 0 )
			do_stat_order_flow( process, con->session, len, 1, 1 );

		//TODO: rewrite recv data
	}

	if( events & EPOLLOUT )
	{
		socks_connection_t *peer = con->peer_conn;
		http_response_t * response = &con->session->http_info->response;
		if( response->data_length > response->sent_length ){
			sys_log(LL_DEBUG, "[ %s:%d ] continue, send to client , fd:%d, recv_fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
				con->fd, peer->fd, response->data_length, response->sent_length);
			
			int len = _send_rewrite_buf_data( peer, response, con->fd );
			if( len <0 ) {
				int err = errno;
				if( err == EPIPE || err == ECONNRESET){
					con->eof = 1;
					close_session( process, con->session);
				}
				int level = (con->eof == 1 ? LL_DEBUG: LL_ERROR );
				sys_log(level, "[ %s:%d ] client send eof:%d, fd:%d, recv_fd:%d, dlen:%d, slen:%d, len: %d, errno:%d, %s", __FILE__, __LINE__, 
					con->eof, con->fd, peer->fd, response->data_length, 
					response->sent_length, len, errno, strerror(errno) );
				return;
			}

			//stat down flow
			if( len > 0 )
				do_stat_order_flow( process, con->session, len, 0, 1 );
			
			if( response->sent_length == response->data_length && response->data_length>0 ){
				_clean_rewrite_buf( response );
				_copy_remote_data_to_rewrite_buf(peer, &peer->session->http_info->response);
				if (peer->sent_length == peer->data_length && peer->data_length > 0){
					_clean_recv_buf(peer);
				}
			}
		}
		else{
			//sys_log(LL_DEBUG, "[ %s:%d ] no data for send to %s , fd:%d, recv_fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
			//	up_direct?"client":"remote", con->fd, peer->fd, peer->data_length, peer->sent_length);
		}
	}

}

static void _http_remote_data_transform_cb(  socks_worker_process_t *process, int fd, int events, void *arg)
{
	// about recv and send, see http://www.cnblogs.com/blankqdb/archive/2012/08/30/2663859.html
	socks_connection_t *con = (socks_connection_t*)arg;

	if( con->session->stage != HTTP_STAGE_TCP_DATA ){
		sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d", __FILE__, __LINE__, con->session->stage, fd );
		close_session( process, con->session);
		return;
	}

	if( con->closed ){
		sys_log(LL_DEBUG, "[ %s:%d ] remote closed by %d, fd:%d, dlen:%d, slen:%d, ", __FILE__, __LINE__, 
			con->session->closed_by, fd, con->data_length, con->sent_length);
		return;
	}
	
	if( events & EPOLLIN)
	{
		int len = _recv_data( con, RECV_BUF_SIZE-con->data_length );
		//sys_log(LL_DEBUG, "[ %s:%d ] just only %s recv, fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
		//	up_direct?"client":"remote", con->fd, con->data_length, con->sent_length );

		//TODO: rewrite recv data
		_copy_remote_data_to_rewrite_buf(con, &con->session->http_info->response);
		if (con->sent_length == con->data_length && con->data_length > 0){
			_clean_recv_buf(con);
		}

		if( len <0 || con->eof == 1) 
		{
			int level = (con->eof == 1? LL_DEBUG: LL_ERROR);
			sys_log(level, "[ %s:%d ] remote recv eof:%d, fd:%d, dlen:%d, slen:%d, len: %d, errno:%d, %s", __FILE__, __LINE__, 
				con->eof, con->fd, con->data_length, con->sent_length, len, errno, strerror(errno) );
			if( con->eof )
				close_session( process, con->session);
			return;
		}
	}

	if( events & EPOLLOUT )
	{
		socks_connection_t *peer = con->peer_conn;
		if( peer->data_length > peer->sent_length ){
			sys_log(LL_DEBUG, "[ %s:%d ] continue, send to remote , fd:%d, recv_fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
				con->fd, peer->fd, peer->data_length, peer->sent_length);
			
			int len = _send_data( peer, con->fd );
			if( len <0 ) {
				int err = errno;
				if( err == EPIPE || err == ECONNRESET){
					con->eof = 1;
					close_session( process, con->session);
				}
				int level = (con->eof == 1 ? LL_DEBUG: LL_ERROR );
				sys_log(level, "[ %s:%d ] remote send eof:%d, fd:%d, recv_fd:%d, dlen:%d, slen:%d, len: %d, errno:%d, %s", __FILE__, __LINE__, 
					con->eof, con->fd, peer->fd, con->data_length, con->sent_length, len, errno, strerror(errno) );
				return;
			}
			
			if( peer->sent_length == peer->data_length && peer->data_length>0 ){
				_clean_recv_buf( peer );
			}
		}
		else{
			//sys_log(LL_DEBUG, "[ %s:%d ] no data for send to %s , fd:%d, recv_fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
			//	up_direct?"client":"remote", con->fd, peer->fd, peer->data_length, peer->sent_length);
		}
	}

}

// connect remote host completed callback, then reply the result to client
// only for ipv4
static void _connect_http_remote_host_complete_cb(  socks_worker_process_t *process, int remote_fd, int events, void *arg)   
{
	socks_connection_t *remote = (socks_connection_t*)arg;
	socks_connection_t *client = remote->session->client;

	if( remote->session->stage != HTTP_STAGE_CONNECT ){
		sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d ", __FILE__, __LINE__, remote->session->stage, remote_fd );

	}

	int error = _test_tcp_connect_result( remote_fd );
	remote->event_count++;
	long cost = get_current_ms() - remote->conn_stamp ;
	if( error ){
		// EPOLLIN:1 EPOLLOUT:4 EPOLLRDHUP:8192  EPOLLPRI:2  EPOLLERR:8  EPOLLHUP:16
		sys_log(LL_ERROR, "[ %s:%d ] connect remote error:%s, fd:%d, %s:%d, events:0x%x, count:%d, cost:%d", __FILE__, __LINE__, 
			strerror(error), remote_fd,  remote->peer_hostname, ntohs(remote->peer_host.port), events, remote->event_count, cost );
		if (error != EINPROGRESS) {
			remote->session->http_info->proxy_response.status = HTTP_CONNECT_ERR;
			_send_http_response(process, remote, &remote->session->http_info->proxy_response, remote->session->http_info->request.proxy_mode);
			close_session(process, remote->session);
			return;
		}
		return;
	}

	remote->session->stage = HTTP_STAGE_TCP_DATA;

	// connect successfully  
	if( events & (EPOLLOUT) ){  
		struct sockaddr_in local_addr; 
		socklen_t len = sizeof(local_addr);
		getsockname( remote_fd, (struct sockaddr*)&local_addr, &len);
		
		copy_sockaddr_to_hostname( &local_addr.sin_addr, remote->local_hostname);
		remote->local_port = ntohs(local_addr.sin_port);
		
		sys_log(LL_DEBUG, "[ %s:%d ] connect remote ok, fd:%d, local: %s:%d", __FILE__, __LINE__, remote_fd, remote->local_hostname, remote->local_port );
		_clean_recv_buf( remote );
		//send http request
		len = _send_http_request(process, client, remote);
		if (len > 0){
			_clean_recv_buf( client );
			_clean_recv_buf( remote );
			_clean_rewrite_buf( &client->session->http_info->response);
			client->session->stage = HTTP_STAGE_TCP_DATA;
			_change_session_event( process->epoll_fd, client, client->fd, EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLERR, _http_client_data_transform_cb );
			_change_session_event( process->epoll_fd, remote, remote_fd, EPOLLIN|EPOLLOUT|EPOLLHUP|EPOLLERR, _http_remote_data_transform_cb );
			return;
		}

		return;
	} 

}

static int _connect_http_remote_host_ipv4(socks_worker_process_t *process, socks_connection_t *con )
{
	socks_connection_t *remote = con->session->remote;

	struct sockaddr_in s_addr;
	convert_to_sockaddr_in( &remote->peer_host, &s_addr);

	int fd = remote->fd = socket(AF_INET, SOCK_STREAM, 0);

	if ( fd < 0) {
		sys_log(LL_ERROR, "[ %s:%d ] create remote socket error, fd:%d, %s:%d", __FILE__, __LINE__, fd, remote->peer_hostname, 
			ntohs(remote->peer_host.port) );
		return -1;
	}

	int value = process->config->reuseaddr ==1?1:0;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(int)) == -1){
		sys_log(LL_ERROR, "[ %s:%d ] set SO_REUSEADDR fail, fd:%d", __FILE__, __LINE__, fd );
	}

	//value = 1;
	//setsockopt( fd, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (void *)&value, sizeof(int));

	int flags = fcntl( fd, F_GETFL, 0);
	if (flags < 0) {
		sys_log(LL_ERROR, "[ %s:%d ] %s: get socket flags errorfd:%d, %s:%d", __FILE__, __LINE__, fd, remote->peer_hostname, 
			ntohs(remote->peer_host.port) );
		return -1;
	}

	if (fcntl( fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		sys_log(LL_ERROR, "[ %s:%d ] %s: set remote socket nonblock error,fd:%d, %s:%d", __FILE__, __LINE__, fd, remote->peer_hostname, 
			ntohs(remote->peer_host.port) );
		return -1;
	}

	con->session->stage = HTTP_STAGE_CONNECT;

	_register_session_event( process->epoll_fd, remote, fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _connect_http_remote_host_complete_cb );
	remote->conn_stamp = get_current_ms();
	int ret = connect( fd, (struct sockaddr*) &s_addr, sizeof (struct sockaddr));
	if (ret < 0) {
		if (errno != EINPROGRESS) {
			sys_log(LL_ERROR, "[ %s:%d ] connect remote error, fd:%d, %s:%d", __FILE__, __LINE__, fd,  remote->peer_hostname, 
				ntohs(remote->peer_host.port) );
			return errno;
		}
	}
	if( ret == 0 ){
		sys_log(LL_ERROR, "[ %s:%d ] quick connect remote ok, fd:%d, %s:%d", __FILE__, __LINE__, fd,  remote->peer_hostname, 
			ntohs(remote->peer_host.port) );
	}

	return 0;

}

static int _send_http_request( socks_worker_process_t *process, socks_connection_t * client, socks_connection_t *remote)
{
	//memcpy( remote->buf, client->buf, client->data_length);
	int len = _send_data(client, remote->fd);
	if( len <0 ) {
		int err = errno;
		if( err == EPIPE || err == ECONNRESET){
			remote->eof = 1;
			close_session( process, remote->session);
		}
		int level = (remote->eof == 1 ? LL_DEBUG: LL_ERROR );
		sys_log(level, "[ %s:%d ] %s send eof:%d, fd:%d, recv_fd:%d, dlen:%d, slen:%d, len: %d, errno:%d, %s", __FILE__, __LINE__, 
			"remote", remote->eof, remote->fd, client->fd, remote->data_length, remote->sent_length, len, errno, strerror(errno) );
		return -1;
	}

	return len;

}

static int _send_http_response(socks_worker_process_t *process, socks_connection_t *con, http_proxy_response_t *response, int proxy_mode)
{
	unsigned char response_buf[512];
	unsigned char str_time[64] = {0};
	unsigned char http_version[16];
	int send_length;
	long now = time(NULL);
	struct tm *ptime = localtime( &now );
	strftime(str_time, sizeof(str_time), "%c", ptime);

	switch ( con->session->http_info->request.http_version){
		case HTTP_VERSION_10:{
			strcpy(http_version, "HTTP/1.0");
			break;
		}
		case HTTP_VERSION_11:{
			strcpy(http_version, "HTTP/1.1");
			break;
		}
		default :{
			strcpy(http_version, "HTTP/1.1");
			break;
		}
	}

	unsigned char uri[HTTP_URI_MAX_LEN] = {0};
	unsigned char *pos = uri;
	int len;

	if (!proxy_mode){
		//forword mode
		len = con->session->http_info->request.uri_end - con->session->http_info->request.uri_start + 1;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] _send_http_response get  header line uri failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(pos, con->session->http_info->request.uri_start, len);
		sprintf(response_buf, "%s %s %s\r\n%s %s\r\n%s %s:%d\r\n%s %d.%d.%ld.%ld.%ld\r\n\r\n",
			http_version, HTTP_CODE_UNAUTHORIZED, HTTP_TEXT_UNAUTHORIZED,
			HTTP_RESPONSE_FIELD_TIME, str_time,
			HTTP_RESPONSE_FIELD_SERVER, process->config->listen_host,  process->config->listen_port,
			HTTP_RESPONSE_FIELD_METEORS, response->status, response->order_status,
			response->order_balance, response->used_today, response->company_balance);
	}
	else{
		//reverse mode
		len = con->session->http_info->request.host_start - con->session->http_info->request.uri_start;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] _send_http_response get  header line uri failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(pos, con->session->http_info->request.uri_start, len);
		pos += len;

		len = con->session->http_info->request.real_uri_end - con->session->http_info->request.real_uri_start + 1;
		if(len <= 1){
			sys_log(LL_ERROR, "[ %s:%d ] _send_http_response get  header line uri failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(pos, con->session->http_info->request.real_uri_start, len);
		sprintf(response_buf, "%s %s %s\r\n%s %s\r\n%s %s:%d\r\n%s %s\r\n%s %d.%d.%ld.%ld.%ld\r\n\r\n",
			http_version, HTTP_CODE_MOVE_TEMPORARY, HTTP_TEXT_MOVE_TEMPORARY,
			HTTP_RESPONSE_FIELD_TIME, str_time,
			HTTP_RESPONSE_FIELD_SERVER, process->config->listen_host, process->config->listen_port,
			HTTP_RESPONSE_FIELD_LOCATION, uri,
			HTTP_RESPONSE_FIELD_METEORS, response->status, response->order_status,
			response->order_balance, response->used_today, response->company_balance);
	}

	memset(con->buf, 0, RECV_BUF_SIZE);
	memcpy(con->buf, response_buf, sizeof(response_buf));
	send_length = sizeof(response_buf);
	printf("response\n%s\n", con->buf);
	
	
	len = _send_data_until_length( con, con->fd, send_length );
	if(len <= 0 )	
	{  
		sys_log(LL_ERROR, "[ %s:%d ] cmd status:0x%2x send failed, fd:%d", __FILE__, __LINE__, response->status, con->fd );
		close_session( process, con->session);
	}
	else
		do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 0, 0 );
	return 0;
}

void http_cb (  socks_worker_process_t *process, int client_fd, int events, socks_connection_t *con)    
{    

	if( con->session->stage != SOCKS_STAGE_NEGOTIATION ){
		sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d ", __FILE__, __LINE__, con->session->stage, client_fd );
		close_session( process, con->session);
		return;
	}
	
	int len;    
	int will_read = HTTP_REQUSET_HEADER_MAX_LENGTH;
	len = _recv_data_until_length ( con, will_read );
	
	//TODO: check if header recv complted
	/*char *test_buf ="GET http://172.18.12.1s/meteorq.0.0.1.001|888|b29adac2bdc027497fa3a327d8566326/www.baidu.com HTTP/1.1\r\n"
			"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\n"
			"Proxy-Connection: keep-alive\r\n"
			"Connection: keep-alive\r\n"
			"Host: 172.18.12.1\r\n\r\n";
			"Connection: keep-alive\r\n\r\n";*/

	/*char *test_buf ="GET http://www.baidu.com HTTP/1.1\r\n"
			"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\n"
			"Proxy-Connection: keep-alive\r\n"
			"Connection: keep-alive\r\n"
			"Host: www.baidu.com\r\n"
			"X-Meteorq: 1.001|888|b29adac2bdc027497fa3a327d8566326\r\n\r\n";

	len = strlen(test_buf);
	_clean_recv_buf(con);
	strcpy(con->buf, test_buf);
	con->data_length = len;*/

	http_info_t *http_info = (http_info_t *)malloc(sizeof(http_info_t));
	memset(http_info, 0, sizeof(http_info));
	con->session->http_info = http_info;

	if( con->eof ){
		//net disconnected. close session
		sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv http connection, len: %d", __FILE__, __LINE__, len );
		close_session( process, con->session);
		return;
	}

	if (con->data_length > will_read){
		sys_log(LL_ERROR, "[ %s:%d ] http header too long, len: %d, def max: %d", __FILE__, __LINE__, len, HTTP_REQUSET_HEADER_MAX_LENGTH );
		close_session(process, con->session);
		return;
	}

	int ret = _chk_header_recv_complete(con);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] http header not recv completly !", __FILE__, __LINE__, len, HTTP_REQUSET_HEADER_MAX_LENGTH );
		close_session(process, con->session);
		return;
	}

	//TODO: parse header line, header
	memcpy(con->session->http_info->request.head_in, con->buf, HTTP_REQUSET_HEADER_MAX_LENGTH);

	printf("head_in\n%s\n", con->session->http_info->request.head_in);

	ret = http_parse_request_header_line(con->session->http_info->request.head_in, len, &con->session->http_info->request);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] parse request line failed ! fd: %d", __FILE__, __LINE__, con->fd );
		close_session(process, con->session);
		return;
	}

	ret = http_parse_request_header_body(con->session->http_info->request.head_in, len, &con->session->http_info->request);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] parse header line failed ! fd: %d", __FILE__, __LINE__, con->fd );
		close_session(process, con->session);
		return;
	}

	ret = _chk_header_recv_legal( &http_info->request);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] _chk_header_recv_legal failed ! fd: %d", __FILE__, __LINE__, con->fd );
		close_session(process, con->session);
		return;
	}
	
	struct sockaddr_in http_addr;
	ret = _get_http_addr( http_info, &http_addr);
	if (ret<0){
		sys_log(LL_ERROR, "[ %s:%d ] get http host from header failed ! fd: %d", __FILE__, __LINE__, con->fd);
		_send_http_response(process, con, &http_info->proxy_response, http_info->request.proxy_mode);
		close_session(process, con->session);
		return ;
	}

	http_auth(process, con, http_info, &http_info->proxy_response);
	if ( http_info->proxy_response.status != HTTP_AUTH_SUCCESS){
		sys_log(LL_ERROR, "[ %s:%d ] http auth failed ! status: %d", __FILE__, __LINE__, http_info->proxy_response.status);
		_send_http_response(process, con, &http_info->proxy_response, http_info->request.proxy_mode);
		close_session(process, con->session);
		return;
	}

	
	ret = _rewrite_request_header(process, con, http_info);
	if ( ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] rewrite http header failed ! fd : %d", __FILE__, __LINE__, con->fd);
		_send_http_response(process, con, &http_info->proxy_response, http_info->request.proxy_mode);
		close_session(process, con->session);
		return ;
	}
	printf("rewrite\n%s\n", con->buf);

	_do_http_connect( process, con, &http_addr);
	return ;			
}







