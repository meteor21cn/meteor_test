#include "http_transform.h"

static int _copy_remote_data_to_rewrite_buf(socks_worker_process_t *process,socks_connection_t *con, http_response_t * response);
static int _send_rewrite_buf_data( socks_connection_t * con ,http_response_t * response, int send_fd );
static int _send_http_request( socks_worker_process_t *process, socks_connection_t * client, socks_connection_t *remote);
static void _clean_rewrite_buf( http_response_t *response );
static void _http_client_data_transform_cb(  socks_worker_process_t *process, int fd, int events, void *arg);
static void _http_remote_data_transform_cb(  socks_worker_process_t *process, int fd, int events, void *arg);
static void _connect_http_remote_host_complete_cb(  socks_worker_process_t *process, int remote_fd, int events, void *arg);


static int _copy_remote_data_to_rewrite_buf(socks_worker_process_t *process, socks_connection_t *con, http_response_t * response)
{
	int recv_len = con->data_length - con->sent_length;
	int will_read = HTTP_REWRITE_BUF_SIZE - response->data_length;
	http_request_t *request = &con->session->http_info->request;
	if ( !response->header_done ) //deal with 
	{
		if (!response->response_header_end)
			response->response_header_end = strstr(con->buf + con->sent_length,CRLFCRLF);

		if ( response->response_header_end == NULL )
		{
			will_read = 0;
		}
		else
		{
			if (!response->response_header_parsed)
			{
				int ret = http_parse_response_header_line(con->buf + con->sent_length, 
				con->data_length - con->sent_length, response);
				if (ret < 0){
					sys_log(LL_ERROR,  "[ %s:%d ] http_parse_response_header_line failed ! fd: %d", __FILE__, __LINE__, con->fd);
					return -1;
				}

				ret = http_parse_response_header_body(con->buf + con->sent_length, response);
				if (ret < 0){
					sys_log(LL_ERROR,  "[ %s:%d ] http_parse_response_header_line failed ! fd: %d", __FILE__, __LINE__, con->fd);
					return -1;
				}
				response->response_header_parsed = 1;
			}

			int len = response->response_header_end - (con->buf + con->sent_length);
			if( len  <= will_read)
			{
				will_read = len;
			}
		}

		if (will_read >0)
		{
			memcpy(response->rewrite_buf + response->data_length, con->buf + con->sent_length, will_read);
			response->data_length += will_read;
			con->sent_length += will_read;
		}

		if (con->buf +con->sent_length == response->response_header_end)
		{
			will_read = HTTP_REWRITE_BUF_SIZE - response->data_length;
			int len = strlen(response->x_meteors) + 2 + 4; //x_meteor + CRLF + CRLFCRLF
			if (len <= will_read)
			{
				memcpy(response->rewrite_buf + response->data_length,&CRLF, 2);
				memcpy(response->rewrite_buf + response->data_length + 2, response->x_meteors, strlen(response->x_meteors));
				memcpy(response->rewrite_buf + response->data_length + 2 + strlen(response->x_meteors), &CRLFCRLF, 4);
				response->data_length += len;
				con->sent_length += 4;
				response->header_done = 1;
			}
		}

	}
	else if( request->domain_flag != 0 && request->at_flag != 0 && response->content_type ==  CONTENT_TYPE_M3U8)//header_done 
	{
		int ret = rewrite_url_in_file(process,con,response);
		if (ret < 0 )
			return -1; //error
	}
	else
	{
		if( recv_len < will_read)
			will_read = recv_len;
		memcpy(response->rewrite_buf + response->data_length, con->buf + con->sent_length, will_read);
		response->data_length += will_read;
		con->sent_length += will_read;
	}

	if ( con->data_length == con->sent_length && con->data_length > 0)
	{
		_clean_recv_buf(con);
	}
	else if (con->data_length == RECV_BUF_SIZE)
	{
		int len = con->data_length - con->sent_length;
		if ( !response->header_done )
			response->response_header_end -= con->data_length;
		memmove(con->buf,con->buf + con->sent_length,len);
		con->sent_length = 0;
		con->data_length = len;
		memset(con->buf + con->data_length, 0, RECV_BUF_SIZE- len);
	}


	/*int recv_len = con->data_length - con->sent_length;
	int will_read = HTTP_REWRITE_BUF_SIZE - response->data_length;
	if( recv_len < will_read)
		will_read = recv_len;
	memcpy(response->rewrite_buf + response->data_length, con->buf + con->sent_length, will_read);
	response->data_length += will_read;
	con->sent_length += will_read;
	if ( con->data_length == con->sent_length && con->data_length > 0)
	{
		_clean_recv_buf(con);
	}*/
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
				_copy_remote_data_to_rewrite_buf(process,peer, &peer->session->http_info->response);
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
		_copy_remote_data_to_rewrite_buf(process,con, &con->session->http_info->response);

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
			send_http_response(process, remote, &remote->session->http_info->proxy_response, remote->session->http_info->request.proxy_mode);
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

int send_http_response(socks_worker_process_t *process, socks_connection_t *con, http_proxy_response_t *proxy_response, int proxy_mode)
{
	http_info_t * http_info = con->session->http_info;
	unsigned char response_buf[512];
	unsigned char str_time[64] = {0};
	unsigned char http_version[16];
	int send_length;
	long now = time(NULL);
	struct tm *ptime = localtime( &now );
	strftime(str_time, sizeof(str_time), "%c", ptime);

	switch ( http_info->request.http_version){
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
		len = http_info->request.uri_end - http_info->request.uri_start + 1;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] send_http_response get  header line uri failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(pos, http_info->request.uri_start, len);
		sprintf(response_buf, "%s %s %s\r\n%s %s\r\n%s %s:%d\r\n%s\r\n\r\n",
			http_version, HTTP_CODE_UNAUTHORIZED, HTTP_TEXT_UNAUTHORIZED,
			HTTP_RESPONSE_FIELD_TIME, str_time,
			HTTP_RESPONSE_FIELD_SERVER, process->config->listen_host,  process->config->listen_port,
			http_info->response.x_meteors);
	}
	else{
		//reverse mode
		len = http_info->request.host_start - http_info->request.uri_start;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] send_http_response get  header line uri failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(pos, http_info->request.uri_start, len);
		pos += len;

		len = http_info->request.real_uri_end - http_info->request.real_uri_start + 1;
		if(len <= 1){
			sys_log(LL_ERROR, "[ %s:%d ] send_http_response get  header line uri failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(pos, http_info->request.real_uri_start, len);
		sprintf(response_buf, "%s %s %s\r\n%s %s\r\n%s %s:%d\r\n%s %s\r\n%s\r\n\r\n",
			http_version, HTTP_CODE_MOVE_TEMPORARY, HTTP_TEXT_MOVE_TEMPORARY,
			HTTP_RESPONSE_FIELD_TIME, str_time,
			HTTP_RESPONSE_FIELD_SERVER, process->config->listen_host, process->config->listen_port,
			HTTP_RESPONSE_FIELD_LOCATION, uri,
			http_info->response.x_meteors);
	}

	memset(con->buf, 0, RECV_BUF_SIZE);
	memcpy(con->buf, response_buf, sizeof(response_buf));
	send_length = sizeof(response_buf);
	printf("response\n%s\n", con->buf);
	
	
	len = _send_data_until_length( con, con->fd, send_length );
	if(len <= 0 )	
	{  
		sys_log(LL_ERROR, "[ %s:%d ] cmd status:0x%2x send failed, fd:%d", __FILE__, __LINE__, proxy_response->status, con->fd );
		close_session( process, con->session);
	}
	else
		do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 0, 0 );
	return 0;
}

int connect_http_remote_host_ipv4(socks_worker_process_t *process, socks_connection_t *con )
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