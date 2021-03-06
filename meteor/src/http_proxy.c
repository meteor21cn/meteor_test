#include "http_proxy.h"

static int _get_http_addr( socks_worker_process_t *process, http_info_t * http_info, struct sockaddr_in *sin );
static int _conver_domain_to_addr( char * domain, struct sockaddr_in * addr_in);
static int _chk_header_recv_complete(socks_connection_t *con);
static int _chk_header_recv_legal(http_request_t *request);
static int _rewrite_request_header(socks_worker_process_t *process, socks_connection_t *con, http_info_t *http_info);
static void _copy_temp_buf_to_con_buf(socks_connection_t *con, unsigned char *temp_buf);
static void _do_http_connect( socks_worker_process_t *process, socks_connection_t *con,  struct sockaddr_in * addr_in );
static void _generate_x_meteors(http_response_t *response, http_proxy_response_t *proxy_response);

static int _rewrite_request_header(socks_worker_process_t *process, socks_connection_t *con, http_info_t *http_info)
{
	int old_header_len = strlen(http_info->request.head_in);
	unsigned char temp_buf[HTTP_REQUSET_HEADER_MAX_LENGTH];
	memset(temp_buf, 0, HTTP_REQUSET_HEADER_MAX_LENGTH);
	//_clean_recv_buf(con);

	if(http_info->request.proxy_mode == HTTP_PROXY_MODE_FORWORD){
		//forword mode
		//TODO: do some test
		int len = http_info->request.x_meteorq_start - http_info->request.head_in;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] get  x_meteorq_start failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(temp_buf, http_info->request.head_in, len);

		unsigned char x_meteor[512];
		sprintf(x_meteor, "%s %s.%d.%d.%s.%s.%s.",
			HTTP_REQUSET_FIELD_XMETEOR,
			process->config->listen_host, process->config->listen_port,
			http_info->request.auth_mode, con->session->token,
			con->session->app_pname, con->session->passwd);
		memcpy(temp_buf + len, x_meteor, strlen(x_meteor));
		len += strlen(x_meteor);

		memcpy(temp_buf + len , http_info->request.x_meteorq_end + 1, 
			old_header_len - (http_info->request.x_meteorq_end - http_info->request.head_in));

	}
	else if (http_info->request.proxy_mode == HTTP_PROXY_MODE_REVERSE){
		//reverse mode
		unsigned char * header_end = strstr(http_info->request.head_in, CRLFCRLF);
		if (header_end == NULL){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		int len = 0;
		int add_len = 0;
		add_len = http_info->request.host_start - http_info->request.head_in;
		if (add_len<0){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(temp_buf, http_info->request.head_in, add_len);
		len += add_len;

		
		// change HOST: area
		unsigned char* host_pos = http_info->request.header_host_start ;
		unsigned char* host_end = http_info->request.header_host_end + 2;
		if (!host_pos){
			return -1;
		}
		add_len =  host_pos - http_info->request.real_uri_start;
		if (add_len<0 ){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(temp_buf + len, http_info->request.real_uri_start, add_len);
		len += add_len;

		if ( http_info->request.dest_port_end)
			add_len = http_info->request.dest_port_end - http_info->request.dest_host_start + 1;
		else
			add_len = http_info->request.dest_host_end - http_info->request.dest_host_start + 1;
		if (add_len<0 ){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(temp_buf + len, http_info->request.dest_host_start, add_len);
		len += add_len;

		add_len = header_end+2 - host_end;
		if (add_len<0 ){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(temp_buf + len, host_end , add_len);
		len  += add_len;

		unsigned char x_meteor[512];
		sprintf(x_meteor, "%s %s.%d.%d.%s.%s.%s",
			HTTP_REQUSET_FIELD_XMETEOR,
			process->config->listen_host, process->config->listen_port,
			http_info->request.auth_mode, con->session->token,
			con->session->app_pname, con->session->passwd);

		memcpy(temp_buf + len, x_meteor, strlen(x_meteor));
		len += strlen(x_meteor);

		add_len = old_header_len - (header_end -  http_info->request.head_in);
		if (add_len<0){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
			return -1;
		}
		memcpy(temp_buf + len, header_end, add_len);
	}
	_copy_temp_buf_to_con_buf(con, temp_buf);
	return 0;
}

static int _get_http_addr( socks_worker_process_t *process, http_info_t * http_info, struct sockaddr_in *sin )
{
	unsigned char header_addr[256];
	unsigned char header_port[8];
	memset(header_addr, 0, sizeof(header_addr));
	memset(header_port, 0, sizeof(header_port));
	int len;
	
	if (http_info->request.proxy_mode == HTTP_PROXY_MODE_FORWORD ||
		http_info->request.proxy_mode == HTTP_PROXY_MODE_TUNNEL){
		//forword mode
		len = http_info->request.host_end - http_info->request.host_start + 1;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] get  header line addr failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(header_addr, http_info->request.host_start, len);

		len = http_info->request.port_end - http_info->request.port_start + 1;
		if (len > 1){
			memcpy(header_port, http_info->request.port_start, len);
		}
	}
	else if (http_info->request.proxy_mode == HTTP_PROXY_MODE_REVERSE){
		//reverse mode
		len = http_info->request.dest_host_end - http_info->request.dest_host_start + 1;
		if(len <= 0){
			sys_log(LL_ERROR, "[ %s:%d ] get  header line addr failed !", __FILE__, __LINE__);
			return -1;
		}
		memcpy(header_addr, http_info->request.dest_host_start, len);

		len = http_info->request.dest_port_end - http_info->request.dest_port_start + 1;
		if (len >1){
			memcpy(header_port, http_info->request.dest_port_start, len);
		}
	}

	

	socks_addr_t s_addr;
	memset(&s_addr, 0, sizeof(socks_addr_t));
	//unsigned char hostname[host_len + 1];
	memcpy( s_addr.domain, header_addr, strlen(header_addr));

	int port = atoi(header_port);
	if (!port){
		 port = HTTP_DEFINE_PORT;
	}
	sys_log(LL_DEBUG, "[ %s:%d ] http host %s:%d", __FILE__, __LINE__ , s_addr.domain, port);

	sin->sin_port = htons(port);
	//int ret = _conver_domain_to_addr( s_addr.domain, sin);
	int ret = convert_domain_to_ipaddr(process, &s_addr);
	if (ret<0){
		return -1;
	}
	memcpy(&sin->sin_addr, &s_addr.ipv4, sizeof(s_addr.ipv4));
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

static void _copy_temp_buf_to_con_buf(socks_connection_t *con, unsigned char *temp_buf)
{
	int old_header_len =  (strstr(con->buf, CRLFCRLF) - (char*)con->buf )+ 4;
	int len = con->data_length - old_header_len;
	int temp_buf_len = strlen(temp_buf);
	memmove( con->buf + temp_buf_len, con->buf + old_header_len, len);
	memcpy(con->buf, temp_buf, temp_buf_len);
	con->data_length = strlen(con->buf);
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
	
	int ret = connect_http_remote_host_ipv4( process, con ); 
	if( ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] connect remote: %s:%d failed !", __FILE__, __LINE__, remote->peer_hostname, ntohs(remote->peer_host.port));
		con->session->http_info->proxy_response.status = HTTP_CONNECT_ERR;
		send_http_failed_response(process, con, &con->session->http_info->proxy_response, con->session->http_info->request.proxy_mode);
		close_session(process, con->session);
		return;
	}

	return;
}

static void _generate_x_meteors(http_response_t *response, http_proxy_response_t *proxy_response)
{
	unsigned char x_meteors[X_METEORS_LEN];
	sprintf(x_meteors, "%s %d.%d.%ld.%ld.%ld", HTTP_RESPONSE_FIELD_METEORS, 
		proxy_response->status, proxy_response->order_status,
		proxy_response->order_balance, proxy_response->used_today, 
		proxy_response->company_balance);
	memcpy(response->x_meteors, x_meteors, sizeof(x_meteors));
}

int chk_response_legal(http_response_t * response)
{
	if (!response->response_header_content_length_start && !response->response_header_transfer_encoding_start)
		return -1;

	return 0;
}

int chk_response_recv_done(socks_connection_t *con, http_response_t *response, int recv_len)
{
	int ret = chk_response_legal(response);
	//check content-length or transfer encoding
	if (ret < 0)
		return -1;

	if (response->response_header_transfer_encoding_start){
		// transfer-encoding: chunked
		unsigned char *chunked_end = strstr(con->buf + con->sent_length, HTTP_CHUNKED_END);
		if (chunked_end){
			return 1;
		}
	}
	else if(response->response_content_length){
		//content-length
		response->recv_body_length += recv_len;
		if (response->recv_body_length >= response->response_content_length){
			return 1;
		}
	}
	return 0;
}

int chk_request_recv_done(http_request_t *request, int recv_len)
{
	request->recv_body_length += recv_len;
	if (request->recv_body_length >= request->request_content_length)
		return 1;

	return 0;
}

int _chk_header_recv_complete(socks_connection_t *con)
{
	if (strstr(con->buf, CRLF) == NULL)
		return -1;
	if (strstr(con->buf, CRLFCRLF) == NULL)
		return -1;

	return 0;
}

int _chk_header_recv_legal(http_request_t *request)
{
	if (request->http_version != HTTP_VERSION_10 && request->http_version != HTTP_VERSION_11){
		return -1;
	}
	
	if (request->method == MET_HTTP_POST){
		if (!request->header_content_length_start || !request->header_content_length_end)
			return -1;
	}

	if (request->proxy_mode == HTTP_PROXY_MODE_FORWORD){
		//forword mode
		if (request->method == MET_HTTP_CONNECT){
			request->proxy_mode = HTTP_PROXY_MODE_TUNNEL;
			return 0;
		}
		if (!request->x_meteorq_start || !request->x_meteorq_end)
			return -1;
	}

	return 0;
}

int http_parse_header(socks_worker_process_t *process, socks_connection_t * con,
		int recv_len, int is_subrequest)
{
	http_info_t *http_info = con->session->http_info;
	http_info->busy = 1;
	http_request_t *request = &http_info->request;
	request->is_subrequest = is_subrequest;
	request->main = &http_info->request;
	request->parent = &http_info->request;

	if( con->eof ){
		//net disconnected. close session
		sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv http connection, len: %d", __FILE__, __LINE__, recv_len );
		close_session( process, con->session);
		return -1;
	}

	int ret = _chk_header_recv_complete(con);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] http header not recv completly !", __FILE__, __LINE__, recv_len, HTTP_REQUSET_HEADER_MAX_LENGTH );
		close_session(process, con->session);
		return -1;
	}

	if (((strstr(con->buf, CRLFCRLF) - (char*)con->buf) + 4) > HTTP_REQUSET_HEADER_MAX_LENGTH){
		sys_log(LL_ERROR, "[ %s:%d ] http header too long, len: %d, def max: %d", __FILE__, __LINE__, recv_len, HTTP_REQUSET_HEADER_MAX_LENGTH );
		close_session(process, con->session);
		return -1;
	}

	//TODO: parse header line, header
	memcpy(request->head_in, con->buf, ((strstr(con->buf, CRLFCRLF) - (char*)con->buf ) + 4));

	printf("head_in\n%s\n", request->head_in);

	ret = http_parse_request_header_line(request->head_in, recv_len, &http_info->request);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] parse request line failed ! fd: %d", __FILE__, __LINE__, con->fd );
		close_session(process, con->session);
		return -1;
	}

	ret = http_parse_request_header_body(request->head_in, recv_len, request);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] parse header line failed ! fd: %d", __FILE__, __LINE__, con->fd );
		close_session(process, con->session);
		return -1;
	}

	request->recv_body_length = con->data_length - strlen(request->head_in);

	ret = _chk_header_recv_legal( request);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] _chk_header_recv_legal failed ! fd: %d", __FILE__, __LINE__, con->fd );
		close_session(process, con->session);
		return -1;
	}

	http_auth(process, con, http_info, &http_info->proxy_response);
	_generate_x_meteors(&http_info->response, &http_info->proxy_response);
	if ( http_info->proxy_response.status != HTTP_AUTH_SUCCESS){
		sys_log(LL_ERROR, "[ %s:%d ] http auth failed ! status: %d", __FILE__, __LINE__, http_info->proxy_response.status);
		send_http_failed_response(process, con, &http_info->proxy_response,request->proxy_mode);
		close_session(process, con->session);
		return -1;
	}

	if (request->proxy_mode != HTTP_PROXY_MODE_TUNNEL){
		ret = _rewrite_request_header(process, con, http_info);
		if ( ret < 0){
			sys_log(LL_ERROR, "[ %s:%d ] rewrite http header failed ! fd : %d", __FILE__, __LINE__, con->fd);
			send_http_failed_response(process, con, &http_info->proxy_response, request->proxy_mode);
			close_session(process, con->session);
			return -1;
		}
		printf("rewrite\n%s\n", con->buf);
	}

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
	len = _recv_data( con, RECV_BUF_SIZE-con->data_length );
	if( con->eof ){
		//net disconnected. close session
		sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv http header, len: %d", __FILE__, __LINE__, len );
		close_session( process, con->session);
		return;
	}
	
	http_info_t *http_info = (http_info_t *)malloc(sizeof(http_info_t));
	memset(http_info, 0, sizeof(http_info_t));
	con->session->http_info = http_info;
	//TODO: check if header recv complted
	/*char *test_buf ="GET http://172.18.12.1s/meteorq.0.0.1.001|888|b29adac2bdc027497fa3a327d8566326/www.baidu.com HTTP/1.1\r\n"
			"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\n"
			"Proxy-Connection: keep-alive\r\n"
			"Host: 172.18.12.1\r\n"
			"Content-Length: 33\r\n"
			"Connection: keep-alive\r\n\r\n"
			"666666666666666666666666666666666";*/
	/*char *test_buf ="GET http://www.baidu.com HTTP/1.1\r\n"
			"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\n"
			"Proxy-Connection: keep-alive\r\n"
			"Host: www.baidu.com\r\n"
			"Connection: keep-alive\r\n"
			"X-Meteorq: 1.001|888|b29adac2bdc027497fa3a327d8566326\r\n\r\n";*/
	/*char *test_buf = "CONNECT www.baidu.com:443 HTTP/1.1\r\n"
			"User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\n"
			"Proxy-Connection: keep-alive\r\n"
			"Connection: keep-alive\r\n"
			"Host: www.baidu.com:443\r\n"
			"X-Meteorq: 1.001|888|e57162bca28edd1f7a7178a5de4f457f\r\n\r\n";*/

	/*len = strlen(test_buf);
	_clean_recv_buf(con);
	strcpy(con->buf, test_buf);
	con->data_length = len;*/
	int ret = http_parse_header(process, con, len, 1);
	if (ret < 0){
		sys_log(LL_ERROR, "[ %s:%d ] http_parse_header failed ! fd : %d", __FILE__, __LINE__, con->fd);
		return ;
	}

	struct sockaddr_in http_addr;
	ret = _get_http_addr( process, http_info, &http_addr);
	if (ret<0){
		sys_log(LL_ERROR, "[ %s:%d ] get http host from header failed ! fd: %d", __FILE__, __LINE__, con->fd);
		close_session(process, con->session);
		return;
	}

	http_info->request.request_done  = chk_request_recv_done(&http_info->request, 0);

	_do_http_connect( process, con, &http_addr);

	return ;			
}