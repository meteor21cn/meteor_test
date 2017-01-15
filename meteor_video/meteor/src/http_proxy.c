#include "http_proxy.h"

static int _get_http_addr( socks_worker_process_t *process, http_info_t * http_info, struct sockaddr_in *sin );
static int _conver_domain_to_addr( char * domain, struct sockaddr_in * addr_in);
static int _chk_header_recv_complete(socks_connection_t *con);
static int _chk_header_recv_legal(http_request_t *request);
static int _rewrite_request_header(socks_worker_process_t *process, socks_connection_t *con, http_info_t *http_info);
static int _rewrite_proxy_connection( unsigned char *buf, int buf_len );
static int  _find_chunked_end(unsigned char *buf, int sent_length, int data_length);
static void _copy_temp_buf_to_con_buf(socks_connection_t *con, unsigned char *temp_buf);
static void _do_http_connect( socks_worker_process_t *process, socks_connection_t *con,  struct sockaddr_in * addr_in );
static void _generate_x_meteors(http_response_t *response, mtr_auth_reply_t *reply);
static void _reset_remote_connection(socks_worker_process_t *process, socks_connection_t *remote);

static int _rewrite_request_header(socks_worker_process_t *process, socks_connection_t *con, http_info_t *http_info)
{
    http_request_t *request = &http_info->request;
    int old_header_len = strlen(request->head_in);
    int len = 0;
    int add_len = 0;
    unsigned char temp_buf[HTTP_REQUSET_HEADER_MAX_LENGTH];
    memset(temp_buf, 0, HTTP_REQUSET_HEADER_MAX_LENGTH);
    unsigned char x_meteor[512];
    sprintf(x_meteor, "%s %s.%d.%d.%s.%s.%s",
        HTTP_REQUSET_FIELD_XMETEOR,
        process->config->listen_host, process->config->listen_port,
        request->auth_mode, con->session->token,
        con->session->app_pname, con->session->passwd);
    //_clean_recv_buf(con);

    if(request->proxy_mode == HTTP_PROXY_MODE_FORWORD){
        //正向代理修改uri，由于不需要修改Host，对http1.0 1.1 版本不做区分，
        if(request->host_start ){
            //request lines have original-host 
            //request method
            add_len = request->method_end - request->method_start + 2;
            if (add_len <= 2){
                sys_log(LL_ERROR, "[ %s:%d ] get  request method failed !", __FILE__, __LINE__);
                return -1;
            }
            memcpy(temp_buf + len, request->head_in, add_len);
            len += add_len;

            if( request->port_start){
                if (*(request->port_end +1) == ' '){
                    //top dir
                    memcpy(temp_buf + len, "/", 1);
                    len += 1;
                }

                add_len = request->x_meteorq_start - request->port_end;
                if(add_len <= 0){
                    sys_log(LL_ERROR, "[ %s:%d ] get  x_meteorq_start failed !", __FILE__, __LINE__);
                    return -1;
                }
                memcpy(temp_buf + len, request->port_end+1, add_len);
            }
            else{
                if (*(request->host_end +1) == ' '){
                    //top dir
                    memcpy(temp_buf + len, "/", 1);
                    len += 1;
                }
                add_len = request->x_meteorq_start - request->host_end - 1;
                if(add_len <= 0){
                    sys_log(LL_ERROR, "[ %s:%d ] get  x_meteorq_start failed !", __FILE__, __LINE__);
                    return -1;
                }
                memcpy(temp_buf + len, request->host_end+1, add_len);
            }
            len += add_len;
        }
        else{
            //request lines have no original-host 
            add_len = request->x_meteorq_start - request->head_in;
            if(add_len <= 0){
                sys_log(LL_ERROR, "[ %s:%d ] get  x_meteorq_start failed !", __FILE__, __LINE__);
                return -1;
            }
            memcpy(temp_buf + len, request->head_in, add_len);
            len += add_len;
        }

        add_len = strlen(x_meteor);
        memcpy(temp_buf + len, x_meteor, add_len);
        len += add_len;

        memcpy(temp_buf + len , request->x_meteorq_end + 1, 
            old_header_len - (request->x_meteorq_end - request->head_in));

    }
    else if (request->proxy_mode == HTTP_PROXY_MODE_REVERSE){
        //反向代理需要对Host属性，uri进行修改，但http1.0版本可以没有Host，需要进行区分
        unsigned char * header_end = strstr(request->head_in, CRLFCRLF);
        if (header_end == NULL){
            sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
            return -1;
        }

        //request method
        add_len = request->method_end - request->method_start + 2;
        if (add_len <= 2){
            sys_log(LL_ERROR, "[ %s:%d ] get  request method failed !", __FILE__, __LINE__);
            return -1;
        }
        memcpy(temp_buf + len, request->head_in, add_len);
        len += add_len;

        if (request->header_host_start){
            //request resourse:
            if ( request->dest_port_end){
                if (*(request->dest_port_end +1) == ' '){
                    //top dir
                    memcpy(temp_buf + len, "/", 1);
                    len += 1;
                }
                add_len = request->header_host_start - request->dest_port_end -1;
                if (add_len<0 ){
                    sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
                    return -1;
                }
                memcpy(temp_buf + len, request->dest_port_end + 1, add_len);
            }
            else{
                if (*(request->dest_host_end +1)  == ' '){
                    //top dir
                    memcpy(temp_buf + len, " /", 2);
                    len += 2;
                }
                
                add_len = request->header_host_start - request->dest_host_end - 1;
                if (add_len<0 ){
                    sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
                    return -1;
                }
                memcpy(temp_buf + len, request->dest_host_end + 1, add_len);
            }   
            len += add_len;

            // change HOST: area
            if ( request->dest_port_end)
                add_len = request->dest_port_end - request->dest_host_start + 1;
            else
                add_len = request->dest_host_end - request->dest_host_start + 1;
            if (add_len<= 1 ){
                sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
                return -1;
            }
            memcpy(temp_buf + len, request->dest_host_start, add_len);
            len += add_len;

            //header HOST end to end
            if (request->header_port_end){
                add_len = header_end - request->header_port_end +1;
                if (add_len <= 1 ){
                    sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
                    return -1;
                }
                memcpy(temp_buf + len, request->header_port_end + 1, add_len);
            }
            else{
                add_len = header_end - request->header_host_end +1;
                if (add_len <= 1){
                    sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
                    return -1;
                }
                memcpy(temp_buf + len, request->header_host_end + 1, add_len);
            }
            len  += add_len;
        }
        else if (request->http_version == HTTP_VERSION_10){
            //request resourse
            if ( request->dest_port_end){
                if (*(request->dest_port_end +1) == ' '){
                    //top dir
                    memcpy(temp_buf + len, "/", 1);
                    len += 1;
                }
                add_len = header_end - request->dest_port_end -1;
                if (add_len<0 ){
                    sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
                    return -1;
                }
                memcpy(temp_buf + len, request->dest_port_end + 1, add_len);
            }
            else{
                if (*(request->dest_host_end +1)  == ' '){
                    //top dir
                    memcpy(temp_buf + len, " /", 2);
                    len += 2;
                }
                
                add_len = header_end - request->dest_host_end - 1;
                if (add_len<0 ){
                    sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
                    return -1;
                }
                memcpy(temp_buf + len, request->dest_host_end + 1, add_len);
            }   
            len += add_len;
        }
        else{
            sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
            return -1;
        }

        memcpy(temp_buf + len, x_meteor, strlen(x_meteor));
        len += strlen(x_meteor);

        add_len = old_header_len - (header_end -  request->head_in);
        if (add_len <= 0){
            sys_log(LL_ERROR, "[ %s:%d ] rewrite request header failed ! fd: %d", __FILE__, __LINE__, con->fd);
            return -1;
        }
        memcpy(temp_buf + len, header_end, add_len);
    }

    _rewrite_proxy_connection(temp_buf, HTTP_REQUSET_HEADER_MAX_LENGTH);
    _copy_temp_buf_to_con_buf(con, temp_buf);
    return 0;
}

static int _rewrite_proxy_connection( unsigned char *buf , int buf_len)
{
    unsigned char *pos = strstr(buf, HTTP_REQUSET_FIELD_PROXY_CONNECTION);
    if (pos){
        //has Proxy-Connection
        int old_header_len = strlen(buf);
        int index_len = strlen("Proxy-");
        int len = old_header_len - (pos - buf) -  index_len;
        memmove(pos, pos + index_len, len);
        memset(buf + old_header_len - index_len, 0, buf_len - old_header_len + index_len);
    }
}

static int _get_http_addr( socks_worker_process_t *process, http_info_t * http_info, struct sockaddr_in *sin )
{
    http_request_t *request = &http_info->request;
    unsigned char header_addr[128];
    unsigned char header_port[8];
    memset(header_addr, 0, sizeof(header_addr));
    memset(header_port, 0, sizeof(header_port));
    int len;
    
    if (request->proxy_mode == HTTP_PROXY_MODE_FORWORD ||
        request->proxy_mode == HTTP_PROXY_MODE_TUNNEL){
        //forword mode, tunnel mode, get addr from "Host:"
        len = request->header_host_end - request->header_host_start + 1;
        if(len <= 1){
            if (request->http_version == HTTP_VERSION_10){
                //http1.0 try request line
                len = request->host_end - request->host_start + 1;
                if (len <= 1){
                    sys_log(LL_ERROR, "[ %s:%d ] get  header  addr failed !", __FILE__, __LINE__);
                    return -1;
                }
                else{
                    memcpy(header_addr, request->host_start, len);
                }
            }
            else{
                sys_log(LL_ERROR, "[ %s:%d ] get  header  addr failed !", __FILE__, __LINE__);
                return -1;
            }
        }
        else{
            memcpy(header_addr, request->header_host_start, len);
        }

        if(request->header_host_start){
            //has "Host:"
            len = request->header_port_end - request->header_port_start + 1;
            if (len >1){
                memcpy(header_port, request->header_port_start, len);
            }
        }
        else{
            if (request->http_version == HTTP_VERSION_10){
                len = request->port_end - request->port_start + 1;
                if (len >1){
                    memcpy(header_port, request->port_start, len);
                }
            }
        }
        
    }
    else if (request->proxy_mode == HTTP_PROXY_MODE_REVERSE){
        //reverse mode
        len = request->dest_host_end - request->dest_host_start + 1;
        if(len <= 0){
            sys_log(LL_ERROR, "[ %s:%d ] get  header  addr failed !", __FILE__, __LINE__);
            return -1;
        }
        memcpy(header_addr, request->dest_host_start, len);

        len = request->dest_port_end - request->dest_port_start + 1;
        if (len >1){
            memcpy(header_port, request->dest_port_start, len);
        }
    }

    if (strstr(http_info->pre_host, header_addr) == NULL)
        http_info->redirect = 1;
    

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

static int  _find_chunked_end(unsigned char *buf, int sent_length, int data_length)
{
    unsigned char *chunked_end_sign = HTTP_CHUNKED_END;
    unsigned char *str = buf + sent_length;
    int chunked_end_sign_len = strlen(chunked_end_sign);
    int find_len = data_length - sent_length - chunked_end_sign_len + 2;
    int i;
    for (i = 0; i < find_len; i++){
        if ( str[i] == chunked_end_sign[0] ){
            if(strstr(&str[i], chunked_end_sign) != NULL)
                return 1;
        }
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
    memset(con->buf+len+temp_buf_len, 0, RECV_BUF_SIZE - len -temp_buf_len);
    con->data_length = strlen(con->buf);
}

static void _do_http_connect( socks_worker_process_t *process, socks_connection_t *con,  struct sockaddr_in * addr_in )
{
    socks_connection_t *remote;
    int stage;
    if (!con->session->remote){
        stage = HTTP_STAGE_CONNECT;
        remote = (socks_connection_t *)malloc(sizeof(socks_connection_t));
        if( remote == NULL ){
            sys_log(LL_ERROR, "[ %s:%d ] malloc remote error,fd: %d", __FILE__, __LINE__, con->fd );
            close_session( process, con->session);
            return;
        }

    }
    else{
        stage = HTTP_STAGE_RECONNECT;
        remote = con->session->remote;
        _reset_remote_connection(process, remote );
    }

    memset( (void *)remote, 0, sizeof(socks_connection_t) );
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
    
    int ret = connect_http_remote_host_ipv4( process, con , stage); 
    if( ret < 0){
        sys_log(LL_ERROR, "[ %s:%d ] connect remote: %s:%d failed !", __FILE__, __LINE__, remote->peer_hostname, ntohs(remote->peer_host.port));
        con->session->http_info->reply.status = HTTP_CONNECT_ERR;
        send_http_failed_response(process, con, &con->session->http_info->reply, con->session->http_info->request.proxy_mode);
        close_session(process, con->session);
        return;
    }

    return;
}

static void _generate_x_meteors(http_response_t *response, mtr_auth_reply_t *reply)
{
    unsigned char x_meteors[X_METEORS_LEN];
    sprintf(x_meteors, "%s %x.%d.%ld.%ld.%ld", HTTP_RESPONSE_FIELD_METEORS, 
        reply->status, reply->order_status,
        reply->order_balance, reply->used_today, 
        reply->company_balance);
    memcpy(response->x_meteors, x_meteors, sizeof(x_meteors));
}

static void _reset_remote_connection(socks_worker_process_t *process, socks_connection_t *remote)
{
    if( remote->closed)
        return;

    remote->closed = 1;

    struct epoll_event epv = {0, {0}};
    epv.data.ptr = remote;    

    int op = EPOLL_CTL_DEL;
    if( epoll_ctl(  process->epoll_fd, op, remote->fd, &epv) < 0)
        sys_log(LL_ERROR, "[ %s:%d ] epoll del failed, fd:%d", __FILE__, __LINE__, remote->fd );    
    //else  
        //sys_log(LL_DEBUG, "[ %s:%d ] epoll del ok, fd:%d", __FILE__, __LINE__, remote->fd );    
    sys_log(LL_DEBUG, "[ %s:%d ] connect closed, fd:%d, peer: %s:%d", __FILE__, __LINE__, remote->fd, remote->peer_hostname, ntohs(remote->peer_host.port) );
    if( remote->fd > 0 ){
        if( 0 )
        {
            struct linger ling = {0, 0};
            if( setsockopt( remote->fd, SOL_SOCKET, SO_LINGER, (void*)&ling, sizeof(ling) ) == -1 )
            {
                sys_log(LL_ERROR, "[ %s:%d ] setsockopt(linger) failed, fd:%d, %s", __FILE__, __LINE__, remote->fd, strerror(errno));   
            }
        }
        if( close(remote->fd ) < 0 ){
            sys_log(LL_ERROR, "[ %s:%d ] close socket failed, fd:%d, %s", __FILE__, __LINE__, remote->fd, strerror(errno) );   
        }
        else
            remote->fd = 0;
    }

    memset(remote, 0 , sizeof(socks_connection_t));
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

    if (!response->response_done){
        if (response->response_header_transfer_encoding_start){
            // transfer-encoding: chunked
            int ret = _find_chunked_end(con->buf + con->sent_length, con->sent_length, con->data_length);
            if ( ret ) {
                return 1;
            }
        }
        else if(response->response_content_length){
            //content-length
            response->recv_body_length += recv_len;
            sys_log(LL_DEBUG,"[ %s:%d ]content len:%d  sent_length:%d\n",__FILE__, __LINE__,
                 response->response_content_length, response->recv_body_length);
            if (response->recv_body_length >= response->response_content_length){
                return 1;
            }
        }
        return 0;
    }

    return response->response_done;
    
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

    if (request->http_version == HTTP_VERSION_11){
        if (!request->header_host_start )
            return -1;
    }

    if (request->http_version == HTTP_VERSION_10){
        if (request->proxy_mode == HTTP_PROXY_MODE_FORWORD)
            if(!request->header_host_start && !request->host_start)
                return -1;
        else if(request->proxy_mode == HTTP_PROXY_MODE_REVERSE)
            if(!request->header_host_start && !request->dest_host_start)
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
    memcpy(request->head_in, con->buf, (strstr(con->buf, CRLFCRLF) - (char*)con->buf) + 4);

    printf("head_in\n%s\n", request->head_in);

    ret = http_parse_request_line(request->head_in, recv_len, &http_info->request);
    if (ret < 0){
        sys_log(LL_ERROR, "[ %s:%d ] parse request line failed ! fd: %d", __FILE__, __LINE__, con->fd );
        close_session(process, con->session);
        return -1;
    }

    ret = http_parse_request_header_body(request->head_in, recv_len, request);
    if (ret < 0){
        sys_log(LL_ERROR, "[ %s:%d ] parse header body failed ! fd: %d", __FILE__, __LINE__, con->fd );
        close_session(process, con->session);
        return -1;
    }

    request->recv_body_length = con->data_length - strlen(request->head_in);

    /*if (strstr(request->head_in, "CONNECT"))
        request->proxy_mode = HTTP_PROXY_MODE_TUNNEL;*/

    ret = _chk_header_recv_legal( request);
    if (ret < 0){
        sys_log(LL_ERROR, "[ %s:%d ] _chk_header_recv_legal failed ! fd: %d", __FILE__, __LINE__, con->fd );
        close_session(process, con->session);
        return -1;
    }

    http_auth(process, con, http_info, &http_info->reply);
    _generate_x_meteors(&http_info->response, &http_info->reply);
    if ( http_info->reply.status != MTR_ORDER_AUTH_SUCCESS){
        sys_log(LL_ERROR, "[ %s:%d ] http auth failed ! status: %d", __FILE__, __LINE__, http_info->reply.status);
        send_http_failed_response(process, con, &http_info->reply,request->proxy_mode);
        close_session(process, con->session);
        return -1;
    }

    if (request->proxy_mode != HTTP_PROXY_MODE_TUNNEL){
        ret = _rewrite_request_header(process, con, http_info);
        if ( ret < 0){
            sys_log(LL_ERROR, "[ %s:%d ] rewrite http header failed ! fd : %d", __FILE__, __LINE__, con->fd);
            send_http_failed_response(process, con, &http_info->reply, request->proxy_mode);
            close_session(process, con->session);
            return -1;
        }
        printf("rewrite\n%s\n", con->buf);
    }

    http_info->request.request_done  = chk_request_recv_done(&http_info->request, 0);

    struct sockaddr_in http_addr;
    ret = _get_http_addr( process, http_info, &http_addr);
    if (ret<0){
        sys_log(LL_ERROR, "[ %s:%d ] get http host from header failed ! fd: %d", __FILE__, __LINE__, con->fd);
        close_session(process, con->session);
        return;
    }

    if (http_info->redirect){
        //printf("need redirect\n");
        _do_http_connect( process, con, &http_addr);
        http_info->redirect = 0;
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

    if ( http_info == NULL ) {
        sys_log(LL_ERROR, "[ %s:%d ] malloc http_info error,fd: %d", __FILE__, __LINE__, con->fd );
        close_session( process, con->session);
        return;
    }
    memset(http_info, 0, sizeof(http_info_t));
    con->session->http_info = http_info;

    //temp deal
/*  HTML
    http_info->htmlparser_ctx_ext.ctx = htmlparser_new(); // TODO: new() fail
*/
    con->session->protocol = HTTP_PROTOCOL;
    //TODO: check if header recv complted
    /*char *test_buf ="GET http://172.18.12.1:1080/meteorq|0|0|1|001|888|b29adac2bdc027497fa3a327d8566326/www.baidu.com/index.html HTTP/1.1\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "Host: 172.18.12.1:1080\r\n"
            "Connection: keep-alive\r\n\r\n"
            "666666666666666666666";*/
    /*char *test_buf ="GET /include HTTP/1.1\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "Host: www.baidu.com:80\r\n"
            "Connection: keep-alive\r\n"
            "X-Meteorq: 1|001|888|b29adac2bdc027497fa3a327d8566326\r\n\r\n";*/
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

    return ;
}
