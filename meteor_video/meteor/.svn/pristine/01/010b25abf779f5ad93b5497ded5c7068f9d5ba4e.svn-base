//     
// meteor server(socks5 flow gateway) using epoll in linux    
//     
// by jimmy zhou    
//  

#include "meteor.h"
#include "sockd.h"
#include "order.h"
#include "log.h"
#include "meteor_auth.h"
#include "sockd_auth.h"
#include "http_auth.h"
#include "sockd_redis.h"
#include "sockd_tcp.h"
#include "sockd_udp.h"
#include "sockd_rbtree.h"
#include "meteor_process.h"
#include "http_proxy.h"

#include <streamhtmlparser/htmlparser.h> // htmlparser_delete()



long domain_delete_stamp = 0; 
static sigjmp_buf jmpbuf;
static sig_atomic_t canjump;

extern sig_atomic_t  to_terminate;
extern sig_atomic_t  to_quit;
extern unsigned int status_exiting;

void tcl_sig_alrm(int signo)
{
    if(!canjump)
    {
        return ;
    }
    siglongjmp(jmpbuf, 1);
}

int get_udp_listen( socks_worker_process_t *process, socks_udp_listen_t * udp_listen)
{
    if (process->udp_listen_fd_num == 0)
        return -1;

    udp_listen->fd = process->udp_listen[process->udp_listen_fd_pos].fd;
    udp_listen->port = process->udp_listen[process->udp_listen_fd_pos].port;
    process->udp_listen_fd_pos++;
    if (process->udp_listen_fd_pos == process->udp_listen_fd_num){
        process->udp_listen_fd_pos = 0;
    }

    return 0;
}

int is_fd_in_udp_listen_fd(socks_worker_process_t *process, int fd)
{
    int i;
    for ( i = 0; i < process->udp_listen_fd_num; i++){
        if (fd == process->udp_listen[i].fd)
            return 1;
    }

    return 0;
}

int _add_to_domain_cache( socks_worker_process_t *process, socks_domain_t *domain )
{
    rb_node_t *node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for domain_cache rb_node, domain:%s", __FILE__, __LINE__, domain->domain);
        return -1;
    }
    node->key.pkey = domain->domain;
    node->data = (void *)domain;
    if( rb_tree_insert_node( &process->domain_cache, node, 0 )<0 )
        rb_list_add( &process->rb_node_pool, node );
    return 0;
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

socks_host_t *convert_to_socks_host_t( socks_host_t *host, struct sockaddr_in *addr)
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

int convert_domain_to_ipaddr(socks_worker_process_t *process, socks_addr_t *addr)
{
    char ipstr[128];
    socks_domain_t *domain = NULL;

    rb_node_t *node;
    rb_key_t key;
    key.pkey = addr->domain;
    node = rb_tree_search(&process->domain_cache, &key);
    if(node != NULL)
    {
        socks_domain_t *domain_remote = (socks_domain_t*)node->data;
        srand(time(NULL));
        int tmp = rand()%domain_remote->size;
        addr->ipv4.s_addr = domain_remote->ip_addr[tmp].ipv4.s_addr;
        sys_log(LL_DEBUG, "[ %s:%d ] domain of %s has existed in cache", __FILE__, __LINE__,domain_remote->domain);
        return 1;
    }

    domain = domain_pool_pop( process );
    if( !domain ){
        return 0;
    }

    int pool = domain->pool;
    memset( domain, 0, sizeof(domain) );
    domain->pool = pool;
    strncpy(domain->domain, addr->domain, strlen(addr->domain));
    domain->domain[strlen(addr->domain)] = '\0';
    domain->size = 0;

    struct addrinfo *result, hint, *res;
    bzero(&hint, sizeof(hint));
    hint.ai_family = PF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;

    signal(SIGALRM, tcl_sig_alrm);
    if(sigsetjmp(jmpbuf, 1))
    {
        sys_log(LL_DEBUG, "[ %s:%d ]  domain of %s has timeout", __FILE__, __LINE__, addr->domain);
        return -1;
    }

    canjump = 1;
    alarm(1);

    int ret = getaddrinfo(addr->domain, NULL, &hint, &result);
    canjump = 0;
    if(ret == 0)
    {
        for(res = result; res != NULL; res = res->ai_next)
        {
            switch(res->ai_family){
                case AF_INET:
                    inet_ntop(AF_INET,&(((struct sockaddr_in *)(res->ai_addr))->sin_addr),ipstr, 16);
                    domain->ip_addr[domain->size++].ipv4.s_addr = inet_addr(ipstr);
                    break;
                case AF_INET6:
                default:
                    sys_log(LL_ERROR, "[ %s:%d ] the type of domain %s can't be recognize", __FILE__, __LINE__, domain->domain);
                    break;
            }

            if(domain->size >= 10)
                    break;
        }

        if(domain_delete_stamp == 0)
        {
            time_t now = time(NULL);
            domain_delete_stamp = (long)now;
        }

        //choice host ip address in random
        srand(time(NULL));
        int tmp = rand()%domain->size;
        addr->ipv4.s_addr = domain->ip_addr[tmp].ipv4.s_addr;
        sys_log(LL_DEBUG, "[ %s:%d ] domain of %s has resolved to %s", __FILE__, __LINE__, domain->domain, inet_ntoa(addr->ipv4));

        if( _add_to_domain_cache( process, domain ) <0 ){
            domain_pool_add( process, domain);
        }

        freeaddrinfo(result);
        return 1;
    }
    else if(ret != 0)
    {
        sys_log(LL_DEBUG, "[ %s:%d ] domain of %s resolve failed", __FILE__, __LINE__, domain);
        return -1;
    }
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

unsigned char * copy_buf_to_socks_host(socks_host_t *host, unsigned char *buf )
{
    memcpy(&host->atype, buf, sizeof(host->atype));
    buf += sizeof(host->atype);
    
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


// set event    
void _register_session_event(int epoll_fd, socks_connection_t *con, int fd, int events, 
            void (*call_back)(socks_worker_process_t *,int, int, void*))    
{    
    struct epoll_event epv = {0, {0}};
    epv.data.ptr = con;    
    epv.events = events;  
    
    con->fd = fd;    
    con->call_back = call_back;    

    int op = EPOLL_CTL_ADD;
    if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
        sys_log(LL_ERROR, "[ %s:%d ] epoll add failed, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
    //else  
    //  sys_log(LL_DEBUG, "[ %s:%d ] epoll add ok, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);  
} 

// set listen event
static void _register_listen_event(int epoll_fd, int fd, int events)    
{    
    struct epoll_event epv = {0, {0}};
    epv.data.fd = fd;  
    epv.events = events;  
    
    int op = EPOLL_CTL_ADD;
    if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
        sys_log(LL_ERROR, "[ %s:%d ] epoll listen failed, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
    //else  
        //sys_log(LL_DEBUG, "[ %s:%d ] epoll listen ok, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events); 
} 


void _change_session_event(int epoll_fd, socks_connection_t *con, int fd, int events, 
        void (*call_back)(socks_worker_process_t *,int, int, void*))    
{    
    struct epoll_event epv = {0, {0}};
    epv.data.ptr = con;    
    epv.events = events;  
    
    con->fd = fd;    
    con->call_back = call_back;    

    int op = EPOLL_CTL_MOD;
    if(epoll_ctl(epoll_fd, op, fd, &epv) < 0)    
        sys_log(LL_ERROR, "[ %s:%d ] epoll change failed, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
    //else    
        //sys_log(LL_DEBUG, "[ %s:%d ] epoll change ok, fd:%d, evnets:%d", __FILE__, __LINE__, fd, events);    
} 

static void _close_listen_socket( socks_worker_process_t *process )
{

    if( process->listen_fd == 0)
        return;

    struct epoll_event epv = {0, {0}};

    int op = EPOLL_CTL_DEL;
    if( epoll_ctl( process->epoll_fd, op, process->listen_fd, &epv) < 0)
        sys_log(LL_ERROR, "[ %s:%d ] epoll del failed, fd:%d", __FILE__, __LINE__, process->listen_fd );    
    //else  
        //sys_log(LL_DEBUG, "[ %s:%d ] epoll del ok, fd:%d", __FILE__, __LINE__, process->listen_fd );    

    close( process->listen_fd );
    process->listen_fd = 0;
}

  
static void _close_conenect(int epoll_fd, socks_connection_t *con, int force )    
{    
    if( con->closed)
        return;
    
    con->closed = 1;

    struct epoll_event epv = {0, {0}};
    epv.data.ptr = con;    

    int op = EPOLL_CTL_DEL;
    if( epoll_ctl( epoll_fd, op, con->fd, &epv) < 0)
        sys_log(LL_ERROR, "[ %s:%d ] epoll del failed, fd:%d", __FILE__, __LINE__, con->fd );    
    //else  
        //sys_log(LL_DEBUG, "[ %s:%d ] epoll del ok, fd:%d", __FILE__, __LINE__, con->fd );    

    if( con->fd > 0 ){
        if( force )
        {
            struct linger ling = {0, 0};
            if( setsockopt( con->fd, SOL_SOCKET, SO_LINGER, (void*)&ling, sizeof(ling) ) == -1 )
            {
                sys_log(LL_ERROR, "[ %s:%d ] setsockopt(linger) failed, fd:%d, %s", __FILE__, __LINE__, con->fd, strerror(errno));  
            }
        }
        if( close(con->fd ) < 0 ){
            sys_log(LL_ERROR, "[ %s:%d ] close socket failed, fd:%d, %s", __FILE__, __LINE__, con->fd, strerror(errno) );   
        }
        else
            con->fd = 0;
    }
    
    sys_log(LL_DEBUG, "[ %s:%d ] connect closed, fd:%d, peer: %s:%d", __FILE__, __LINE__, con->fd, con->peer_hostname, ntohs(con->peer_host.port) );    
} 

static void _close_udp_conenect(socks_worker_process_t *process, int epoll_fd, socks_udp_connection_t *con, int force )    
{    
    if( con->closed)
        return;

    int ret = is_fd_in_udp_listen_fd( process, con->fd);
    if (ret){
        sys_log(LL_DEBUG, "udp_listen_fd: %d should not be closed !", con->fd);
        return;
    }
    
    con->closed = 1;

    struct epoll_event epv = {0, {0}};
    epv.data.ptr = con;    

    int op = EPOLL_CTL_DEL;
    if( epoll_ctl( epoll_fd, op, con->fd, &epv) < 0)
        sys_log(LL_ERROR, "[ %s:%d ] epoll del failed, fd:%d", __FILE__, __LINE__, con->fd );    
    //else  
        //sys_log(LL_DEBUG, "[ %s:%d ] epoll del ok, fd:%d", __FILE__, __LINE__, con->fd );   

    if( con->fd > 0 ){
        if( force )
        {
            struct linger ling = {0, 0};
            if( setsockopt( con->fd, SOL_SOCKET, SO_LINGER, (void*)&ling, sizeof(ling) ) == -1 )
            {
                sys_log(LL_ERROR, "[ %s:%d ] setsockopt(linger) failed, fd:%d, %s", __FILE__, __LINE__, con->fd, strerror(errno));  
            }
        }
        if( close(con->fd ) < 0 ){
            sys_log(LL_ERROR, "[ %s:%d ] close socket failed, fd:%d, %s", __FILE__, __LINE__, con->fd, strerror(errno) );   
        }
        else
            con->fd = 0;
    }

    ret = udp_port_pool_add(process, con->local_port);
    if (ret < 0){
        sys_log(LL_ERROR,  "[ %s:%d ] add udp_port_pool failed, port:%d", __FILE__, __LINE__, con->local_port);
    }
    
    sys_log(LL_DEBUG, "[ %s:%d ] connect closed, fd:%d, peer: %s:%d", __FILE__, __LINE__, con->fd, con->peer_hostname, ntohs(con->peer_host.port) );    
} 

   
void close_session_with_force(socks_worker_process_t *process, socks_session_t *session, int force)    
{    
    
    if( session->closed )
        return;

    session->closed = 1;
    session->closed_by = SOCKS_CLOSE_BY_SOCKD;
    session->close_stamp = get_current_ms();
    
    if( session->client )
    {
        if( session->client->eof )
            session->closed_by = SOCKS_CLOSE_BY_CLIENT;
        _close_conenect( process->epoll_fd, session->client, force );
    }

    if( session->remote )
    {
        if( session->remote->eof )
            session->closed_by = SOCKS_CLOSE_BY_REMOTE;
        _close_conenect( process->epoll_fd, session->remote, force );
    }
    if( session->remote ){
        sys_log(LL_DEBUG, "[ %s:%d ] %s:%d-%s:%d session closed, up bytes:%d, down bytes:%d, c-eof:%d, r-eof:%d", __FILE__, __LINE__, 
            session->client->peer_hostname, ntohs(session->client->peer_host.port), 
            session->remote->peer_hostname, ntohs(session->remote->peer_host.port), 
            session->up_byte_num, session->down_byte_num, session->client->eof, session->remote->eof );
    }
    else
    {
        sys_log(LL_DEBUG, "[ %s:%d ] %s:%d -  session closed, up bytes:%d, c-eof:%d", __FILE__, __LINE__, 
            session->client->peer_hostname, ntohs(session->client->peer_host.port), 
            session->up_byte_num, session->down_byte_num, session->client->eof );
    }

    if( session->udp_client )
    {
        _close_udp_conenect( process, process->epoll_fd, session->udp_client, force );
    }

    if (session->udp_remote )
    {
        _close_udp_conenect( process, process->epoll_fd, session->udp_remote, force );
    }

    // write flow-log
    update_order_when_session_close(session);
    
    // 从订单的session cache中移除，并放入已关闭的session，等待释放内存
    rb_node_t *node = NULL;
    if( session->order ){
        rb_key_t key;
        key.pkey = (void *)session;
        node = rb_tree_delete( &session->order->session_cache, &key );
    }
    if( !node ){
        node = rb_list_pop( &process->rb_node_pool );
    }
    if( node ){
        node->key.lkey = session->close_stamp;
        node->data = session;
        rb_tree_insert_node( &process->closed_sessions, node, 1 );
        del_from_new_session_cache( process, session );
    }
    else{
        sys_log(LL_ERROR, "[ %s:%d ] put closed_sessions failed, will memory leak. fd:%d", __FILE__, __LINE__, session->client->fd ); 
    }

    // 工作进程的session计数器
    process->session_num--;
}

void close_session(socks_worker_process_t *process, socks_session_t *session)
{
    close_session_with_force(process, session, 0); 
}   


// free resources after session closed 100ms 
int free_closed_session_resource(socks_worker_process_t *process, int timeout )    
{    
    int i = 0;
    long expired = get_current_ms()-timeout;        // 缓存10ms?
    
    rb_node_t *node, *next, *session_node;
    rb_key_t key;
    node = rb_first(&process->closed_sessions);
    while( node )
    {
        next = rb_next(node);
        socks_session_t *session = (socks_session_t *)node->data;
            
        // free session obj, when 10ms after closed  
        if( session->close_stamp< expired ){
            i++;
            //if( session->client ){
            //  free( session->client );
            //  session->client = NULL;
            //}
            if( session->udp_client ){
                free( session->udp_client );
                session->udp_client = NULL;
            }
            
            if( session->remote){
                free( session->remote );
                session->remote = NULL;
            }
            if( session->udp_remote){
                memcpy(&key.lkey, &session, sizeof(session));
                session_node = rb_tree_search(&process->udp_session_cache, &key);
                if (!session_node){
                    sys_log(LL_ERROR, "[ %s:%d ] can not find %ld in udp_session_cache", __FILE__, __LINE__, 
                        session);
                }
                else{
                    rb_erase(session_node, &process->udp_session_cache);
                }
                free( session->udp_remote );
                session->udp_remote = NULL;
            }
            if(session->http_info){
/* HTML
                if (session->http_info->htmlparser_ctx_ext.ctx){
                    htmlparser_delete(session->http_info->htmlparser_ctx_ext.ctx);
                    session->http_info->htmlparser_ctx_ext.ctx = NULL;
                }
*/
                memset(session->http_info,0, sizeof(session->http_info));
                free(session->http_info);
                session->http_info = NULL;
            }
            session->stage = SOCKS_STAGE_CLOSE;
            rb_erase(node, &process->closed_sessions );
            rb_list_add( &process->rb_node_pool, node );
            free(session);
            session = NULL;
            node = next;
        }
        else{
            // no timeout
            break;
        }
    }
    return i;
} 


int _recv_data ( socks_connection_t *con, int size )
{
    int total = 0;  

    // see http://www.cnblogs.com/jingzhishen/p/3616156.html

    if( con->data_length >= RECV_BUF_SIZE ){
        sys_log(LL_DEBUG, "[ %s:%d ] buf full,no recv, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
            con->fd, con->data_length, con->sent_length,  size, total );
        return 0;
    }
    /*if( con->data_length <0 || 
            con->sent_length <0 || con->data_length < con->sent_length ){
        sys_log(LL_ERROR, "[ %s:%d ] begin recv, buf overflow, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
            con->fd, con->data_length, con->sent_length,  size, total );
        return -1;
    }*/
    do{
        int will_read = size;
        if( con->data_length+size >RECV_BUF_SIZE ){
            will_read = RECV_BUF_SIZE - con->data_length;
        }
        if( will_read <=0 ){
            sys_log(LL_ERROR, "[ %s:%d ] recv size error, fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
                con->fd, con->data_length, con->sent_length,  size, total );
            return 0;
        }
        /*if( con->fd == 0 ){
            sys_log(LL_ERROR, "[ %s:%d ] connection already closed, fd: %d, peer:%s:%d", __FILE__, __LINE__, 
                con->fd, con->peer_hostname, ntohs(con->peer_host.port) );
            return -1;
        }*/
        int len = recv(con->fd, &con->buf[con->data_length], will_read, MSG_DONTWAIT ); //MSG_WAITALL

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
                sys_log(LL_ERROR, "[ %s:%d ] recv EAGAIN : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
                    con->fd, con->data_length, con->sent_length, size, total );
                break;
            }

            else if (err == EINTR )
            {
                sys_log(LL_ERROR, "[ %s:%d ] recv EINTR : fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
                    con->fd, con->data_length, con->sent_length, size, total );
                continue;
            }
            else
            {
                sys_log(LL_ERROR, "[ %s:%d ] recv error:%d, %s. fd: %d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__, 
                    errno, strerror(errno), con->fd, con->data_length, con->sent_length, size, total );
                //func_stack_dump( err);
                return -1;
            }
        }
        else if( len == 0 ){ // 如果recv函数在等待协议接收数据时网络中断了，那么它返回0。
            sys_log(LL_DEBUG, "[ %s:%d ] eof. recv eof. fd:%d, dlen:%d, slen:%d, expect:%d, recv:%d", __FILE__, __LINE__,
                con->fd, con->data_length, con->sent_length, size, total );
            con->eof = 1;
            //break;
            return -1;
        }

    }
    while( 1 );
    
    return total;

}

int _recv_data_until_length( socks_connection_t *con, int length )
{
    while( con->data_length < length)
    {
        int len = _recv_data ( con, length-con->data_length );
        if( len<=0 )
            break;
    }
    return con->data_length;
}

void _clean_recv_buf( socks_connection_t *con )
{
    memset( con->buf, 0, RECV_BUF_SIZE );
    con->data_length = 0;
    con->sent_length = 0;
}

void _clean_udp_recv_buf( socks_udp_connection_t *con )
{
    memset( con->buf, 0, UDP_RECV_BUF_SIZE );
    con->data_length = 0;
    con->sent_length = 0;
}

int _send_data( socks_connection_t *con, int send_fd )
{
    int total = 0;  
    // will send size 
    int size = con->data_length-con->sent_length;
    if( size <=0 | size+con->sent_length>RECV_BUF_SIZE|| con->sent_length < 0 || 
        con->sent_length >=RECV_BUF_SIZE || con->data_length<=0 || con->data_length>RECV_BUF_SIZE ){
        sys_log(LL_ERROR, "[ %s:%d ] buf error, fd:%d, send_fd: %d, dlen:%d, slen:%d", __FILE__, __LINE__, con->fd, send_fd, 
            con->data_length, con->sent_length );
        func_stack_dump( 0 );
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
            sys_log(LL_ERROR, "[ %s:%d ] net disconnected when send data. fd: %d, dlen:%d, slen:%d, size:%d", __FILE__, __LINE__, 
                send_fd, con->data_length, con->sent_length, size );
            return -1;
        }
        else{
            int err = errno;
            if (err == EAGAIN)
            {
                sys_log(LL_DEBUG, "[ %s:%d ] send EAGAIN, fd: %d, dlen:%d, size:%d, %s", __FILE__, __LINE__, 
                    send_fd, con->data_length, size, strerror(errno)  );
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
    
    return con->sent_length;

}

ssize_t _send_data_until_length( socks_connection_t *con, int send_fd, ssize_t length )
{
    con->data_length = length;
    con->sent_length = 0;
    return _send_data(con, send_fd );
}

socks_session_t *_create_session( socks_worker_process_t *process, int fd)
{
    // 一次性分配session和client的内存
    socks_session_t *session = (socks_session_t *)malloc(sizeof(socks_session_t)+sizeof(socks_connection_t));
    if( session == NULL ){
        sys_log(LL_ERROR, "[ %s:%d ] malloc error,fd: %d", __FILE__, __LINE__, fd );
        return NULL;
    }
    memset( session, 0, sizeof(socks_session_t) );
    session->connect_stamp = get_current_ms();
    session->last_data_stamp = session->connect_stamp;
    session->stage = SOCKS_STAGE_INIT;
    
    socks_connection_t *con = (socks_connection_t *)((void *)session+sizeof(socks_session_t));
    if( con == NULL ){
        sys_log(LL_ERROR, "[ %s:%d ] malloc error,fd: %d", __FILE__, __LINE__, fd );
        free(session );
        return NULL;
    }
    memset( con, 0, sizeof(socks_connection_t) );
    session->client = con;
    con->session = session;
    con->fd = fd;

    return session;

}


// call back for accept new connections from clients    
void _accept_connect_cb( socks_worker_process_t *process, int listen_fd, int events )    
{    
    int fd;    
    struct sockaddr_in sin;    
    socklen_t len = sizeof(struct sockaddr_in);    
    fd = accept(listen_fd, (struct sockaddr*)&sin, &len);
    if(fd == -1)    
    {    
        if(errno != EAGAIN && errno != EINTR)    
        {    
            sys_log(LL_ERROR, "[ %s:%d ] accept error:%s, listen_fd:%d, %s", __FILE__, __LINE__, listen_fd, strerror(errno) );    
        }  
        return;    
    }
    
    /*
    if( process->session_num > process->config->max_sessions ){
        int real_session_num = calc_session_of_orders( process );
        sys_log(LL_ERROR, "[ %s:%d ] accept failed, session_num:%d, exceed max_sessions:%d, real_session_num:%d", __FILE__, __LINE__, 
            process->session_num, process->config->max_sessions, real_session_num ); 
        close(fd);
        return;  
    }*/


    int flags = fcntl( fd, F_GETFL, 0);
    if (flags < 0) {
        sys_log(LL_ERROR, "[ %s:%d ] get socket flags error,fd: %d, %s", __FILE__, __LINE__, fd, strerror(errno) );
        close( fd );
        return ;
    }

    // set nonblocking  
    if( fcntl(fd, F_SETFL, flags|O_NONBLOCK) < 0){  
        sys_log(LL_ERROR, "[ %s:%d ] fcntl nonblocking error,fd: %d, %s", __FILE__, __LINE__, fd, strerror(errno) );
        close(fd);
        return;
    }
    
    socks_session_t *session = _create_session( process, fd );
    if( session == NULL ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory,fd: %d", __FILE__, __LINE__, fd );
        close(fd);
        return;
    }
    process->session_num++;
    socks_connection_t *con = session->client;

    copy_sockaddr_to_hostname( &sin.sin_addr, con->peer_hostname );
    convert_to_socks_host_t( &con->peer_host, &sin );


    len = sizeof(sin);
    getsockname( fd, (struct sockaddr*)&sin, &len);
    copy_sockaddr_to_hostname( &sin.sin_addr, con->local_hostname );
    con->local_port = ntohs(sin.sin_port);

    sys_log(LL_DEBUG, "[ %s:%d ] new connection, %s:%d, sessions: %d, stage:%d", __FILE__, __LINE__,  
        con->peer_hostname, ntohs(con->peer_host.port), process->session_num, session->stage );
    
    _clean_recv_buf( con );
    con->session->stage = SOCKS_STAGE_NEGOTIATION;
    _register_session_event( process->epoll_fd, con, fd, EPOLLIN|EPOLLHUP|EPOLLERR, _negotiation_cb );
     
}   

// call back for negotiation    
void _negotiation_cb (  socks_worker_process_t *process, int client_fd, int events, void *arg)    
{    
    socks_connection_t *con = (socks_connection_t*)arg;

    if( con->session->stage != SOCKS_STAGE_NEGOTIATION ){
        sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d ", __FILE__, __LINE__, con->session->stage, client_fd );
        close_session( process, con->session);
        return;
    }
    
    int len;    
    int will_read = 2;
    len = _recv_data_until_length ( con, will_read );
    if( con->eof ){
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv negotiation, len: %d", __FILE__, __LINE__, len );
        close_session( process, con->session);
        return;
    }
    if( con->data_length < will_read){
        add_new_session_to_cache( process, con->session );
        return;
    }
    
    if( con->buf[0] != SOCKS_VERSION_5){
        sys_log(LL_DEBUG, "[ %s:%d ] error socks version: %d, try http proxy !", __FILE__, __LINE__, con->buf[0] );
        http_cb(process, client_fd, events, con);
        //close_session( process, con->session);

        return ;
    }

    unsigned int methods = ((unsigned int)con->buf[1])&0xff;
    if( methods <=0 || methods >255)
    {
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] methods error, fd:%d, len:%d", __FILE__, __LINE__, client_fd, methods );
        close_session( process, con->session);
        return;
    }
    will_read += methods;
    len = _recv_data_until_length ( con, will_read );
    if( con->eof ){
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv, len: %d", __FILE__, __LINE__, len );
        close_session( process, con->session);
        return;
    }
    if( con->data_length < will_read){
        add_new_session_to_cache( process, con->session );
        return;
    }
    
    // 统计session基础流量和协商流量, tcp 3次握手, 4次分手 
    int base_flow = 3*ETHERNET_IP_TCP_HEADER_SIZE + \
        4*ETHERNET_IP_TCP_HEADER_SIZE + \
        len + ETHERNET_IP_TCP_HEADER_SIZE;
    do_stat_order_flow( process, con->session, base_flow, 1, 0 );
    
    int i, k;
    unsigned char useMethod = SOCKS_AUTH_NOT_ACCEPTABLE;
    unsigned char m[2] = { SOCKS_AUTH_FLOW_PACKAGE, SOCKS_AUTH_USER_PASSWORD }; //SOCKS_AUTH_NONE
    for( k=0; useMethod == SOCKS_AUTH_NOT_ACCEPTABLE && k<sizeof(m); k++ )
    {
        for( i=2; i<2+methods; i++)
        {
            unsigned char  method = con->buf[i];
            if( method == m[k] )
            {
                useMethod = method;
                break;
            }
        }
    }
    
    con->buf[1] = useMethod;
    //len = send( client_fd, con->buf, 2, MSG_WAITALL );
    len = _send_data_until_length( con, client_fd, 2 );
    
    sys_log(LL_DEBUG, "[ %s:%d ] auth method : 0x%x, stage: 0x%x", __FILE__, __LINE__, useMethod, con->session->stage  );

    if(len == 2 )    
    {  
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 0, 0 );
        
        con->auth_method = useMethod;
        _clean_recv_buf( con );
        if( useMethod == SOCKS_AUTH_NONE )
        {
            con->session->stage = SOCKS_STAGE_COMMAND;
            _change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR|EPOLLRDHUP, _command_cb );
        }
        else
        {
            con->session->stage = SOCKS_STAGE_AUTH;
            _change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR|EPOLLRDHUP, _auth_cb );
        }
    }
    else
    {
        sys_log(LL_ERROR, "[ %s:%d ] send negotiation result failed, fd:%d", __FILE__, __LINE__, client_fd );
        close_session( process, con->session);
        return ;
    }
    
                
}


// auth callback, support SOCKS_AUTH_USER_PASSWORD, SOCKS_AUTH_FLOW_PACKAGE
void _auth_cb (  socks_worker_process_t *process, int client_fd, int events,   void *arg)    
{    
    socks_connection_t *con = (socks_connection_t*)arg;

    socks_auth_req_t req;
    mtr_auth_reply_t reply;
    memset((void *)&req, 0, sizeof(req) ); 
    memset( (void *)&reply, 0, sizeof( reply ) );
    reply.status = MTR_ORDER_AUTH_ERR_UNKOWN; // set default
    
    req.auth_method = con->auth_method;

    if( process->session_num > process->config->max_sessions ){
        int real_session_num = calc_session_of_orders( process );
        sys_log(LL_ERROR, "[ %s:%d ] accept failed, session_num:%d, exceed max_sessions:%d, real_session_num:%d", __FILE__, __LINE__, 
            process->session_num, process->config->max_sessions, real_session_num ); 

        reply.status = MTR_ORDER_AUTH_ERR_SYS_BUSY;
        send_auth_reply( process, con, &reply);
        close_session(process, con->session);
        return;  
    }

    if( con->session->stage != SOCKS_STAGE_AUTH){
        sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d", __FILE__, __LINE__, con->session->stage, client_fd );
        send_auth_reply( process, con, &reply );
        close_session( process, con->session);
        return;
    }
    
    int len;    
    int will_read = 2;
    len = _recv_data_until_length ( con, will_read );
    if( con->eof ){
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] error when recv auth, fd:%d, eof:%d", __FILE__, __LINE__, client_fd, con->eof );
        close_session( process, con->session);
        return;
    }
    if( con->data_length < will_read){
        add_new_session_to_cache( process, con->session );
        return;
    }
    
    if( con->buf[0] != SOCKS_METHOD_VERSION ){
        sys_log(LL_ERROR, "[ %s:%d ] error method version: 0x%x, fd:%d", __FILE__, __LINE__, con->buf[0], client_fd );
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );
        reply.status = SOCKS_AUTH_ERR_VERSION;
        send_auth_reply( process, con, &reply );
        close_session( process, con->session);
        return ;
    }
    req.method_version = con->buf[0];
    reply.method_version = con->buf[0];

    unsigned int user_len = ((unsigned int)con->buf[1])&0xff;
    if( user_len <=0 || user_len >255)
    {
        //user_len error. close session
        sys_log(LL_ERROR, "[ %s:%d ] user_len error, fd:%d, len:%d", __FILE__, __LINE__, client_fd, user_len );
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );
        reply.status = MTR_ORDER_AUTH_ERR_UNKOWN;
        send_auth_reply( process, con, &reply );
        close_session( process, con->session);
        return;
    }
    will_read = will_read+user_len+1;
    unsigned char *user_name = con->buf+2;
    
    len = _recv_data_until_length ( con, will_read );
    if( con->eof ){
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv username, fd:%d", __FILE__, __LINE__, client_fd );
        close_session( process, con->session);
        return;
    }
    if( con->data_length < will_read){
        add_new_session_to_cache( process, con->session );
        return;
    }

    req.user_name = socks_string_set(&con->buf[1]);
    
    unsigned int pswd_len = ((unsigned int)con->buf[2+user_len])&0xff;
    if( pswd_len <=0 || pswd_len >255)
    {
        //pswd_len error. close session
        sys_log(LL_ERROR, "[ %s:%d ] pswd_len error, fd:%d, len:%d", __FILE__, __LINE__, client_fd, pswd_len );
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );
        reply.status = MTR_ORDER_AUTH_ERR_UNKOWN;
        send_auth_reply( process, con, &reply );
        close_session( process, con->session);
        return;
    }
    unsigned char *passwd = con->buf+2+user_len;
    will_read += pswd_len;
    len = _recv_data_until_length ( con, will_read );
    if( con->eof ){
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] error when recv pswd, fd:%d", __FILE__, __LINE__, client_fd );
        close_session( process, con->session);
        return;
    }
    if( con->data_length < will_read){
        add_new_session_to_cache( process, con->session );
        return;
    }
    
    req.passwd = socks_string_set(&con->buf[2+user_len]);

    do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );

    do_first_auth( process, con, &req, &reply);
    
    send_auth_reply( process, con, &reply );
    if( reply.status != MTR_ORDER_AUTH_SUCCESS ){
        sys_log(LL_ERROR, "[ %s:%d ] auth failed:0x%2x, token:%s, fd:%d", __FILE__, __LINE__, reply.status,
            con->session->token, client_fd );
        close_session( process, con->session);
        return;
    }
    
    _clean_recv_buf( con );
    con->session->stage = SOCKS_STAGE_COMMAND;
    _change_session_event( process->epoll_fd, con, client_fd, EPOLLIN|EPOLLHUP|EPOLLERR, _command_cb );
                
}

int send_cmd_reply( socks_worker_process_t *process, socks_connection_t *con, socks_command_reply_t *reply )
{
    memcpy((void *)&con->buf[0], (void *)reply, 3 );
    unsigned char *pos = (unsigned char *)copy_socks_host_to_buf( &reply->host, (unsigned char *)&con->buf[3]);
    if (reply->session != 0){
        //for cmd 0x04, FIXME
        memcpy( (unsigned char*)&con->buf[10], &reply->session, sizeof(reply->session));
        pos += sizeof(reply->session);
    }
    int send_length = pos- &con->buf[0];
    
    int len = _send_data_until_length( con, con->fd, send_length );
    if(len <= 0 )   
    {  
        sys_log(LL_ERROR, "[ %s:%d ] cmd status:0x%2x send failed, fd:%d", __FILE__, __LINE__, reply->status, con->fd );
        close_session( process, con->session);
    }
    else
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 0, 0 );
    return len;
}


// command callback
void _command_cb (  socks_worker_process_t *process, int client_fd, int events,   void *arg)    
{    
    socks_connection_t *con = (socks_connection_t*)arg;
    
    sys_log(LL_DEBUG, "[ %s:%d ] cmd from: %s:%d, stage:%d, ", __FILE__, __LINE__, con->peer_hostname, 
        ntohs(con->peer_host.port), con->session->stage );

    socks_command_t cmd;
    socks_command_reply_t reply;
    
    memset( &cmd, 0, sizeof(cmd) );
    memset( &reply, 0, sizeof(reply) );
    reply.version = SOCKS_VERSION_5;
    reply.host.atype = SOCKS_ATYPE_IPV4;
    reply.status = SOCKS_CMD_ERR_FAIL;
    
    if( con->session->stage != SOCKS_STAGE_COMMAND){
        sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d ", __FILE__, __LINE__, con->session->stage, client_fd );
        send_cmd_reply( process, con, &reply );
        close_session( process, con->session);
        return;
    }
    
    int head_length = 4;
    int will_read =  head_length+1;
    int len = _recv_data_until_length ( con, will_read );
    if( con->eof ){
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv cmd, fd:%d", __FILE__, __LINE__, client_fd );
        close_session( process, con->session);
        return;
    }
    if( len< will_read)
    {
        sys_log(LL_DEBUG, "[ %s:%d ] recv cmd, len: %d, will:%d, fd:%d", __FILE__, __LINE__, len, will_read, client_fd );
        add_new_session_to_cache( process, con->session );
        return;
    }

    if( con->buf[0] != SOCKS_VERSION_5){
        sys_log(LL_ERROR, "[ %s:%d ]  error socks version: %d, fd:%d", __FILE__, __LINE__,  con->buf[0], client_fd );
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );
        send_cmd_reply( process, con, &reply );
        close_session( process, con->session);
        return ;
    }
    memcpy( &cmd, con->buf, 3 );
    
    
    unsigned char atype = con->buf[3];
    
    int host_length = 4;
    unsigned char *host = con->buf+head_length;
    if ( atype == SOCKS_ATYPE_IPV4){
        host_length = 4;
        will_read = head_length+host_length+2;
    }
    else if( atype == SOCKS_ATYPE_DOMAIN )
    {
        host_length = ((int)con->buf[4])&0xff;
        will_read = head_length+host_length+1+2;
        host++;
    }
    else if ( atype == SOCKS_ATYPE_IPV6 ){
        host_length = 16;
        will_read = head_length+host_length+2;
    }
    else{
        // unsupported atype
        sys_log(LL_ERROR, "[ %s:%d ] atype:0x%x unsupported, fd:%d", __FILE__, __LINE__, atype, client_fd  );
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );
        reply.status = SOCKS_CMD_ERR_ATYPE;
        send_cmd_reply( process, con, &reply );
        close_session( process, con->session);
        return;
    }
    
    len = _recv_data_until_length ( con, will_read );
    if( con->eof ){
        //net disconnected. close session
        sys_log(LL_ERROR, "[ %s:%d ] disconnected when recv dst addr, fd:%d", __FILE__, __LINE__, client_fd  );
        do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );
        close_session( process, con->session);
        return;
    }
    
    if( len < will_read){
        add_new_session_to_cache( process, con->session );
        return;
    }
    // update up_byte_num of session
    do_stat_order_flow( process, con->session, len+ETHERNET_IP_TCP_HEADER_SIZE, 1, 0 );

    copy_buf_to_socks_host( &cmd.host, &con->buf[3] );
    sys_log(LL_DEBUG, "[ %s:%d ] recv 0x%x cmd addr %s:%d, fd:%d", __FILE__, __LINE__, cmd.cmd, inet_ntoa(cmd.host.addr.ipv4), ntohs(cmd.host.port),client_fd  );
    
    // 做二次鉴权;
    int ret = do_second_auth( process, con, &cmd, &reply );
    if (ret == SOCKS_CMD_SUCCESS )
    {
        //con->cmd = cmd.cmd;
        if( cmd.cmd == SOCKS_COMMAND_CONNECT ){
            con->session->protocol = SOCKS_PROTOCOL_TCP;
            _do_command_connect( process, con, &cmd, &reply );
        }

        else if(cmd.cmd == SOCKS_COMMAND_UDP_ASSOCIATE || SOCKS_COMMAND_UDP_CONNECT)
        {
            con->session->protocol = SOCKS_PROTOCOL_UDP;
            _do_command_udp( process, con, &cmd, &reply );
        }

        else
        { //  unsupported
            reply.host.atype = SOCKS_ATYPE_IPV4;
            reply.status = SOCKS_CMD_ERR_COMMAND;
            send_cmd_reply( process, con, &reply );
            close_session( process, con->session);
            return;
        }   
    }
    else
    { 
        reply.host.atype = SOCKS_ATYPE_IPV4;
        send_cmd_reply( process, con, &reply );
        close_session( process, con->session);
        return;
    }
                
}




int _init_listen_socket(  socks_worker_process_t *process)    
{    
    int tries =0;
    int listen_fd = -1;
    int failed = 0;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0); 
    if( listen_fd == -1 ){
        sys_log(LL_ERROR, "[ %s:%d ] open socket fail, fd:%d", __FILE__, __LINE__, listen_fd );
        return -1;
    }
    
    process->listen_fd = listen_fd;
    _register_listen_event( process->epoll_fd, listen_fd, EPOLLIN|EPOLLHUP|EPOLLERR );
    
    for( tries=0; tries< 5; tries++ )
    {
        failed = 0;

        if (process->config->reuseaddr ) {
            int value = process->config->reuseaddr ==1?1:0;
            if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(int)) == -1)
            {
                sys_log(LL_ERROR, "[ %s:%d ] set SO_REUSEADDR fail, fd:%d", __FILE__, __LINE__, listen_fd );
            }
        }
        
        if (process->config->recv_buf_size ) {
            if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVBUF, (void *) &process->config->recv_buf_size, sizeof(int)) == -1)
            {
                sys_log(LL_ERROR, "[ %s:%d ] set SO_RCVBUF fail, fd:%d", __FILE__, __LINE__, listen_fd );
            }
        }

        if (process->config->send_buf_size ) {
            if (setsockopt(listen_fd, SOL_SOCKET, SO_SNDBUF, (void *) &process->config->send_buf_size, sizeof(int)) == -1)
            {
                sys_log(LL_ERROR, "[ %s:%d ] set SO_SNDBUF fail, fd:%d", __FILE__, __LINE__, listen_fd );
            }
        }

        if (process->config->keepalive ) {
            int value = process->config->keepalive ==1?1:0;
            if (setsockopt(listen_fd, SOL_SOCKET, SO_KEEPALIVE, (void *) &value, sizeof(int)) == -1)
            {
                sys_log(LL_ERROR, "[ %s:%d ] set SO_SNDBUF fail, fd:%d", __FILE__, __LINE__, listen_fd );
            }
        }
        
        if( fcntl(listen_fd, F_SETFL, O_NONBLOCK) == -1 ){ // set non-blocking    
            sys_log(LL_ERROR, "[ %s:%d ] set O_NONBLOCK failed, fd=%d\n", __FILE__, __LINE__, listen_fd); 
            failed = 1;
            continue;
        }
        

        // bind & listen    
        struct sockaddr_in sin;    
        memset(&sin, 0, sizeof(sin));    
        sin.sin_family = AF_INET;    
        sin.sin_addr.s_addr = INADDR_ANY;    
        sin.sin_port = htons( process->config->listen_port );  
        
        if( bind(listen_fd, (  struct sockaddr*)&sin, sizeof(sin)) == -1 ){
            failed = 1;
            fprintf(stderr, "try to bind port:%d failed, %s\n", process->config->listen_port, strerror(errno) );
            sys_log(LL_ERROR, "[ %s:%d ] bind port:%d failed, fd=%d, %s", __FILE__, __LINE__, 
                process->config->listen_port, listen_fd, strerror(errno) ); 
            //close(listen_fd);
            continue;
        }
        
        if( listen(listen_fd, process->config->listen_backlog ) == -1){
            failed = 1;
            sys_log(LL_ERROR, "[ %s:%d ] listen failed, port:%d, backlog:%d, fd=%d\n", __FILE__, __LINE__, 
                process->config->listen_port, process->config->listen_backlog, listen_fd); 
            continue;
        }
        
        if( !failed ){
            break;
        }
    }
    
    if( failed ){
        close( listen_fd );
        process->listen_fd = -1;
        return -1;
    }
    
    return listen_fd;
    
} 

int _init_udp_socket( socks_worker_process_t * process , int  udp_port)
{
    socks_udp_connection_t * udp_conn = (socks_udp_connection_t*)malloc(sizeof(socks_udp_connection_t));
    int fd = process->udp_listen[process->udp_listen_fd_num].fd = socket(AF_INET, SOCK_DGRAM, 0);
    process->udp_listen[process->udp_listen_fd_num].port = udp_port;

    if ( fd < 0) {
        sys_log(LL_ERROR, "[ %s:%d ] init create  udp error", __FILE__, __LINE__ );
        return -1;
    }

    int flags = fcntl( fd, F_GETFL, 0);
    if (flags < 0) {
        sys_log(LL_ERROR, "[ %s:%d ] get  socket flags error fd:%d", __FILE__, __LINE__,  fd );
        return -1;
    }

    if (fcntl( fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    sys_log(LL_ERROR, "[ %s:%d ] set udp nonblock error,fd:%d, %s:%d", __FILE__, __LINE__, fd );
        return -1;
    }
    
    int value = process->config->reuseaddr ==1?1:0;
    if (setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (void *) &value, sizeof(int)) == -1)
    {
        sys_log(LL_ERROR, "[ %s:%d ] set udp SO_REUSEADDR fail, fd:%d", __FILE__, __LINE__, fd );
    }

    struct sockaddr_in s_addr;
    memset(&s_addr, 0, sizeof (s_addr));
    s_addr.sin_family = AF_INET;
    inet_aton( process->config->listen_host, &s_addr.sin_addr);  
    // TODO: 实现配置监听的UDP端口范围 0x04
    s_addr.sin_port = htons(udp_port);
    if( bind( fd, (  struct sockaddr*)&s_addr, sizeof(s_addr)) == -1 ){
        sys_log(LL_ERROR, "[ %s:%d ] bind init udp failed,  fd=%d", __FILE__, __LINE__, fd); 
        return errno;
    }

    socklen_t len = sizeof(s_addr);
    getsockname( fd, (struct sockaddr*)&s_addr, &len);
    sys_log(LL_DEBUG, "[ %s:%d ] bind init udp ok, local: %s:%d, fd:%d", __FILE__, __LINE__, process->config->listen_host, ntohs(s_addr.sin_port ), fd); 

    _register_session_event( process->epoll_fd, (socks_connection_t *)udp_conn, fd, EPOLLIN|EPOLLHUP|EPOLLERR, _udp_data_transform_cb_2 );

    return 0;
}

void init_worker_process( socks_worker_process_t *process, socks_worker_config_t *w_config)
{
    long now = get_current_ms();
    long now_sec = time(NULL);
    memset( process, 0, sizeof( socks_worker_process_t ) );
    process->config = w_config;

    process->today_sum_flow_stamp = get_mid_night_second((time_t)now_sec);
    process->last_check_order_event_stamp = now;
    process->last_defrag_pool_stamp = now;
    process->last_update_worker_stat_stamp = now_sec;

    //open logfile
    if( log_init( w_config->listen_port ) < 0)
    {
        fprintf( stderr, "[ %s:%d ] open log file failed.\n", __FILE__, __LINE__);
        /* fatal */
        exit(2);
    }

    if (geteuid() == 0 && g_config.user_id>0 ) {
        if (setuid(g_config.user_id) == -1) {
            sys_log( LL_ERROR, "setuid(%d), username:%s failed, %s", g_config.user_id, g_config.user_name, strerror(errno) );
            /* fatal */
            exit(2);
        }
    }
  
    if (strlen(g_config.working_dir)) {
        if (chdir((char *) g_config.working_dir ) == -1) {
            sys_log( LL_ERROR, "chdir(\"%s\") failed", g_config.working_dir );
            /* fatal */
            exit(2);
        }
    }

    // 申请红黑树节点的缓存空间
    rb_list_init( &process->rb_node_pool, process->config->max_sessions*2 + 
        process->config->udp_port_end - process->config->udp_port_start + 1 + process->config->max_domains); //w_config->max_sessions
    // 申请订单的缓存空间
    order_pool_init( process, process->config->max_sessions ); //w_config->max_sessions
    //init udp_port_pool
    udp_port_pool_init(process, process->config->udp_port_start, process->config->udp_port_end);
    //init domain pool
    domain_pool_init(process, process->config->max_domains);

    passwd_pool_init(process, process->config->max_passwds);

    rb_tree_init_for_long_key( &process->closed_sessions );
    rb_tree_init_for_long_key( &process->order_timer );
    rb_tree_init_for_long_key( &process->activity_cache );
    rb_tree_init_for_long_key( &process->udp_session_cache);
    
    rb_tree_init_for_ptr_key( &process->new_session_cache );

    rb_tree_init_for_str_key( &process->order_cache );
    rb_tree_init_for_str_key( &process->overflow_events );
    rb_tree_init_for_str_key( &process->update_events );
    rb_tree_init_for_str_key( &process->will_close_orders );
    rb_tree_init_for_str_key( &process->invalid_orders);
    rb_tree_init_for_str_key( &process->domain_cache );

    
    //create redis connect
    process->redis_connect = redis_init();
    if (!process->redis_connect )
    {
        sys_log(LL_ERROR, "[ %s:%d ] connect redis %s:%d failed.", __FILE__, __LINE__, g_config.redis_host, g_config.redis_port );
        /* fatal */
        exit(2);
    }

    // create epoll    
    process->epoll_fd = epoll_create(MAX_EVENTS);    
    if(process->epoll_fd <= 0) {
        sys_log(LL_ERROR, "[ %s:%d ] create epoll failed:%d, %s", __FILE__, __LINE__, errno, strerror(errno) );  
        /* fatal */
        exit(2);
    }
    
    // create & bind listen socket, and add to epoll, set non-blocking    
    int listen_fd = _init_listen_socket( process ); 
    if( listen_fd < 0 )
    {
        sys_log(LL_ERROR, "[ %s:%d ] _init_listen_socket failed.", __FILE__, __LINE__  );
        /* fatal */
        exit(2);
    }

    //create & bind udp socket
    int udp_listen_fd, udp_port;
    for ( udp_port = udp_port_pool_pop(process) ;
        process->udp_listen_fd_num < UDP_LISTEN_PORT_MAX_NUM && udp_port >0;
        udp_port = udp_port_pool_pop(process) ){
            udp_listen_fd = _init_udp_socket( process, udp_port); 
            if( udp_listen_fd < 0 )
            {
                sys_log(LL_ERROR, "[ %s:%d ] _init_udp_socket failed ! udp_port: %d.", __FILE__, __LINE__, udp_port  );
            }
            else
            {
                process->udp_listen_fd_num++;
            }
    }
    if (process->udp_listen_fd_num == 0){
        sys_log(LL_ERROR, "[ %s:%d ] can not init udp port, check conf again!", __FILE__, __LINE__  );
        /* fatal */
        exit(2);
    }
    

    sys_log( LL_NOTICE, "meteor worker-%d started [pid:%d].", process->config->listen_port, getpid() );  

}

static int wait_and_handle_epoll_events( socks_worker_process_t *process, struct epoll_event *events, int timer )
{
    // wait for events to happen 
    int fds = epoll_wait( process->epoll_fd, events, MAX_EVENTS, timer);      
    if(fds < 0){
        if( errno == EINTR ){
            sys_log( LL_INFO, "epoll_wait interrupted, continue.");  
            return 0;
        }
        sys_log( LL_ERROR, "epoll_wait exit, %s", strerror(errno) );  
        return -1;  
    }
    
    int i = 0;
    for( i = 0; i < fds; i++){
        if(events[i].events&(EPOLLIN|EPOLLOUT) )    
        {    
            if( events[i].data.fd == process->listen_fd )
            {
                _accept_connect_cb( process, process->listen_fd, events[i].events );
            }
            else
            {
                socks_connection_t *con = (socks_connection_t*)events[i].data.ptr; 
                if( !con || con->closed )
                    continue;
                con->events = events[i].events;
                con->call_back( process, con->fd, events[i].events, con );  
            }   
        }
        if((events[i].events&(EPOLLERR|EPOLLHUP) ))     
        {    
            if( events[i].data.fd == process->listen_fd )
            {
                sys_log(LL_ERROR, "[ %s:%d ] epoll error events: %d, listen_fd: %d", __FILE__, __LINE__, 
                    events[i].events, events[i].data.fd );
            }
            else
            {
                socks_connection_t *con = (socks_connection_t*)events[i].data.ptr;  
                if( !con || con->closed )
                    continue;
                con->events = events[i].events;
                sys_log(LL_ERROR, "[ %s:%d ] epoll error events: %d, fd:%d, sock:%s:%d", __FILE__, __LINE__, con->events, 
                    con->fd, con->peer_hostname, ntohs(con->peer_host.port) );
                if( con->session )
                    close_session( process, con->session);
            }   
        } 
    }
    return 0;

}

void start_worker_process( socks_worker_config_t *worker_config )
{
    socks_worker_process_t process;
    
    init_worker_process( &process, worker_config );
    //sys_log( LL_NOTICE, "worker process [%d] listen: %d", getpid(), worker_config->listen_port);  

    // event loop    
    struct epoll_event *events = (struct epoll_event *)calloc( MAX_EVENTS, sizeof(struct epoll_event) ); 
    if( events == NULL )
        return ;
    
    int timer = TIMER_DEFAULT;    
    
    while(1){    

        if (status_exiting || to_terminate) {
            sys_log( LL_NOTICE, "worker process %d exiting", worker_config->listen_port );
            break;
        }

        if(to_quit) {
            to_quit = 0;
            sys_log( LL_NOTICE, "worker process %d gracefully shutting down", worker_config->listen_port );
            
            char title[64];
            sprintf( title, "meteor:worker-%d is shutting down", worker_config->listen_port );
            meteor_set_process_title( title );
            
            if (!status_exiting) {  
                status_exiting = 1;  
            }
            _close_listen_socket( &process );
        }
                
        if( wait_and_handle_epoll_events( &process, events, timer )< 0 )
            break;
        
        timer = handle_order_timer( &process );
        if (timer < 0)
            timer = TIMER_DEFAULT;
    }
    
    free( events );
    
    // free resource  
    worker_process_exit( &process );

}


void worker_process_exit( socks_worker_process_t *process )
{
    _close_listen_socket( process );

    handle_order_timer( process );
    new_session_cache_exit( process );
    order_pool_exit( process );
    udp_port_pool_exit( process );
    passwd_pool_exit(process);
    save_orders_when_process_exit( process );
    save_activity_when_process_exit( process );
    free_closed_session_resource( process, 0 );
    rb_tree_destory( &process->overflow_events, NULL );
    rb_tree_destory( &process->update_events, NULL );
    rb_tree_destory( &process->order_timer, NULL );
    rb_tree_destory( &process->invalid_orders, NULL );
    rb_tree_destory( &process->new_session_cache, NULL);
    rb_tree_destory( &process->udp_session_cache, NULL);
    rb_list_exit( &process->rb_node_pool );
    
    if( process->epoll_fd )
        close( process->epoll_fd );
    
    redisFree(process->redis_connect);
    sys_log( LL_NOTICE, "meteor worker-%d exited [pid:%d].\n", process->config->listen_port, getpid() );
    log_exit();
    
    exit(0);
}
 
