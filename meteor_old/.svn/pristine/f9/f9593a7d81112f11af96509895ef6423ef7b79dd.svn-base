#include "meteor.h"
#include "sockd_tcp.h"
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

void _send_connect_fail_msg( socks_worker_process_t *process, socks_connection_t *con, socks_command_reply_t *reply, int result )
{
	if( result == 0 ){ 
		return;
	}
	
	int ret;
	// send connect failed msg to client
	if( ret == ENETUNREACH ) // 101
		reply->status= SOCKS_CMD_ERR_NET;
	else if( ret == ECONNREFUSED )	//111
		reply->status= SOCKS_CMD_ERR_REFUSE;
	else if( ret == EHOSTUNREACH )
		reply->status= SOCKS_CMD_ERR_HOST;
	else
		reply->status= SOCKS_CMD_ERR_FAIL;
	reply->host.atype = SOCKS_ATYPE_IPV4;
	send_cmd_reply( process, con, reply );
	close_session( process, con->session);

}


void _do_command_connect( socks_worker_process_t *process, socks_connection_t *con, 
	socks_command_t *cmd, socks_command_reply_t *reply )
{
	if(cmd->host.atype == SOCKS_ATYPE_IPV4){
		socks_connection_t *remote = (socks_connection_t *)malloc(sizeof(socks_connection_t));
		if( remote == NULL ){
			sys_log(LL_ERROR, "[ %s:%d ] malloc remote error,fd: %d", __FILE__, __LINE__, con->fd );
			reply->version = SOCKS_VERSION_5;
			reply->host.atype = SOCKS_ATYPE_IPV4;
			reply->status = SOCKS_CMD_ERR_FAIL;
			send_cmd_reply( process, con, reply );
			close_session( process, con->session);
			return;
		}
		memset( (void *)remote, 0,	sizeof(socks_connection_t) );
		con->session->remote = remote;
		remote->session = con->session;
	
		copy_sockaddr_to_hostname( &cmd->host.addr.ipv4, remote->peer_hostname);
		memcpy( &remote->peer_host, &cmd->host, sizeof(socks_host_t) );
	
		remote->peer_conn = con;
		con->peer_conn = remote;
		
		sys_log(LL_DEBUG, "[ %s:%d ] connect command: %s:%d", __FILE__, __LINE__, remote->peer_hostname, ntohs(remote->peer_host.port));
		
		int ret = _connect_remote_host_ipv4( process, con ); 
		
		_send_connect_fail_msg( process, con, reply, ret );
	}
	else
	{
		sys_log(LL_ERROR, "[ %s:%d ] atype: 0x%x unsupported,fd: %d", __FILE__, __LINE__, cmd->host.atype, con->fd );
		reply->version = SOCKS_VERSION_5;
		reply->host.atype = SOCKS_ATYPE_IPV4;
		reply->status = SOCKS_CMD_ERR_ATYPE;
		send_cmd_reply( process, con, reply );
		close_session( process, con->session);
		return;
	}

}


int _connect_remote_host_ipv4(socks_worker_process_t *process, socks_connection_t *con )
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

	con->session->stage = SOCKS_STAGE_CONNECT_REMOTE;

	_register_session_event( process->epoll_fd, remote, fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _connect_remote_host_complete_cb );
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



// connect remote host completed callback, then reply the result to client
// only for ipv4
void _connect_remote_host_complete_cb(  socks_worker_process_t *process, int remote_fd, int events, void *arg)   
{
    socks_connection_t *remote = (socks_connection_t*)arg;
	socks_connection_t *client = remote->session->client;

	socks_command_reply_t reply;
	memset( &reply, 0, sizeof(reply) );
	reply.version = SOCKS_VERSION_5;
	reply.host.atype = SOCKS_ATYPE_IPV4;

	if( remote->session->stage != SOCKS_STAGE_CONNECT_REMOTE ){
		sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d ", __FILE__, __LINE__, remote->session->stage, remote_fd );
		reply.status = SOCKS_CMD_ERR_FAIL;
		send_cmd_reply( process, client, &reply );
		close_session( process, remote->session);
		return;
	}

	int error = _test_tcp_connect_result( remote_fd );
	remote->event_count++;
	long cost = get_current_ms() - remote->conn_stamp ;
	if( error ){
		// EPOLLIN:1 EPOLLOUT:4 EPOLLRDHUP:8192  EPOLLPRI:2  EPOLLERR:8  EPOLLHUP:16
		sys_log(LL_ERROR, "[ %s:%d ] connect remote error:%s, fd:%d, %s:%d, events:0x%x, count:%d, cost:%d", __FILE__, __LINE__, 
			strerror(error), remote_fd,  remote->peer_hostname, ntohs(remote->peer_host.port), events, remote->event_count, cost );
		if (error != EINPROGRESS) {
			_send_connect_fail_msg( process, client, &reply, error );
			return;
        }
		return;
	}

	remote->session->stage = SOCKS_STAGE_TCP_DATA;

	// connect successfully  
    if( events & (EPOLLOUT) ){  
		
		struct sockaddr_in local_addr; 
		socklen_t len = sizeof(local_addr);
		getsockname( remote_fd, (struct sockaddr*)&local_addr, &len);
		
		copy_sockaddr_to_hostname( &local_addr.sin_addr, remote->local_hostname);
		remote->local_port = ntohs(local_addr.sin_port);
		
		sys_log(LL_DEBUG, "[ %s:%d ] connect remote ok, fd:%d, local: %s:%d", __FILE__, __LINE__, remote_fd, remote->local_hostname, remote->local_port );
		_clean_recv_buf( remote );
		_change_session_event( process->epoll_fd, remote, remote_fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _tcp_data_transform_cb );

		// send connect msg to client
		reply.status = SOCKS_CMD_SUCCESS;
		reply.host.port = local_addr.sin_port;
		memcpy((void *)&reply.host.addr.ipv4, (void *)&local_addr.sin_addr, sizeof(local_addr.sin_addr) );
		len = send_cmd_reply( process, client, &reply );
		if(len > 0 )
		{
			_clean_recv_buf( client );
			client->session->stage = SOCKS_STAGE_TCP_DATA;
			_change_session_event( process->epoll_fd, client, client->fd, EPOLLOUT|EPOLLIN|EPOLLHUP|EPOLLERR, _tcp_data_transform_cb );
		}

    } 

}


// while data from client or remote host, then transform to the orther peer
void _tcp_data_transform_cb(  socks_worker_process_t *process, int fd, int events, void *arg)
{
	// about recv and send, see http://www.cnblogs.com/blankqdb/archive/2012/08/30/2663859.html
    socks_connection_t *con = (socks_connection_t*)arg;

	if( con->session->stage != SOCKS_STAGE_TCP_DATA ){
		sys_log(LL_ERROR, "[ %s:%d ] error stage: %d, fd:%d", __FILE__, __LINE__, con->session->stage, fd );
		close_session( process, con->session);
		return;
	}
	
	int up_direct =  0;
	if( fd == con->session->client->fd )
		up_direct = 1;

	if( con->closed ){
		sys_log(LL_DEBUG, "[ %s:%d ] %s closed by %d, fd:%d, dlen:%d, slen:%d, ", __FILE__, __LINE__, 
			up_direct?"client":"remote", con->session->closed_by, fd, con->data_length, con->sent_length);
		return;
	}
	
	if( events & EPOLLIN)
	{
		int len = _recv_data( con, RECV_BUF_SIZE-con->data_length );
		sys_log(LL_DEBUG, "[ %s:%d ] just only %s recv, fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
			up_direct?"client":"remote", con->fd, con->data_length, con->sent_length );
		if( len <0 || con->eof == 1) 
		{
			int level = (con->eof == 1? LL_DEBUG: LL_ERROR);
			sys_log(level, "[ %s:%d ] %s recv eof:%d, fd:%d, dlen:%d, slen:%d, len: %d, errno:%d, %s", __FILE__, __LINE__, 
				up_direct?"client":"remote", con->eof, con->fd, con->data_length, con->sent_length, len, errno, strerror(errno) );
			if( con->eof )
				close_session( process, con->session);
			return;
		}
		//stat up flow
		if( len > 0 && up_direct == 1)
			do_stat_order_flow( process, con->session, len, up_direct, 1 );
	}

	if( events & EPOLLOUT )
	{
		socks_connection_t *peer = con->peer_conn;
		if( peer->data_length > peer->sent_length ){
			sys_log(LL_DEBUG, "[ %s:%d ] continue, send to %s , fd:%d, recv_fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
				up_direct?"client":"remote", con->fd, peer->fd, peer->data_length, peer->sent_length);
			
			int len = _send_data( peer, con->fd );
			if( len <0 ) {
				int err = errno;
				if( err == EPIPE || err == ECONNRESET){
					con->eof = 1;
					close_session( process, con->session);
				}
				int level = (con->eof == 1 ? LL_DEBUG: LL_ERROR );
				sys_log(level, "[ %s:%d ] %s send eof:%d, fd:%d, recv_fd:%d, dlen:%d, slen:%d, len: %d, errno:%d, %s", __FILE__, __LINE__, 
					up_direct?"client":"remote", con->eof, con->fd, peer->fd, con->data_length, con->sent_length, len, errno, strerror(errno) );
				return;
			}
			
			if( peer->sent_length == peer->data_length && peer->data_length>0 ){
				_clean_recv_buf( peer );
			}
			//stat down flow
			if( len > 0 && up_direct == 1 )
				do_stat_order_flow( process, con->session, len, 0, 1 );
		}
		else{
			sys_log(LL_DEBUG, "[ %s:%d ] no data for send to %s , fd:%d, recv_fd:%d, dlen:%d, slen:%d", __FILE__, __LINE__, 
				up_direct?"client":"remote", con->fd, peer->fd, peer->data_length, peer->sent_length);
		}
	}

}


