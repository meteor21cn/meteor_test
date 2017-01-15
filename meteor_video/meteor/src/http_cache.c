#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sockd.h"
#include "http_cache.h"
#include "meteor_process.h"  //meteor_cpystrn()
#include "http_proxy.h"
#include "order.h"  //socks_order_t
#include "log.h"
#include "../lib/md5c.h"

static int convert_to_md5(meteor_str_t uri, char *filename) {

	char  decrypt[16];
    char  hex[33];
    memset( decrypt, 0, sizeof(decrypt ) );
    memset( hex, 0, sizeof(hex ) );

	MD5_CTX md5;
    MD5Init(&md5);              
    MD5Update( &md5, uri.data, uri.length );
    MD5Final( &md5, decrypt );       
    MDString2Hex( decrypt, hex ); 
    strncpy(filename, hex, 33);
	return 1;
}

int save_to_cache_file(socks_worker_process_t *process, meteor_str_t uri, socks_connection_t *con)
{
	
	static char last_uri[1024];
	static int fd = -1;
	if(strncmp(last_uri, uri.data, uri.length))	{
		strncpy(last_uri, uri.data, uri.length);
		if(fd != -1)	{
			close(fd);
		}
		char filename[33];
		char file_path[1024] = "../cache/";
		convert_to_md5(uri, filename);
		strncat(file_path, filename, 33);
		fd = open(file_path, O_CREAT | O_WRONLY | O_APPEND);		//handle error
	}
	u_char *c_pos = con->buf + con->sent_length; 
	int w_length = con->data_length - con->sent_length;
	if(w_length > 0)
		write(fd, c_pos, w_length);				//handle error
	
	return 1;
}