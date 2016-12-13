//#include <libavformat/avformat.h>
//#include <libavcodec/avcodec.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include "meteor_process.h"  //meteor_cpystrn()
#include "rewrite_url.h"
#include "http_proxy.h"
#include "order.h"  //socks_order_t

//#include "msg.h"
//#include "misc.h"
#include "../lib/md5c.h"

typedef unsigned char u_char;

#define MAXSIZE 1024
#define REWRITE_URL_MAX_SIZE 1024

typedef struct {
    char *data;
    int length;
}meteor_str_t;

typedef struct {
    int at_flag;
    int domain_flag;
    int auth_mode;

    //HEX(MD5(...))

    //char *order_token;
    //char *order_key;
    socks_order_t *order;

    meteor_str_t original_host; // domain
    meteor_str_t meteor_host;

    meteor_str_t m3u8_file_dir;

    meteor_str_t dir_1st_level;
    meteor_str_t orignal_host_corp;

    meteor_str_t passwd;
    char  rewrite_url_buf[REWRITE_URL_MAX_SIZE];
    char *rewrite_url_pos;   
    //char *host_corp;    // if at_flag:3   
}rewrite_url_info_t;

static char *c_name[]={
    "com",
    "edu",
    "cn",
    "net",
    "org",
    NULL
};

// error: -1, not same corp: 0, same: 1 
int is_domain_same_corp(meteor_str_t *visiting_domain,meteor_str_t *domain_in_file)
{
    assert(visiting_domain && domain_in_file );

    int len_v = visiting_domain->length;
    int len_f = domain_in_file->length;

    int dot_count = 0;

    char *v = visiting_domain->data + len_v;
    char *f = domain_in_file->data + len_f;

    while ( *--v == *--f )
    {
        if ( v == visiting_domain->data || f == domain_in_file->data)
            break;
        if ( *v == '.') 
            dot_count++;
    }

    if ( dot_count > 2)
        return 1;
    else if ( dot_count < 2)
        goto done;
    else
    {
        int i;

        if(*v == *f && len_v == len_f)
            return 1;

        char *cc = strchr(v,'.');
        char c_tmp[len_v];

        for( i=0,cc++; c_tmp[i] = *cc ; i++,cc++)
        {
            if(c_tmp[i] == '.' )
            {
                c_tmp[i] = '\0';
                break;
            }
        }

        for ( i = 0; c_name[i]; i++)
        {
            if(!strcmp(c_name[i],c_tmp)) //
            {
                break;
            }
        }

        if (c_name[i])
            goto done;
        else
            return 1;
    }

done: 
    if (*v != *f)
    {
        return 0;
    }
    else
    {
        if ( len_v == len_f ) 
            return 1;
        return v == visiting_domain->data ? *--f == '.' : *--v == '.';
    }
}
#if 0
int rewrite_meteorq(char *token, char *addr, char *key, struct meteorq *extension)
{
    //extension->domain_flag
    //extension->auth_info
    //extension->str

    /*
       鉴权模式（auth-mode）：后续可扩展其他模式，当前先实现默认模式1，其对应的鉴权信息auth-info格式为：
       订单token：默认为订单id；
       app标识：如安卓系统中的app包名或ios系统中为bundleid
       passwd：鉴权密码，算法为：HEX（MD5（token|orignal-host|orderKey））。注：采用orignal-host而没采用ORIGNAL_URI,是考虑到地址转换的性能。
       */

    char  conbinedstr[1024];
    char  decrypt[16];
    char  hex[33];

    memset( conbinedstr, 0, sizeof(conbinedstr ) );
    memset( decrypt, 0, sizeof(decrypt ) );
    memset( hex, 0, sizeof(hex ) );

    /*strcpy(conbinedstr, token);
      strcat(conbinedstr, addr);
      strcat(conbinedstr, key);*/
    sprintf( conbinedstr, "%s|%s|%s", token, key, addr);

    MD5_CTX md5;
    MD5Init(&md5);              
    MD5Update( &md5, conbinedstr, strlen((char *)conbinedstr) );
    MD5Final( &md5, decrypt );       
    MDString2Hex( decrypt, hex ); 

    strcpy( extension->auth_info, hex);
    sprintf(extension->str, "/meteorq.%d.%d.%d.%s/", 
            extension->at_flag,
            extension->domain_flag,
            extension->auth_mode,
            extension->auth_info);

    return 1;
}
#endif
int generate_url(socks_worker_process_t *process, char *url, rewrite_url_info_t *info)
{
    /*TODO: passwd:HEX(MD5(OrderToken|orignal_host|orderKey)) */
    char *src,*dst;


    //int get_md5_with_cache(socks_worker_process_t *process, socks_order_t *order, char *orderKey, char *addr, char *passwd)
    //char *passwd = "THIS_IS_PASSWD"; 
    get_md5_with_cache(process, info->order, info->original_host.data, info->passwd.data);
    for(dst=info->rewrite_url_pos,src=info->passwd.data;*src != '\0';*dst++ = *src++);
    *dst++ = '/';

    //  "original-host/path_to_file" 
    strcpy(dst, url + 7); // no "http://"

    strcpy(url, info->rewrite_url_buf); 
}

int generate_url_from_relative(socks_worker_process_t *process, char *url, rewrite_url_info_t *info)
{

    /*TODO: HEX(MD5(OrderToken|orignal_host|orderKey)) */
    char *src,*dst;

    // char *order_token;
    //char *order_key;
    //meteor_str_t original_host; // domain
    //int get_md5_with_cache(socks_worker_process_t *process, socks_order_t *order, char *orderKey, char *addr, char *passwd)
    //char *passwd = "THIS_IS_PASSWD"; 

    get_md5_with_cache(process, info->order, info->original_host.data, info->passwd.data);
    for(dst=info->rewrite_url_pos,src=info->passwd.data;*src != '\0';*dst++ = *src++);
    *dst++ = '/';

    //  "original_host"
    dst = meteor_cpystrn(dst,info->original_host.data,info->original_host.length + 1);

    //  "path-to-m3u8-file"
    if (*url != '/')
    {
        dst = meteor_cpystrn(dst,info->m3u8_file_dir.data,info->m3u8_file_dir.length + 1);
    }
    strcpy(dst,url);       
    strcpy(url,info->rewrite_url_buf);
}


// change *url:  url in m3u8 file? --> http://proxy_domain/meteorq/....
static int rewrite_url(socks_worker_process_t *process, char *url_in_file, rewrite_url_info_t *info)
{
    int len;
    enum at_flag_type{
        none,
        dir_lst_level,
        domain,
        corp,//??
        all
    };

    //absolute addr
    if (!strncmp(url_in_file, "http://", 7)) {
        char *p;
        meteor_str_t url_domain;
        meteor_str_t url_dir_1st_level; // "/" "/Dir_1st/"
        url_domain.data = url_in_file + 7;
        p = strchr(url_domain.data,'/');
        url_domain.length = p - url_domain.data;

        switch(info->at_flag) {
            case none:    
                break;
            case dir_lst_level:
                //auto-info needs to modify                   
                url_dir_1st_level.data = p;
                char *q = strchr(url_dir_1st_level.data + 1,'/');
                url_dir_1st_level.length = (q == NULL ? 1 : q - p + 1);

                if (url_dir_1st_level.length != info->dir_1st_level.length ||
                    strncmp(url_dir_1st_level.data,info->dir_1st_level.data,url_dir_1st_level.length) != 0 )
                break;

            case domain:
                if ( url_domain.length == info->original_host.length &&
                     strncmp( url_domain.data,info->original_host.data,url_domain.length) == 0 )
                {
                    generate_url(process, url_in_file,info); 
                }
                break;
            case corp:
                if(is_domain_same_corp(&info->original_host,&url_domain)) {
                    generate_url(process, url_in_file,info);
                }
                break;
            case all:
                generate_url(process, url_in_file, info);
                break;
            default:
                return 1;
        }
        return 0;
    } 
    else {
        switch(info->at_flag) {
            case none:    
                break;
            case dir_lst_level:
                if(*url_in_file == '/')
                {
                    meteor_str_t url_dir_1st_level; // "/" "/Dir_1st/"
                    url_dir_1st_level.data = url_in_file;
                    char *p = url_dir_1st_level.data;
                    char *q = strchr( p + 1,'/');
                    url_dir_1st_level.length = (q == NULL ? 1 : q - p + 1);

                    if (url_dir_1st_level.length != info->dir_1st_level.length ||
                        strncmp(url_dir_1st_level.data,info->dir_1st_level.data,url_dir_1st_level.length) != 0 )                
                    break;
                }
            case domain:
            case corp:
            case all:
                generate_url_from_relative(process, url_in_file,info);
                break;
            default:
                return 1;
        }
        return 0;
    }         
}



static void init_rewrite_url_info(rewrite_url_info_t *info, socks_connection_t *con)
{
    memset(info,0,sizeof(rewrite_url_info_t));
    http_info_t *h_info = con->session->http_info;
    //flag               
    info->at_flag = h_info->request.at_flag;
    info->domain_flag = h_info->request.domain_flag;
    info->auth_mode = h_info->request.auth_mode;

         
    info->order = con->session->order; // or session->order->token
    
    //original_host              
    info->original_host = (meteor_str_t){ h_info->request.dest_host_start,
        h_info->request.dest_host_end - h_info->request.dest_host_start +1};

    //meteor_host              
    info->meteor_host = (meteor_str_t){h_info->request.host_start,
        h_info->request.host_end - h_info->request.host_start +1};

    //m3u8_file_Dir:"/"  "/DirName/" ------------
    u_char *pos,*slash_pos;
    assert(h_info->request.dest_host_end[1] == '/');
    for (pos = h_info->request.dest_host_end + 1;
         pos <= h_info->request.real_uri_end; 
         pos++)
    {
        if ( *pos == '/') slash_pos = pos;
    }

    info->m3u8_file_dir = (meteor_str_t){h_info->request.dest_host_end + 1,
        slash_pos - h_info->request.dest_host_end
    };

    //dir_1st_level
    if (info->at_flag == 1)
    {
        if ( info->m3u8_file_dir.length == 1)
        {
            info->dir_1st_level = info->m3u8_file_dir;
        }
        else
        {
            for (pos = h_info->request.dest_host_end + 2; // first char MUST '/' ?
                 pos <= h_info->request.real_uri_end; 
                 pos++)
            {
                if ( *pos = '/') break;
            }
            info->dir_1st_level = (meteor_str_t) { h_info->request.dest_host_end + 1,
                pos - h_info->request.dest_host_end };
        }
    }

    ///fixed_part:init info->buf    ------------
    u_char *src,*dst;
    //  "http://"
    dst = info->rewrite_url_buf;
    strcpy(dst,"http://");

    //  "meteor-host/"
    for(src = h_info->request.host_start,dst += 7;
        src <= h_info->request.host_end;
        src++,dst++) {
        *dst = *src;
    }
    *dst++ = '/';

    //  "meteorq.2.1.1.orderToken|appID|"
    for(src = h_info->request.meteorq_start;
        src <= h_info->request.auth_info_app_end;
        src++,dst++) {
        *dst = *src;
    }
    *dst++ = '|';
    info->rewrite_url_pos = dst;    
}

int rewrite_url_in_file( socks_worker_process_t *process, socks_connection_t *con,http_response_t * response )
{

    u_char *const recved1 = con->buf + con->data_length;
    u_char *const r_end = response->rewrite_buf + HTTP_REWRITE_BUF_SIZE;
    
    u_char *c_pos = con->buf + con->parsed_length; 	 // |<-- parsed -->| parsed1..recved1 | .. end |
    u_char *r_pos = response->rewrite_buf + response->data_length;
    u_char *line_start,*line_end;
    
    rewrite_url_info_t info;
    init_rewrite_url_info(&info,con);

    *recved1 = '\n';
    for(;c_pos < recved1;) 
    {
        //should assert(convert_buf->pos < convert_buf->end)
        line_start = c_pos;            
        line_end = strchr(c_pos/*line_start*/,'\n'); //   LINE_END or RECVED1 or NULL(EOF?) 

        if ( line_end == recved1 ||  // NOT COMPLETED LINE
                line_end ?     //COMPLETED LINE
                ( r_end - r_pos < line_end - line_start ) :    //A REAL_LINE
                ( r_end - r_pos < strlen(c_pos) ) )              //EOF? '\0'
        {
            if(line_end - line_start > 4096/2) //如何判断单行过长？？
                return -1; //bug：若单行过长, 则无法按行解析，需设置一个长度值；
            break;  //若没有 足.够.的.缓存处理 完.整.的.一行数据，则parse end
        }

        if( *c_pos == '#')
        {
            do {
                *r_pos++ = *c_pos++; 
            }while(*c_pos != '\n');   // the *recv_buf->recved1 should be '\n'
        }
        else if ( *c_pos == '\n' || *c_pos == '\r' || *c_pos == ' ' || *c_pos == '\t')
        {                    
            *r_pos++ = *c_pos++; 
        }
        else
        {
            char url_in_file[MAXSIZE] ;    //.....temp....
            if ( sscanf(c_pos,"%[^\n]",url_in_file) ) //  https://???-----------
            {
                rewrite_url(process, url_in_file, &info);
                int len = strlen(url_in_file);
                if ( len < ( r_end - r_pos))
                {
                    strcpy(r_pos,url_in_file);
                    r_pos += len;
                    c_pos = line_end;
                }
                else
                {
                    break;
                }
            }
        }
    }
    con->parsed_length = c_pos - con->buf;
    response->data_length = r_pos - response->rewrite_buf;
    return 0;
}




// for TEST....
static void read_file(FILE* fp, char** output, int* length) {
#include <sys/stat.h>
    int fileno(FILE*);
    struct stat filestats;
    int fd = fileno(fp);
    fstat(fd, &filestats);
    *length = filestats.st_size;
    *output = malloc(*length + 1);
    int start = 0;
    int bytes_read;
    while ((bytes_read = fread(*output + start, 1, *length - start, fp))) {
        start += bytes_read;
    }
}

#if 0
//test
int main()
{
    int fd;
    char recv_buf[4096];
    char parse_buf[4096];

    fd = open("example1.m3u8",O_RDONLY);
    if (fd < 0) 
    {
        printf("File not found!\n");
        exit(EXIT_FAILURE);
    }

    //INIT　BUF ---------------------------------------------------
    recv_buf_t r;
    r.recved1 = r.parsed1 = r.start = recv_buf;
    r.end = recv_buf + sizeof(recv_buf) - 1;

    chgAddr_buf_t h;
    h.parsed1 = h.start = parse_buf;
    h.send = parse_buf;
    h.end = parse_buf + sizeof(parse_buf) - 1;

    char test_info[]=
        "GET http://meteor-host/meteorq.2.1.2.001|qq.com.com|d29adac2bdc027497fa3a327d8566320/www.example.com/music/winter-is-cold.m3u8 HTTP/1.1"; 
    struct meteor_http_request_s test_h_req;

   
    memset(&test_h_req, 0, sizeof(struct meteor_http_request_s));
    int length=strlen(test_info);
    int ret = meteor_http_parse_request_line(test_info,length,&test_h_req);

    /*test_h_req.at_flag = 2;
    test_h_req.domain_flag = 1;
    test_h_req.auth_mode = 1;

    test_h_req.host_start = strstr(test_info,"meteor-host");
    test_h_req.host_end = strstr(test_info,"t/meteorq");
    test_h_req.meteorq_start = strstr(test_info,"meteorq");

    test_h_req.real_uri_start = strstr(test_info,"www.example.com");
    test_h_req.real_uri_end = test_info + strlen(test_info); */

    for(;;)
    {
        // reset r.pos r.recved1
        if ( r.parsed1 == r.recved1)
        {
            r.parsed1 = r.recved1 = r.start;
        }
        else if ( r.recved1 == r.end /*or r.end - r.recved1 < 300 ???*/ ) 
        {
            int len = r.recved1 - r.parsed1;
            memmove(r.start,r.parsed1,len);
            r.parsed1 = r.start;
            r.recved1 = r.start + len;
        }

        int ret = read(fd,r.recved1,r.end - r.recved1); 

        if (ret == 0)
        {
            break; //EOF
        }
        else if (ret>0)
        {
            r.recved1 += ret;
        }
        else
        {
            printf("read error\n");
            exit(1);
        }

        convert_addr_in_file(&r,&h,&test_h_req,"ORDERKEY",NULL); // 逐行处理

        // send the parsed
        u_char *c = h.start;
        for(;c<h.parsed1;c++)
            putchar(*c); // send -> | start -> pos|....

        //reset h.send,h.pos after sented
        h.parsed1 = h.start;   
    }

    exit(1);
#endif

int add_to_md5_cache( socks_worker_process_t *process, socks_order_t *order, char *addr, char *passwd)
{
    if (order->md5_cache.size == 0)
        rb_tree_init_for_str_key( &order->md5_cache );

    rb_node_t * node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for md5_cache rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
        return -1;
    }
    node->key.pkey = addr;
    node->data = passwd;
    if (rb_tree_insert_node( &order->md5_cache, node, 0 )< 0 )
        rb_list_add( &process->rb_node_pool, node );
    return 0;
}

int get_md5_without_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, char *passwd) {
    char  conbinedstr[1024];
    char  decrypt[16];
    char  hex[33];

    memset( conbinedstr, 0, sizeof(conbinedstr ) );
    memset( decrypt, 0, sizeof(decrypt ) );
    memset( hex, 0, sizeof(hex ) );

    char *orderKey = order->order_key;
    /*strcpy(conbinedstr, token);
      strcat(conbinedstr, addr);
      strcat(conbinedstr, key);*/
    sprintf( conbinedstr, "%s|%s|%s", order->token, orderKey, addr);

    MD5_CTX md5;
    MD5Init(&md5);              
    MD5Update( &md5, conbinedstr, strlen((char *)conbinedstr) );
    MD5Final( &md5, decrypt );       
    MDString2Hex( decrypt, hex ); 

    strcpy(passwd, hex);
   
    return 1;
}

int get_md5_with_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, char *passwd) {
    
    rb_key_t key;
    rb_node_t *node, *next;

    key.pkey = addr;
    node = rb_tree_search( &order->md5_cache, &key );
    if( node ){
        passwd = (char *)node->data;
        if( passwd ){
            return 1;
        }
    }
    char *orderKey = order->order_key;
    get_md5_without_cache(process, order, addr, passwd);
    add_to_md5_cache(process, order, addr, passwd);
    return 1;
}

int update_md5_cache(socks_worker_process_t *process, socks_order_t *order) {

    struct rb_node *node;
    char *orderKey = order->order_key;
    node = rb_first( &order->md5_cache );
    while( node ) {
        char *addr = node->key.pkey;
        get_md5_without_cache(process, order, addr, node->data);
        node = rb_next(node);
        
    }
    return 1;
}