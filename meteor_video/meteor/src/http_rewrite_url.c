
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>



#include "meteor_process.h"  //meteor_cpystrn()
#include "http_rewrite_url.h"
#include "http_proxy.h"
#include "order.h"  //socks_order_t
#include "log.h"

//#include "msg.h"
//#include "misc.h"
#include "../lib/md5c.h"

typedef unsigned char u_char;

#define MAXSIZE 1024
#define REWRITE_URL_MAX_SIZE 1024



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

    meteor_str_t file_dir;
    meteor_str_t dir_1st_level;
    meteor_str_t file_path;
    meteor_str_t orignal_host_corp;

    socks_passwd_t *passwd;
//  meteor_str_t passwd;
    char  rewrite_url_buf[REWRITE_URL_MAX_SIZE];
    char *rewrite_url_pos;   
    //char *host_corp;    // if at_flag:3   
}rewrite_url_info_t;

static char *c_name[] = {
    "com",
    "edu",
    "cn",
    "net",
    "org",
    NULL
};


char* get_real_path( char *path ) // /path/../../real/path/file -> /real/path/file
{
    int count = 0;
    char *c, *p;

    for( c = p = path; *c != '\0';) {

        while ( *c == '/' ) {
            c++;
        }

        if( c[0] == '.' ) {

            if ( c[1] == '/' ) {
                c += 1;
                if( count == 0)
                    p = c;
                continue;

            } else if ( c[1] == '.' && c[2] == '/') {
                c += 2;
                count--;
                if(count <= 0) {
                    count = 0;
                    p = c;
                }
                continue;

            } else {
                while( *c != '/' && *c != '\0' && *c != '?' && *c != '#')
                    c++;
            }

        } else {
            while( *c != '/' && *c != '\0' && *c != '?' && *c != '#') 
                c++;
        }

        if (*c != '/')
            break;
        count++;
    }
    return p;
}

// cmp absolute_path("/path/to/file?key=value#fragment") directly: condition - not "/./" or "/../" for head
static int is_dir_1st_level_same(u_char *path_of_file,u_char *path_in_file) 
{
    u_char *s,*t;
    for ( s = path_of_file + 1,t = path_in_file + 1; *s == *t; s++,t++ ) {
        switch (*s) {
            case '/':
            case '?':
            case '#':
            case '\0':
                return 1;
        }
    }

    // if (dir_1st_level is "/") return 1; else return 0; can be default
    for (;;) {
        switch (*s++) {
            case '/':
                return 0;
            case '?':
            case '#':
            case '\0':
                return 1;
        }
    }
}

// not same corp: 0, same: 1 
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


static int generate_url(socks_worker_process_t *process, char *url, rewrite_url_info_t *info)
{
    /*TODO: passwd:HEX(MD5(OrderToken|orignal_host|orderKey)) */
    char *src,*dst;


    //int get_passwd_with_cache(socks_worker_process_t *process, socks_order_t *order, char *orderKey, char *addr, char *passwd)
    //char *passwd = "THIS_IS_PASSWD"; 
    char original_host[info->original_host.length+1];
    meteor_cpystrn(original_host,info->original_host.data,info->original_host.length+1);

    get_passwd_with_cache(process, info->order, original_host, &(info->passwd));
    for(dst=info->rewrite_url_pos,src=info->passwd->passwd;*src != '\0';*dst++ = *src++);
    *dst++ = '/';

    //  "original-host/path_to_file" 
    strcpy(dst, url + 7); // no "http://"

    strcpy(url, info->rewrite_url_buf); 
}

static int generate_url_from_relative(socks_worker_process_t *process, char *url, rewrite_url_info_t *info)
{

    /*TODO: HEX(MD5(OrderToken|orignal_host|orderKey)) */
    char *src,*dst;

    // char *order_token;
    //char *order_key;
    //meteor_str_t original_host; // domain
    //int get_passwd_with_cache(socks_worker_process_t *process, socks_order_t *order, char *orderKey, char *addr, char *passwd)
    //char *passwd = "THIS_IS_PASSWD"; 
    char original_host[info->original_host.length+1];
    meteor_cpystrn(original_host,info->original_host.data,info->original_host.length+1);

    get_passwd_with_cache(process, info->order, original_host, &(info->passwd));
    for(dst=info->rewrite_url_pos,src=info->passwd->passwd;*src != '\0';*dst++ = *src++);
    *dst++ = '/';

    //  "original_host"
    dst = meteor_cpystrn(dst,info->original_host.data,info->original_host.length + 1);

    char *path = dst;

    //  "path-to-file" e.g. "/" "/path/to/file"
    if ( *url == '?' ){
        dst = meteor_cpystrn(dst,info->file_path.data,info->file_path.length + 1);
    } else if(*url != '/') {
        dst = meteor_cpystrn(dst,info->file_dir.data,info->file_dir.length + 1);
    }
    strcpy(dst,url);

    char *r_path = get_real_path(path);
    if ( r_path != path ) {
        memmove( path, r_path, strlen(r_path) + 1 );
    }

    strcpy(url,info->rewrite_url_buf);
}

int url_has_scheme(const char *url)
{
    for (;;)
    {
        switch (*url++)
        {
            case ':':
                return 1;
            case '/':
            case '?':
            case '#':
            case '\0':
                return 0;
        }
    }
}

#define FIND_URL_CH(url)                                        \
    do {                                                        \
        char ch = *url;                                         \
        if (ch = '/' || ch = '?' || ch == '#' || ch == '\0' )   \
            break;                                              \
        url++;                                                  \
    } while(1)

// change *url:  url in m3u8 file? --> http://proxy_domain/meteorq/....
static int rewrite_url(socks_worker_process_t *process, char *url_in_file, rewrite_url_info_t *info)
{
    int len;
    
    if( url_has_scheme(url_in_file) || ( url_in_file[0] == '/' && url_in_file[1] == '/' ) )
    {
        /* absolute abbr
         * 
         * 1. scheme:...   -> http://...  , mailto:... , ...
         * 2. //...        -> default scheme
         *
         */
        meteor_str_t url_domain;
        meteor_str_t url_dir_1st_level; // "/" "/Dir_1st/"

        // domain... part 
        if (!strncmp(url_in_file, "http://", 7)) 
            url_domain.data = url_in_file + 7;
        else if ( url_in_file[0] == '/' ) // "//orignal-host..."
            url_domain.data = url_in_file + 2;
        else
            return 0;
    
        char *p = url_domain.data;
        for(;;p++) {
            char ch = *p;
            if (ch == '/' || ch == '?' || ch == '#' || ch == '\0')
                break;
        }//TODO:

        url_domain.length = p - url_domain.data;

        //
        switch(info->at_flag) {
            case HTTP_AT_FLAG_NONE:    
                break;
            case HTTP_AT_FLAG_FIRST_CHILD:
                //auto-info needs to modify
                if ( *p != '/' ) { //empty path:http://domain?key=value#fragment
                    break;
                }
                else {   // not empty path
                    url_dir_1st_level.data = p;

                    for(p++;;p++) {
                        char ch = *p;
                        if (ch == '/' || ch == '?' || ch == '#' || ch == '\0')
                            break;
                    } // TODO: duplicated code?

                    url_dir_1st_level.length = (*p == '/' ? p - url_dir_1st_level.data + 1 : 1 );           
                                  
                    if (url_dir_1st_level.length != info->dir_1st_level.length ||
                        strncmp(url_dir_1st_level.data,info->dir_1st_level.data,url_dir_1st_level.length) != 0 )
                    break;
                }

            case HTTP_AT_FLAG_SAME:
                if ( url_domain.length == info->original_host.length &&
                     strncmp( url_domain.data,info->original_host.data,url_domain.length) == 0 )
                {
                    generate_url(process, url_in_file,info); 
                }
                break;

            case HTTP_AT_FLAG_PARENT:
                if(is_domain_same_corp(&info->original_host,&url_domain)) {
                    generate_url(process, url_in_file,info);
                }
                break;

            case HTTP_AT_FLAG_ALL:
                {
                    meteor_str_t tmp_domain = info->original_host; 
                    info->original_host = url_domain;
                    generate_url(process, url_in_file, info);
                    info->original_host = tmp_domain;
                }
                break;

            default:
                return -1;
        }

        return 0;

    }   
    else {  
        /* relative abbr:has no domain part?
         *  
         * 1. #fragment     -> no  rewrite
         * 2. ?key=value    -> yes
         * 3. foo.html      -> yes
         * 4. dir1/foo.html -> yes
         * 5. /dir1/foo.html-> ... may no ??
         * 6. ../foo.html   -> TODO??
         * 
         */
        if (*url_in_file == '#')
            return 0;

        switch(info->at_flag) {
            case HTTP_AT_FLAG_NONE:    
                break;
            case HTTP_AT_FLAG_FIRST_CHILD:
                if(*url_in_file == '/') {
                    meteor_str_t url_dir_1st_level; // "/" "/Dir_1st/"
                    url_dir_1st_level.data = url_in_file;

                    char *p = url_dir_1st_level.data;
                    for(p++;;p++) {
                        char ch = *p;
                        if (ch == '/' || ch == '?' || ch == '#' || ch == '\0')
                            break;
                    } // TODO: ...?

                    url_dir_1st_level.length = (*p == '/' ? p - url_dir_1st_level.data + 1 : 1 );

                    if (url_dir_1st_level.length != info->dir_1st_level.length ||
                        strncmp(url_dir_1st_level.data,info->dir_1st_level.data,url_dir_1st_level.length) != 0 )                
                    break;
                }
            case HTTP_AT_FLAG_SAME:
            case HTTP_AT_FLAG_PARENT:
            case HTTP_AT_FLAG_ALL:
                generate_url_from_relative(process, url_in_file,info);
                break;
            default:
                return 1;
        }
        return 0;
    }         
}

static int init_rewrite_url_info(rewrite_url_info_t *info, socks_connection_t *con)
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

    //file_Dir:"/"  "/DirName/" ------------
    u_char *pos,*url_path,*slash_pos;
    
    if (h_info->request.dest_port_end)  
        url_path = h_info->request.dest_port_end + 1;
    else
        url_path = h_info->request.dest_host_end + 1;

    for (pos = url_path; pos <= h_info->request.real_uri_end; pos++)
    {
        char ch = *pos;
        if ( ch == '/') 
            slash_pos = pos;
        else if ( ch == '?' || ch == '#' /* || ch == '\0' */)
            break;
    }

    info->file_path = (meteor_str_t) { url_path, pos - url_path }; // /dir1/foo.html

    info->file_dir = ( pos ==  url_path ? (meteor_str_t){"",0} :  // empty url_path
        (meteor_str_t){url_path, slash_pos - url_path + 1 
    } ) ;

    
    //dir_1st_level
    if (info->at_flag == 1)
    {
        if ( info->file_dir.length <= 1) // empty url_path or  "/"
        {
            info->dir_1st_level = info->file_dir;
        }
        else
        {
            for (pos = url_path + 1; 
                 pos <= h_info->request.real_uri_end; 
                 pos++)
            {
                char ch = *pos;
                if ( ch == '/' || ch == '?' || ch == '#' /* || ch == '\0' */ )
                    break;
            }
            info->dir_1st_level = (meteor_str_t) { h_info->request.dest_host_end + 1,
                pos - h_info->request.dest_host_end };
        }
    }

    ///fixed_part:init info->rewrite_url_buf    ------------
    u_char *src,*dst;
    //  "http://"
    dst = info->rewrite_url_buf;
    dst = meteor_cpystrn(dst,"http://",8);

    // "meteor_host[:meteor_port]/"
    u_char *m_host_end;
    if ( h_info->request.header_host_start ) {
        src = h_info->request.header_host_start;
        m_host_end = h_info->request.header_port_end ? h_info->request.header_port_end : h_info->request.header_host_end;

    } else if ( h_info->request.host_start ) {
        src = h_info->request.host_start;
        m_host_end = h_info->request.port_end ? h_info->request.port_end : h_info->request.host_end;
    } else {
        sys_log(LL_ERROR,"[ %s:%d ] header line has no host");
        return -1;
    }

    for(;src <= m_host_end;src++,dst++) {
        *dst = *src;
    }
    *dst++ = '/';   

    //  "meteorq|2|1|1|orderToken|appID|"
    for(src = h_info->request.meteorq_start;
        src <= h_info->request.auth_info_app_end;
        src++,dst++) {
        *dst = *src;
    }
    *dst++ = '|';
    info->rewrite_url_pos = dst; 
    return 0;   
}

int init_htmlparser(htmlparser_ctx_ext_t *ctx_ext) {

    htmlparser_reset( ctx_ext->ctx );

    ctx_ext->inside_url = 0;
    ctx_ext->quoted = 0;
    ctx_ext->last_attr_type = 0;
}

int rewrite_url_in_html(socks_worker_process_t *process, socks_connection_t *con,http_response_t * response,
    htmlparser_ctx_ext_t *ctx_ext)
{
    sys_log(LL_DEBUG,"[ %s:%d ] ###REWRITE_HTML_START###",__FILE__ ,__LINE__);
    sys_log(LL_DEBUG,"[ %s:%d ] RECEVE LEN:%d,dlen:%d,slen:%d",__FILE__ ,__LINE__,con->data_length-con->sent_length,con->data_length,con->sent_length);

    u_char *const recved1 = con->buf + con->data_length;
    u_char *const r_end = response->rewrite_buf + HTTP_REWRITE_BUF_SIZE - 8 /* CRLF || CRLF0CRLRCRLF */;
    
    u_char *c_pos = con->buf + con->sent_length;     // |<-- parsed -->| parsed1..recved1 | .. end |
    u_char *r_pos = response->rewrite_buf + response->data_length;

    u_char *chunk,*content_data;

    if ( recved1 != c_pos && (r_end - r_pos > 10)) {
        chunk = r_pos;
        content_data = r_pos + 6; // HEX{4} CRLF    

    } else {
        return 0;
    }
    
    r_pos = content_data;

    rewrite_url_info_t info;
    init_rewrite_url_info(&info,con);
    

    for( ; c_pos < recved1 && r_pos < r_end ; c_pos++ ) {

      char c = *c_pos;
      htmlparser_parse_chr(ctx_ext->ctx, c);
    
      if(ctx_ext->last_attr_type == HTMLPARSER_ATTR_URI) {

          if( (htmlparser_is_attr_quoted(ctx_ext->ctx) || htmlparser_value_index(ctx_ext->ctx) != -1 )
              && htmlparser_attr_type(ctx_ext->ctx) == HTMLPARSER_ATTR_URI) {

                if(htmlparser_is_attr_quoted(ctx_ext->ctx))    ctx_ext->quoted = 1;

                ctx_ext->inside_url = 1;
                ctx_ext->url = htmlparser_value(ctx_ext->ctx);
          }
          else {
            if(ctx_ext->inside_url)  {

                if(ctx_ext->quoted) {
                  ctx_ext->quoted = 0;
                  *r_pos++ = c;//'\"' OR '\'';
                }

                const char *url_in_file = ctx_ext->url;
                while( *url_in_file == ' ')
                    url_in_file++;

                strcpy(ctx_ext->rewrite_url,url_in_file); // copy first
                rewrite_url(process, ctx_ext->rewrite_url, &info);

                int url_len = strlen( ctx_ext->rewrite_url );

                if (r_end - r_pos > url_len + 1 )
                {
                    r_pos = meteor_cpystrn(r_pos,ctx_ext->rewrite_url,url_len+1);
                    *r_pos++ = c;
                }
                else
                {
                    break;
                }
                ctx_ext->inside_url = 0;
                ctx_ext->last_attr_type = htmlparser_attr_type(ctx_ext->ctx);
            }
          }
         
      }
      else /*(ctx_ext->last_attr_type != HTMLPARSER_ATTR_URI)*/ {
            *r_pos++ = c;
            ctx_ext->last_attr_type = htmlparser_attr_type(ctx_ext->ctx);           
      }
    }

    int chunk_size = r_pos - content_data;
    if (chunk_size == 0 ) {
        return 0; // no modify response->data_length
    }
    u_char chunk_str[10];
    int len = sprintf(chunk_str,"%x"CRLF,chunk_size); // len exclude '\0' 
    strncpy(chunk,chunk_str,len);

    if ( len != 6 ) { // TODO: if sprintf failed?
        memmove(chunk + len, content_data, chunk_size);
        r_pos -= (6 - len);
    }

    r_pos = meteor_cpystrn(r_pos,CRLF,sizeof(CRLF)); // CRLF

    sys_log(LL_DEBUG,"[ %s:%d ] REWRITE LEN:%d",__FILE__ ,__LINE__,c_pos-(con->buf+con->sent_length));
    sys_log(LL_DEBUG,"[ %s:%d ] REWRITED LEN:%d,rdlen:%d,rslen:%d",__FILE__ ,__LINE__,r_pos-(response->rewrite_buf+response->data_length),r_pos - response->rewrite_buf,con->sent_length);
    
    int parsed_len = c_pos - (con->buf + con->sent_length);

    con->sent_length = c_pos - con->buf;
    response->data_length = r_pos - response->rewrite_buf; 

    sys_log(LL_DEBUG,"[ %s:%d ] ###REWRITE_HTML_END###",__FILE__ ,__LINE__);
    
    return parsed_len;
}

int rewrite_url_in_m3u8( socks_worker_process_t *process, socks_connection_t *con,http_response_t * response )
{
    //TODO: assert( con->buf not chunked);
    u_char *const recved1 = con->buf + con->data_length;
    u_char *const r_end = response->rewrite_buf + HTTP_REWRITE_BUF_SIZE - 8 /* CRLF || CRLF0CRLRCRLF */;
    
    u_char *c_pos = con->buf + con->sent_length;     // |<-- parsed -->| parsed1..recved1 | .. end |
    u_char *r_pos = response->rewrite_buf + response->data_length;
    u_char *line_start,*line_end;
    
    u_char *chunk,*content_data;

    if ( recved1 != c_pos && (r_end - r_pos > 10)) {
        chunk = r_pos;
        content_data = r_pos + 6; // HEX{4} CRLF    

    } else {
        return 0;
    }
    
    r_pos = content_data;

    rewrite_url_info_t info;
    init_rewrite_url_info(&info,con);

    *recved1 = '\n';
    for(;c_pos < recved1;) 
    {
        //should assert(convert_buf->pos < convert_buf->end)
        line_start = c_pos;            
        line_end = strchr(c_pos/*line_start*/,'\n'); //   LINE_END or RECVED1 or NULL(EOF?) 

        if ( ( line_end == recved1 &&  // NOT COMPLETED LINE
        (response->response_content_length - response->recv_body_length) > line_end - line_start ) ||  //TODO:if chunked
                ( line_end ?     //COMPLETED LINE
                ( r_end - r_pos < line_end - line_start ) :    //A REAL_LINE
                ( r_end - r_pos < strlen(c_pos) ) ) )          //EOF? '\0'
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

    int chunk_size = r_pos - content_data;
    if (chunk_size == 0 ) {
        return 0; // no modify response->data_length
    }
    u_char chunk_str[10];
    int len = sprintf(chunk_str,"%x"CRLF,chunk_size); // len exclude '\0' 
    strncpy(chunk,chunk_str,len);

    if ( len != 6 ) { // TODO: if sprintf failed?
        memmove(chunk + len, content_data, chunk_size);
        r_pos -= (6 - len);
    }

    int parsed_len = c_pos - (con->buf + con->sent_length);

    r_pos = meteor_cpystrn(r_pos,CRLF,sizeof(CRLF)); // CRLF
    con->sent_length = c_pos - con->buf;
    response->data_length = r_pos - response->rewrite_buf;
    
    return parsed_len;
}


int add_to_passwd_cache( socks_worker_process_t *process, socks_order_t *order,  socks_passwd_t *passwd)
{
    
    if (order->passwd_cache.size == 0)
        rb_tree_init_for_str_key( &order->passwd_cache );
    
    rb_node_t * node = rb_list_pop( &process->rb_node_pool );
    if( !node ){
        sys_log(LL_ERROR, "[ %s:%d ] no memory for passwd_cache rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
        return -1;
    }
    sys_log(LL_ERROR, "[ %s:%d ] no memory for passwd_cache rb_node, order_id:%s", __FILE__, __LINE__, order->order_id);
    node->key.pkey = (void *)passwd->domain;
    node->data = (void *)passwd;
    if (rb_tree_insert_node( &order->passwd_cache, node, 0 )< 0 )
        rb_list_add( &process->rb_node_pool, node );
    
    return 0;
}


int get_passwd_without_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, socks_passwd_t **passwd) {
    char  conbinedstr[1024];
    char  decrypt[16];
    char  hex[33];

    memset( conbinedstr, 0, sizeof(conbinedstr ) );
    memset( decrypt, 0, sizeof(decrypt ) );
    memset( hex, 0, sizeof(hex ) );

    char *orderKey = order->order_key;

    sprintf( conbinedstr, "%s|%s|%s", order->token, orderKey, addr);

    MD5_CTX md5;
    MD5Init(&md5);              
    MD5Update( &md5, conbinedstr, strlen((char *)conbinedstr) );
    MD5Final( &md5, decrypt );       
    MDString2Hex( decrypt, hex ); 

    //*passwd = strdup(hex);
    *passwd = passwd_pool_pop( process, order );
    strncpy((*passwd)->domain, addr, 256);
    strncpy((*passwd)->passwd, hex, 33);
    return 1;
}


int get_passwd_with_cache(socks_worker_process_t *process, socks_order_t *order, char *addr, socks_passwd_t **passwd) {
    
    rb_key_t key;
    rb_node_t *node, *next;

    key.pkey = addr;
    if (order->passwd_cache.size > 0)
    {
        node = rb_tree_search( &order->passwd_cache, &key );
        if( node ){
            *passwd = (socks_passwd_t *)node->data;
            if( *passwd ){
                sys_log(LL_DEBUG,"get passwd with cache: addr:%s,passwd:%s",addr,(*passwd)->passwd);
                return 1;
            }
        }
    }
    char *orderKey = order->order_key;
    get_passwd_without_cache(process, order, addr, passwd);
    if( add_to_passwd_cache( process, order, *passwd ) <0 ){
        passwd_pool_add( process, order, *passwd);
        return 0;
    }
    return 1;
}

int update_passwd_cache(socks_worker_process_t *process, socks_order_t *order) {

    struct rb_node *node;
    char *orderKey = order->order_key;
    node = rb_first( &order->passwd_cache );
    while( node ) {
        char *addr = node->key.pkey;
        get_passwd_without_cache(process, order, addr, node->data);
        node = rb_next(node);
        
    }
    return 1;
}

int delete_passwd_from_cache(socks_worker_process_t *process, socks_order_t *order, socks_passwd_t *passwd)
{
    rb_key_t key;
    struct rb_node *tmp = NULL;

    key.pkey = passwd->domain;
    tmp = rb_tree_delete( &order->passwd_cache, &key );
    if( tmp ) {
        rb_list_add( &process->rb_node_pool, tmp );
        return 1;
    }
    return 0;
}

