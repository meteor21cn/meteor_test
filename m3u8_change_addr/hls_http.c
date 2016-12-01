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
//#include "curl.h"
#include "hls_http.h"
#include "http.h"
//#include "msg.h"
//#include "misc.h"
#include "lib/md5c.c"

typedef unsigned char u_char;

#define MAXSIZE 1024
struct meteorq
{
    //meteorq.at-flag.domain-flag.auth-mode.auth-info
    int at_flag;
    int domain_flag;
    int auth_mode;
    char auth_info[MAXSIZE];
    char str[MAXSIZE];

    char original_domain[MAXSIZE];
    char dir_1st[MAXSIZE];
};
typedef struct {
    char *str;
    //char *end; //??
    int length;
}meteor_str_t;

typedef struct {
    char *start;
    char *pos;   
    int   len;
}url_buf_t;

typedef struct {
    u_char *start; // start of buf
    u_char *end;  // end of buf

    u_char *parsed1; //  parsed+1
    u_char *recved1;
}recv_buf_t;

typedef struct {
    u_char *start;
    u_char *end;

    u_char *parsed1;
    u_char *send;
}chgAddr_buf_t;

typedef struct {
    int at_flag;
    int domain_flag;
    int auth_mode;

    //HEX(MD5(...))
    char *order_token;
    char *original_host;
    char *order_key;
   
    char *meteor_host;


    char *m3u8_file_dir;
    char *fixed_part; // first: "http://meteor-host/meteorq.2.1.1.order_token|appID|" 

    url_buf_t buf;

    char *m3u8_dir1st;  // if at_flag:1
    //char *host_corp;    // if at_flag:3   
}chgAddr_info_t;

static char *c_name[]={
    "com",
    "edu",
    "cn",
    "net",
    "org",
    NULL
};

// error: -1, not same corp: 0, same: 1 
int is_domain_same_corp(char *visiting_domain, char *domain_in_file)
{
    assert(visiting_domain && domain_in_file );

    int len_v = strlen(visiting_domain);
    int len_f = strlen(domain_in_file);

    int dot_count = 0;

    char *v = visiting_domain + len_v;
    char *f = domain_in_file + len_f;

    while ( *--v == *--f )
    {
        if ( v == visiting_domain || f == domain_in_file)
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
        return v == visiting_domain ? *--f == '.' : *--v == '.';
    }
}

int get_meteorq(char *proxy_url, struct meteorq *extension)
{
    //char *proxy_url = "http://meteorq.1.2.abjkjkjkdfjkjk";
    int ret = sscanf(proxy_url,"/meteorq.%d.%d.%d.%[^/]/%[^/]/%[^/]",
            &extension->at_flag,
            &extension->domain_flag,
            &extension->auth_mode,
            extension->auth_info,
            extension->original_domain,
            extension->dir_1st);

    if ( ret != 6)
    {
        return -1;
    }

    sprintf(extension->str, "/meteorq.%d.%d.%d.%s/", 
            extension->at_flag,
            extension->domain_flag,
            extension->auth_mode,
            extension->auth_info);

    return 0;
}


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

int generate_url(char *url, chgAddr_info_t *info)
{

#if 0
    char newUrl[MAXSIZE];
    char *src,*dst;
    //  "http://"
    strcpy(newUrl,"http://");

    //  "proxy-host/"
    for(src = h_req_info->host_start,dst = newUrl+7;
        src <= h_req_info->host_end;
        src++,dst++) {
        *dst = *src;
    }
    *dst++ = '/';

    //  "meteorq.2.1.1.orderToken_appID_******/"
    for(src = h_req_info->meteorq_start;
        src <= h_req_info->auth_info_app_end;
        src++,dst++) {
        *dst = *src;
    }
#endif
    /*TODO: passwd:HEX(MD5(OrderToken|orignal_host|orderKey)) */
    char *src,*dst;

    char *passwd = "THIS_IS_PASSWD"; 

    for(dst=info->buf.pos,src=passwd;*src != '\0';*dst++ = *src++);
    *dst++ = '/';

    //  "original-host/path_to_file" 
    strcpy(dst, url + 7); // no "http://"

    strcpy(url, info->buf.start);
}

int generate_url_from_relative(char *url, chgAddr_info_t *info)
{
#if 0
    char newUrl[MAXSIZE];
    //  "http://"
    strcpy(newUrl,"http://");

    //  "proxy-host/"
    for(src = h_req_info->host_start,dst = newUrl+7;
        src <= h_req_info->host_end;
        src++,dst++) {
        *dst = *src;
    }
    *dst++ = '/';

    //  "meteorq.2.1.1.orderToken_appID_******/"
    for(src = h_req_info->meteorq_start;
        src <= h_req_info->auth_info_app_end;
        src++,dst++) {
        *dst = *src;
    }
#endif
    /*TODO: HEX(MD5(OrderToken|orignal_host|orderKey)) */
    char *src,*dst;

    char *passwd = "THIS_IS_PASSWD"; 

    for(dst=info->buf.pos,src=passwd;*src != '\0';*dst++ = *src++);
    *dst++ = '/';

    //  "original_host"
    for(src=info->original_host;*src != '\0';*dst++ = *src++);

    //  "path-to-m3u8-file"
    if (*url != '/')
    {
        for(src=info->m3u8_file_dir;*src != '\0';*dst++ = *src++);// "/m3u8_file_Dir/"
    }
    strcpy(dst,url);       
    strcpy(url,info->buf.start);
}


// change *url:  url in m3u8 file? --> http://proxy_domain/meteorq/....
static int rewrite_url(char **url_in_file, chgAddr_info_t *info, struct meteor_http_request_s *h_req_info)
{
    enum at_flag_type{
        none,
        dir_lst_level,
        domain,
        corp,//??
        all
    };

    //absolute addr
    if (!strncmp(*url_in_file, "http://", 7)) {
        char url_domain[MAXSIZE];
        char dir_1st[MAXSIZE];
        sscanf(*url_in_file, "http://%[^/]/%[^/]", url_domain, dir_1st);

        switch(h_req_info->at_flag) {
            case none:    
                break;
            case dir_lst_level:
                //auto-info needs to modify
                if(!strcmp(info->m3u8_dir1st, dir_1st) && !strcmp(info->original_host, url_domain)) {
                    generate_url(*url_in_file, info);
                }            
                break;
            case domain:
                if(!strcmp(info->original_host, url_domain)) {
                    generate_url(*url_in_file, info);
                }   
                break;
            case corp:
                //father domain
                // if(extension->original_domain == NULL || url_domain == NULL)
                //   break;
                if(is_domain_same_corp(info->original_host, url_domain)) {
                    generate_url(*url_in_file,info);
                }
                break;
            case all:
                generate_url(*url_in_file, info);
                break;
            default:
                return 1;
        }
        return 0;
    } 
    else {
        char dir_1st[MAXSIZE];
        if(**url_in_file == '/') sscanf(*url_in_file, "/%[^/]", dir_1st);
        else             sscanf(*url_in_file, "%[^/]", dir_1st);
        switch(h_req_info->at_flag) {
            case none:    
                break;
            case dir_lst_level:
                // if(!strcmp(info->original_host, dir_1st)) {
                //     generate_url_from_relative(*url_in_file, extension, proxy_domain);
                // }
                // break;
            case domain:
            case corp:
            case all:
                generate_url_from_relative(*url_in_file,info);
                break;
            default:
                return 1;
        }
        return 0;
    }
         
}



void init_info(chgAddr_info_t *info, struct meteor_http_request_s *h_req_info)
{
    //flag                         ------------
    info->at_flag = h_req_info->at_flag;
    info->domain_flag = h_req_info->domain_flag;
    info->auth_mode = h_req_info->auth_mode;

    //order_token                  ------------
    info->order_token = "ORDERTOKEN";
    //original_host                ------------
    info->original_host = "ORIGINSL_HOST";
    //order_key                    ------------
    info->order_key = "ORDER_KEY";
    //meteor_host                  ------------
    info->meteor_host = "METEOR_HOST";
    //m3u8_file_Dir:"/""/DirName/" ------------
    info->m3u8_file_dir = "/m3u8_file_dir/";
    //m3u8_dir1st
    if (info->at_flag == 1)
        info->m3u8_dir1st = "/m3u8_file_dir/";
    else
        info->m3u8_dir1st = NULL;

    //fixed_part:init info->buf    ------------
    char *src,*dst;
    //  "http://"
    dst = info->buf.pos;
    strcpy(dst,"http://");

    //  "proxy-host/"
    for(src = h_req_info->host_start,dst += 7;
        src <= h_req_info->host_end;
        src++,dst++) {
        *dst = *src;
    }
    *dst++ = '/';

    //  "meteorq.2.1.1.orderToken_appID/"
    for(src = h_req_info->meteorq_start;
        src <= h_req_info->auth_info_app_end;
        src++,dst++) {
        *dst = *src;
    }
    info->buf.pos = dst;

    //*dst = '\0';
    


}
int convert_addr_in_file( recv_buf_t *recv_buf,chgAddr_buf_t *convert_buf,
    struct meteor_http_request_s *h_req_info,
    char *orderKey, 
    char *visit_url_info /* contains:at_flag, domain_flag,domain,dir1st... */)
{
    assert(h_req_info->at_flag != 0 && h_req_info->domain_flag != 0);

    u_char *const recved1 = recv_buf->recved1;
    u_char *const c_end = convert_buf->end;
    u_char *r_pos = recv_buf->parsed1; 	 // |<-- parsed -->| parsed1..recved1 | .. end |
    u_char *c_pos = convert_buf->parsed1;
    u_char *line_start,*line_end;
    
    char url_buf[MAXSIZE];
    chgAddr_info_t info;
    info.buf.start = info.buf.pos = &url_buf[0];
    info.buf.len = MAXSIZE;

    init_info(&info,h_req_info);

    *recved1 = '\n';
    for(;r_pos < recved1;) 
    {
        //should assert(convert_buf->pos < convert_buf->end)
        line_start = r_pos;            
        line_end = strchr(r_pos/*line_start*/,'\n'); //   LINE_END or RECVED1 or NULL(EOF?) 

        if ( line_end == recved1 ||  // NOT COMPLETED LINE
                line_end ?     //COMPLETED LINE
                ( c_end - c_pos < line_end - line_start ) :    //A REAL_LINE
                ( c_end - c_pos < strlen(r_pos) ) )              //EOF? '\0'
        {
            if(line_end - line_start > 4096/2) //如何判断单行过长？？
                return -1; //bug：若单行过长, 则无法按行解析，需设置一个长度值；
            break;  //若没有 足.够.的.缓存处理 完.整.的.一行数据，则parse end
        }

        if( *r_pos == '#')
        {
            do {
                *c_pos++ = *r_pos++; 
            }while(*r_pos != '\n');   // the *recv_buf->recved1 should be '\n'
        }
        else if ( *r_pos == '\n' || *r_pos == '\r' || *r_pos == ' ' || *r_pos == '\t')
        {                    
            *c_pos++ = *r_pos++; 
        }
        else
        {
            char url_in_file[MAXSIZE] ;    //.....temp....
            if ( sscanf(r_pos,"%[^\n]",url_in_file) ) //  https://???-----------
            {
                char *url_f = url_in_file;
                rewrite_url(&url_f, &info, h_req_info);
                int len = strlen(url_f);
                if ( len < ( c_end - c_pos))
                {
                    strcpy(c_pos,url_f);
                    c_pos += len;
                    r_pos = line_end;
                }
                else
                {
                    break;
                }
            }
        }
    }
    recv_buf->parsed1 = r_pos;
    convert_buf->parsed1 = c_pos;
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

    //char buf[MAXSIZE]="GET http://172.18.12.18/meteorq.0.0.2.001"
    //"|qq.com.com|d29adac2bdc027497fa3a327d8566320/127.0.0.1:9999"
    //" HTTP/1.1\r\nContent-length:8888\r\nUser-Agent: Mozilla/5.0"
    //" (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.8.0\r\nHost: www.baidu.com:443\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n";
    
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
    #if 0
    //printf("%s\n",input);
    char myurl[][4096]= {
        "http://www.example.com/low.m3u8",
        "http://www.example.com/high.m3u8",
        "http://www.example.com/abcdef.mp3",

        "http://sameparent1.example.com/low.m3u8",
        "http://sameparent2.example.com/low.m3u8",
        "http://xxx.sameparent1.example.com/low.m3u8",
        "http://yyy.sameparent1.example.com/low.m3u8",

        "http://www.example.com/dir1/low.m3u8",
        "http://www.example.com/dir1.1/low.m3u8",
        "http://www.example.com/dir1.2/low.m3u8",
        "http://www.example.com/dir1/dir2/low.m3u8",
        "http://www.example.com/dir1/dir3/low.m3u8"
    };
    int num = sizeof(myurl)/sizeof(myurl[0]);

#define AT_FLAG "1"    // 0 no change 1 dir1  2 domain 3 parent domain 4 all
#define DOMAIN_FLAG "1" // 0 no 1 yes
#define AUTH_MODE  "1"  

    for(int i=0;i<num;i++)
    {
        char *url = myurl[i];
        char *base_url = "/meteorq."AT_FLAG"."DOMAIN_FLAG"."AUTH_MODE
            ".auth-info-token-appid-passwd/www.example.com/dir1/ORGRINAL-URI";
        char *proxy_domain = "meteor-host";
        rewrite_url(&url, base_url, proxy_domain);
        printf("%s\n", url);
    }


    //free(input);
    //fclose(fp);
    return 0;
    #endif
}
