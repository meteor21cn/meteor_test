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
//#include "curl.h"
#include "hls_http.h"
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


// use sscanf ???
/*
对于http反向代理来说，如果客户端想要访问如下原始请求时： 
http://orignal-host/ORIGNAL_URI?queryString
合作方的服务端获取订单的相关信息，并生成反向代理地址,客户端从合作方的服务端获取反向代理地址，然后向流星网关发起请求：
http://meteor-host:port/meteor-req/orignal-host/ORIGNAL_URI?queryString
流星网关收到请求后，再去请求http://orignal-host/ORIGNAL_URI?queryString

流星网关的请求和鉴权信息meteor-req是以指定格式追加到原始url的前面位置。其中，meteor-req格式为：
meteorq.at-flag.domain-flag.auth-mode.auth-info
其中各部分之间用“.”隔开，各项含义如下：
标识串：固定为meteorq（小写）
地址转换标识(at-flag): 
0不转换，1只转换与当前请求的1级栏目相同的地址；2只转换与当前请求相同域名的地址；3只转换与当前请求相同父域名的地址；4转换全部可能的网址，包括外链。
域名转换标识(domain-flag): 0不转换，1转换域名；该标识只有当at-flag为非零时才有意义。 
鉴权模式（auth-mode）：后续可扩展其他模式，当前先实现默认模式1，其对应的鉴权信息auth-info格式为：
订单token：默认为订单id；
app标识：如安卓系统中的app包名或ios系统中为bundleid
passwd：鉴权密码，算法为：HEX（MD5（token|orignal-host|orderKey））。注：采用orignal-host而没采用ORIGNAL_URI,是考虑到地址转换的性能。

传递cookie有2种方案选择：
1）合作方在适当的情况下，修改自有程序，用url参数来替代cookie；
2）合作方如果在第一种方案不可行或难度太大的情况下，合作方可将domain-flag设为1，流星网关将根据网址中的域名查找事先配置的对应代理域名
（此域名通常为网址中的域名的子域名）
作为meteor-host进行地址转换，以便实现cookie的有效传递。但合作方需在程序中不使用js等脚本动态生成URL。
*/

/*
int rewrite_cycle()
{
     
    while(1) {
       
    }

    return 1;
}
*/

static char *c_name[]={
    "com",
    "edu",
    "cn",
    "net",
    "org",
    NULL
};

int is_domain_same_corp(char *visiting_domain, char *domain_in_file)
{
    if (visiting_domain == NULL || domain_in_file == NULL)
        return -1;

    int len_v = strlen(visiting_domain);
    int len_f = strlen(domain_in_file);

    //int short_len = len_f > len_v ? len_v : len_f;
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
        int in_list,i;

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

int pocceess_from_stream(char *stream, char *str, struct hls_media_playlist *me)
{
    int n = strlen(stream);
    while(stream[n] != '\n' && n >= 0)
    {
        //...
        n--;
    }
    if(n >= 0)
    {
        stream[n] = '\0';
        strcat(str, stream);
        strcpy(me->source, str);
        strcpy(str, "");
    }
    strcat(str, &stream[n+1]);

    return 1;
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

int generate_url(char *url, struct meteorq *extension, char *proxy_domain)
{
    char temp[MAXSIZE];
    strcpy(temp, "http://");
    strcat(temp, proxy_domain);

    //rewrite_meteorq(extension);
                
    strcat(temp, extension->str);  // 
    strcat(temp, url + 7); // strstr MUST NOT NULL ------------
    strcpy(url, temp);
}

int generate_url_from_relative(char *url, struct meteorq *extension, char *proxy_domain)
{
    char temp[MAXSIZE];
    strcpy(temp, "http://");
    strcat(temp, proxy_domain);
           
    //rewrite_meteorq(extension);
                
    strcat(temp, extension->str);
    strcat(temp, extension->original_domain);
    if(*url == '/') strcat(temp, "/");
    else            strcat(temp, "/../");
    strcat(temp, strstr(url, extension->dir_1st)); // seems same to the upper one
    strcpy(url, temp);
}


// change *url:  url in m3u8 file? --> http://proxy_domain/meteorq/....
static int rewrite_url(char **url, char *baseurl, char *proxy_domain)
{
    struct meteorq *extension = (struct meteorq *)malloc(sizeof(struct meteorq));
    int index = get_meteorq(baseurl, extension);

    enum at_flag_type{
        none,
        dir_lst_level,
        domain,
        corp,//??
        all
    };
    
    if (!strncmp(*url, "http://", 7)) {
        char url_domain[MAXSIZE];
        char dir_1st[MAXSIZE];
        sscanf(*url, "http://%[^/]/%[^/]", url_domain, dir_1st);

        switch(extension->at_flag) {
        case none:    
            break;
        case dir_lst_level:
            // auto-info needs to modify
            if(!strcmp(extension->dir_1st, dir_1st)) {
                generate_url(*url, extension, proxy_domain);
            }            
            break;
        case domain:
            if(!strcmp(extension->original_domain, url_domain)) {
                generate_url(*url, extension, proxy_domain);
            }   
            break;
        case corp:
            //father domain
            if(!is_domain_same_corp(extension->original_domain, url_domain)) {
                generate_url(*url, extension, proxy_domain);
            }
            break;
        case all:
            generate_url(*url, extension, proxy_domain);
            break;
        default:
            return 1;
        }
        return 0;
    }

    else //if (**url == '/') {
    {
        char dir_1st[MAXSIZE];
        if(**url == '/') sscanf(*url, "/%[^/]", dir_1st);
        else             sscanf(*url, "%[^/]", dir_1st);
        switch(extension->at_flag) {
        case none:    
            break;
        case dir_lst_level:
            if(!strcmp(extension->dir_1st, dir_1st)) {
                generate_url_from_relative(*url, extension, proxy_domain);
            }
            break;
        case domain:
        case corp:
        case all:
            generate_url_from_relative(*url, extension, proxy_domain);
            break;
        default:
            return 1;
        }
        return 0;
    }
    
}

//
static int extend_url(char **url, const char *baseurl)
{
    size_t max_length = strlen(*url) + strlen(baseurl) + 10;

    if (!strncmp(*url, "http://", 7) || !strncmp(*url, "https://", 8)) {
        return 0;
    }

    else if (**url == '/') {
        char *domain = malloc(max_length);
        strcpy(domain, baseurl);

        if (!sscanf(baseurl, "http://%[^/]", domain)) {
            sscanf(baseurl, "https://%[^/]", domain);
        }

        char *buffer = malloc(max_length);
        snprintf(buffer, max_length, "%s%s", domain, *url);
        *url = realloc(*url, strlen(buffer) + 1);
        strcpy(*url, buffer);
        free(buffer);
        free(domain);
        return 0;
    }
    
    else {
        // URLs can have '?'. To make /../ work, remove it.
        char *find_questionmark = strchr(baseurl, '?');
        if (find_questionmark) {
            *find_questionmark = '\0';
        }

        char *buffer = malloc(max_length);
        snprintf(buffer, max_length, "%s/../%s", baseurl, *url);
        *url = realloc(*url, strlen(buffer) + 1);
        strcpy(*url, buffer);
        free(buffer);
        return 0;
    }
}


int get_playlist_type(char *source)
{
    if (strncmp("#EXTM3U", source, 7) != 0) {
        //MSG_WARNING("Not a valid M3U8 file. Exiting.\n");
        return -1;
    }

    if (strstr(source, "#EXT-X-STREAM-INF")) {
        return 0;
    }

    return 1;
}

static int get_link_count(char *src)
{
    int linkcount = 0;

    while ((src = (strchr(src, '\n')))) {
        src++;
        if (*src == '#') {
            continue;
        }
        if (*src == '\0') {
            break;
        }
        linkcount++;
    }

    return linkcount;
}

static int media_playlist_get_media_sequence(char *source)
{
    int j = 0;
    char *p_media_sequence = strstr(source, "#EXT-X-MEDIA-SEQUENCE:");

    if (p_media_sequence) {
        if (sscanf(p_media_sequence, "#EXT-X-MEDIA-SEQUENCE:%d", &j) != 1) {
            //MSG_ERROR("Could not read EXT-X-MEDIA-SEQUENCE\n");
            return 0;
        }
    }
    return j;
}

static int media_playlist_get_links(struct hls_media_playlist *me, char *proxy_domain)
{
    int ms_init = media_playlist_get_media_sequence(me->source);
    struct hls_media_segment *ms = me->media_segment;
    char *src = me->source;

    for (int i = 0; i < me->count; i++) {
        ms[i].url = malloc(strlen(src));
    }
    
    for (int i = 0; i < me->count; i++) {
        while ((src = (strchr(src, '\n')))) {
            src++;
            if (*src == '\n') {
                continue;
            }
            if (*src == '#') {
                continue;
            }
            if (*src == '\0') {
                goto finish;
            }
            if (sscanf(src, "%[^\n]", ms[i].url) == 1) {
                ms[i].sequence_number = i + ms_init;
                break;
            }
        }
    }

finish:
    // Extend the individual urls.
    for (int i = 0; i < me->count; i++) {
        rewrite_url(&ms[i].url, me->url, proxy_domain);
        //extend_url(&ms[i].url, me->url);
    }
    return 0;
}

int handle_hls_media_playlist(struct hls_media_playlist *me)
{
    //get_data_from_url(me->url, &me->source, NULL, STRING);

    if (get_playlist_type(me->source) != MEDIA_PLAYLIST) {
        return 1;
    }
    me->count = get_link_count(me->source);
    me->media_segment = malloc(sizeof(struct hls_media_segment) * me->count);

//    if (media_playlist_get_links(me)) 

    /*{
        //MSG_ERROR("Could not parse links. Exiting.\n");
        return 1;
    }
    */
    return 0;
}

static int master_playlist_get_bitrate(struct hls_master_playlist *ma)
{
    struct hls_media_playlist *me = ma->media_playlist;

    char *src = ma->source;

    for (int i = 0; i < ma->count && src; i++) {
        if ((src = strstr(src, "BANDWIDTH="))) {
            if ((sscanf(src, "BANDWIDTH=%u", &me[i].bitrate)) == 1) {
                src++;
                continue;
            }
        }
    }
    return 0;
}

static int master_playlist_get_links(struct hls_master_playlist *ma)
{
    struct hls_media_playlist *me = ma->media_playlist;
    char *src = ma->source;

    for (int i = 0; i < ma->count; i++) {
        me[i].url = malloc(strlen(src));
    }

    for (int i = 0; i < ma->count; i++) {
        while ((src = (strchr(src, '\n')))) {
            src++;
            if (*src == '#' || *src == '\n') {
                continue;
            }
            if (*src == '\0') {
                goto finish;
            }
            if (sscanf(src, "%[^\n]", me[i].url) == 1) {
                break;
            }
        }
    }

finish:
    for (int i = 0; i < ma->count; i++) {
        extend_url(&me[i].url, ma->url);
    }
    return 0;
}

int handle_hls_master_playlist(struct hls_master_playlist *ma)
{
    ma->count = get_link_count(ma->source);
    ma->media_playlist = malloc(sizeof(struct hls_media_playlist) * ma->count);
    if (master_playlist_get_links(ma)) {
        //MSG_ERROR("Could not parse links. Exiting.\n");
        return 1;
    }

    for (int i = 0; i < ma->count; i++) {
        ma->media_playlist[i].bitrate = 0;
    }

    if (master_playlist_get_bitrate(ma)) {
        //MSG_ERROR("Could not parse bitrate. Exiting.\n");
        return 1;
    }
    return 0;
}

void print_hls_master_playlist(struct hls_master_playlist *ma)
{
    int i;
    //MSG_VERBOSE("Found %d Qualitys\n\n", ma->count);
    for (i = 0; i < ma->count; i++) {
        //MSG_PRINT("%d: Bandwidth: %d\n", i, ma->media_playlist[i].bitrate);
    }
}

/*
int download_hls(struct hls_media_playlist *me)
{
    //MSG_VERBOSE("Downloading %d segments.\n", me->count);

    char filename[MAX_FILENAME_LEN];

    if (hls_args.custom_filename) {
        strcpy(filename, hls_args.filename);
    } else {
        strcpy(filename, "000_hls_output.ts");
    }

    if (access(filename, F_OK) != -1) {
        if (hls_args.force_overwrite) {
            if (remove(filename) != 0) {
                MSG_ERROR("Error overwriting file");
                exit(1);
            }
        } else {
            char userchoice;
            //MSG_PRINT("File already exists. Overwrite? (y/n) ");
            scanf("\n%c", &userchoice);
            if (userchoice == 'y') {
                if (remove(filename) != 0) {
                    //MSG_ERROR("Error overwriting file");
                    exit(1);
                }
            } else {
                //MSG_WARNING("Choose a different filename. Exiting.\n");
                exit(0);
            }
        }
    }

    FILE *pFile = fopen(filename, "wb");

    for (int i = 0; i < me->count; i++) {
        //MSG_PRINT("Downloading part %d\n", i);
        struct ByteBuffer seg;
        seg.len = (int)get_data_from_url(me->media_segment[i].url, NULL, &(seg.data), BINARY);
        fwrite(seg.data, 1, seg.len, pFile);
        free(seg.data);
    }
    fclose(pFile);
    return 0;
}
*/

void media_playlist_cleanup(struct hls_media_playlist *me)
{
    free(me->source);
    free(me->url);
    for (int i = 0; i < me->count; i++) {
        free(me->media_segment[i].url);
    }
    free(me->media_segment);
}

void master_playlist_cleanup(struct hls_master_playlist *ma)
{
    free(ma->source);
    free(ma->url);
    free(ma->media_playlist);
}


typedef struct {
    u_char *start; // start of buf
    u_char *end;  // end of buf

    u_char *parsed1; //  parsed+1
    u_char *recved1;
}recv_buf_t;

typedef struct {
    u_char *start;
    u_char *end;

    u_char *pos;
    u_char *send;
}chgAddr_buf_t;


int chgAddr_long_file( recv_buf_t *recv,chgAddr_buf_t *handle,char *visit_url_info /* contains:at_flag, domain_flag,domain,dir1st... */)
{
    //ASSERT(DOMAIN_FLAG != 0 && AT_FLAG != 0);
        u_char *const recved1 = recv->recved1;
        u_char *pos = recv->parsed1;  // |<-- parsed -->| parsed1..recved1 | .. end|
        u_char *line_start,*line_end;

        *recved1 = '\n';
        for(;pos < recved1;) 
        {
            //should assert(handle->pos < handle->end)
            line_start = pos;            
            line_end = strchr(pos/*line_start*/,'\n'); //   LINE_END or RECVED1 or NULL(EOF?) 

            if ( line_end == recved1 ||  // NOT COMPLETED LINE
                 line_end ?     //COMPLETED LINE
                 ( handle->end - handle->pos < line_end - line_start ) :    //A REAL_LINE
                 ( handle->end - handle->pos < strlen(pos) ) )              //EOF? '\0'
            {
                if(line_end - line_start > 4096/2) //如何判断单行过长？？
                    return -1; //bug：若单行过长, 则无法按行解析，需设置一个长度值；
                break;  //若没有 足.够.的.缓存处理 完.整.的.一行数据，则parse end
            }

            if( *pos == '#')
            {
                do {
                   *handle->pos++ = *pos++; 
                }while(*pos != '\n');   // the *recv->recved1 should be '\n'
            }
            else if ( *pos == '\n' || *pos == '\r' || *pos == ' ' || *pos == '\t')
            {                    
                *handle->pos++ = *pos++; 
            }
            else
            {
                char url_in_file[666] = "http://";    //.....temp....
                if ( sscanf(pos,"http://%[^\n]",&url_in_file[7]) ) //  https://???-----------
                {
                    #define AT_FLAG "2"    // 0 no change 1 dir1  2 domain 3 parent domain 4 all
                    #define DOMAIN_FLAG "1" // 0 no 1 yes
                    #define AUTH_MODE  "1"  

                    char *url = url_in_file;
                    char *base_url = "/meteorq."AT_FLAG"."DOMAIN_FLAG"."AUTH_MODE
                        ".auth-info-token-appid-passwd/www.example.com/dir1/ORGRINAL-URI";
                    char *proxy_domain = "meteor-host";

                    rewrite_url(&url, base_url, proxy_domain);

                    //printf("url:%s\n============\n",url_in_file);

                    int len = strlen(url);
                    if ( len < ( handle->end - handle->pos))
                    {
                        strcpy(handle->pos,url);
                        handle->pos += len;
                        pos = line_end;
                    }
                    else
                    {
                        break;
                    }

                    #undef AT_FLAG
                    #undef DOMAIN_FLAG
                    #undef AUTH_MODE
                }
                else
                {
                    //relative url? https? others? copy ?-----------------
                    do {
                     *handle->pos++ = *pos++; 
                    }while(*pos != '\n');   // the *recv->recved1 should be '\n'              
                }
            }
        }

        recv->parsed1 = pos;
       // handle->pos,end,start,last = ???
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
    h.pos = h.start = parse_buf;
    h.send = parse_buf;
    h.end = parse_buf + sizeof(parse_buf) - 1;

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

    chgAddr_long_file(&r,&h,NULL); // 逐行处理

    // send the parsed
    u_char *c = h.start;
    for(;c<h.pos;c++)
            putchar(*c); // send -> | start -> pos|....

    //reset h.send,h.pos after sented
    h.pos = h.start;   
}

exit(1);
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
}
