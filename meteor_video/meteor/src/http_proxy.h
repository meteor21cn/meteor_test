#ifndef _HTTP_PROXY_H_
#define _HTTP_PROXY_H_

#include "meteor.h"
#include "sockd.h"
#include "meteor_auth.h"
#include "http_auth.h"
#include "http_parse.h"
#include "http_transform.h"

#define  HTTP_PARSE_OK              0
#define  HTTP_PARSE_ERROR               -1

#define  HTTP_PROXY_MODE_FORWORD            1
#define  HTTP_PROXY_MODE_REVERSE            2
#define  HTTP_PROXY_MODE_TUNNEL         3

#define HTTP_URI_MAX_LEN                2048
#define X_METEORS_LEN               128


#define  MET_HTTP_UNKNOWN               0x0000
#define  MET_HTTP_CONNECT               0X0001
#define  MET_HTTP_GET                   0x0002
#define  MET_HTTP_HEAD              0x0004
#define  MET_HTTP_POST              0x0008
#define  MET_HTTP_PUT                   0x0010
#define  MET_HTTP_DELETE                0x0020
#define  MET_HTTP_MKCOL             0x0040
#define  MET_HTTP_COPY              0x0080
#define  MET_HTTP_MOVE              0x0100
#define  MET_HTTP_OPTIONS               0x0200
#define  MET_HTTP_PROPFIND              0x0400
#define  MET_HTTP_PROPPATCH             0x0800
#define  MET_HTTP_LOCK              0x1000
#define  MET_HTTP_UNLOCK                0x2000
#define  MET_HTTP_PATCH             0x4000
#define  MET_HTTP_TRACE             0x8000


#define  HTTP_VERSION_10                1000
#define  HTTP_VERSION_11                1001

#define HTTP_REQUSET_HEADER_MAX_LENGTH      4096
#define HTTP_REWRITE_BUF_SIZE           8192

#define HTTP_REQUSET_FIELD_HOST         "Host:"
#define HTTP_REQUSET_FIELD_PROXY_CONNECTION "Proxy-Connection:"
#define HTTP_REQUSET_FIELD_XMETEOR          "X-Meteor:"
#define HTTP_REQUSET_FIELD_XMETEORQ     "X-Meteorq:"
#define HTTP_REQUSET_FIELD_METEORQ      "meteorq"

#define HTTP_RESPONSE_FIELD_METEORS     "X-Meteors:"
#define HTTP_RESPONSE_FIELD_TIME            "Date:"
#define HTTP_RESPONSE_FIELD_SERVER          "Server:"
#define HTTP_RESPONSE_FIELD_LOCATION        "Location:"
#define HTTP_RESPONSE_FIELD_PROXY_AGENT     "Proxy-agent:"

#define HTTP_DEFINE_PORT                80

#define LF                       '\n'
#define CR                       '\r'
#define CRLF                        "\r\n"
#define CRLFCRLF                    "\r\n\r\n"

#define HTTP_CODE_MOVE_TEMPORARY            "302"
#define HTTP_CODE_UNAUTHORIZED          "407"
#define HTTP_CODE_NOT_FOUND         "404"
#define HTTP_CODE_CONNECT_ESTA          "200"

#define HTTP_TEXT_MOVE_TEMPORARY            "MOVE TEMPORARY"
#define HTTP_TEXT_UNAUTHORIZED          "UNAUTHORIZED"
#define HTTP_TEXT_NOT_FOUND             "NOT FOUND"
#define HTTP_TEXT_CONNECT_ESTA          "Connection established"
#define HTTP_TEXT_CONNECTION_CLOSE      "Close"
#define HTTP_TEXT_TRANSFER_ENCODING     "Transfer-Encoding: chunked"

#define HTTP_AT_FLAG_NONE               0
#define HTTP_AT_FLAG_FIRST_CHILD            1
#define HTTP_AT_FLAG_SAME               2
#define HTTP_AT_FLAG_PARENT             3
#define HTTP_AT_FLAG_ALL                4

#define HTTP_DOMAIN_FLAG_NONE           0
#define HTTP_DOMAIN_FLAG_REWRITE            1

#define CONTENT_TYPE_HTML               1
#define CONTENT_TYPE_M3U8               2
#define CONTENT_TYPE_OTHER              3
#define CONTENT_TYPE_VIDEO              4

#define CONNECTION_KEEP_ALIVE           1
#define CONNECTION_CLOSE                0
#define CONNECTION_UNKOWN           -1


struct http_request_s
{
    http_request_t          *main;
    http_request_t          *parent;
    http_request_t          *subrequest;

    unsigned char           head_in[HTTP_REQUSET_HEADER_MAX_LENGTH];
    int                 method;
    int                 http_version;

    int             proxy_mode;// 0 forword  1 reverse

    int             at_flag;
    int             domain_flag;
    int             auth_mode;
    int                 recv_body_length;
    int                 request_content_length;

    unsigned char           buf_method[10];

    unsigned char           *method_start;
    unsigned char           *method_end;
    unsigned char           *meteorq_start;
    unsigned char           *auth_info_start;
    unsigned char           *auth_info_token_start;
    unsigned char           *auth_info_token_end;
    unsigned char           *auth_info_app_start;
    unsigned char           *auth_info_app_end;
    unsigned char           *auth_info_passwd_start;
    unsigned char           *auth_info_passwd_end;
    unsigned char           *real_uri_start;
    unsigned char           *real_uri_end;
    unsigned char           *uri_start;
    unsigned char           *uri_end;
    unsigned char           *schema_start;
    unsigned char           *schema_end;
    unsigned char           *host_start;
    unsigned char           *host_end;
    unsigned char           *port_start;
    unsigned char           *port_end;
    unsigned char           *dest_host_start;
    unsigned char           *dest_host_end;
    unsigned char           *dest_port_start;
    unsigned char           *dest_port_end;

    unsigned char           *x_meteorq_start;
    unsigned char           *x_meteorq_end;
    

    /*   request header */
    unsigned char           *x_meteorq;
    unsigned char           *header_host;
    unsigned char           *header_content_length;
    unsigned char           *header_host_start;
    unsigned char           *header_host_end;
    unsigned char           *header_port_start;
    unsigned char           *header_port_end;
    unsigned char           *header_content_length_start;
    unsigned char           *header_content_length_end;

    unsigned int            is_subrequest:1;
    unsigned int            header_done:1; // true : false
    unsigned int            request_done:1;
};

struct http_response_s
{
    unsigned char           rewrite_buf[HTTP_REWRITE_BUF_SIZE];
    unsigned char           x_meteors[X_METEORS_LEN];
    ssize_t                 data_length;  // recv data length
    ssize_t                 sent_length;  // sent data length

    
    int                 response_header_parsed;
    int             response_http_version;
    int             http_response_status_code;
    int             content_type;
    int             connection;
    int                 recv_body_length;
    int                 response_content_length;

    unsigned char           *response_header_end;
    unsigned char           *response_header_content_length_start;
    unsigned char           *response_header_content_length_end;
    unsigned char           *response_header_content_type_start;
    unsigned char           *response_header_content_type_end;
    unsigned char           *response_header_transfer_encoding_start;
    unsigned char           *response_header_transfer_encoding_end;
    unsigned char           *response_header_connection_start;
    unsigned char           *response_header_connection_end;

    unsigned int            header_done:1; // true : false
    unsigned int            response_done:1;
    unsigned int            chunks_done:1;
};

struct http_info_s{
    http_request_t          request;
    http_response_t         response;
    mtr_auth_reply_t        reply;
/*  HTML
    htmlparser_ctx_ext_t    htmlparser_ctx_ext; 
*/
    unsigned char           pre_host[128];

    unsigned int            busy:1;
    unsigned int            redirect:1;
    unsigned int            auth_successed:1;
};

struct table_value_s
{
    char *tmp;
    char *value_start;
    char *value_end;
    
};

void http_cb (  socks_worker_process_t *process, int client_fd, int events, socks_connection_t *con);

int http_parse_header(socks_worker_process_t *process, socks_connection_t * con,
    int header_len, int is_subrequest);

int chk_header_recv_complete(socks_connection_t *con);

int chk_header_recv_legal(http_request_t *request);

int chk_response_legal(http_response_t * response);

int chk_response_recv_done(socks_connection_t *con, http_response_t *response, int recv_len);

int chk_request_recv_done(http_request_t *request, int recv_len);

#endif /* _HTTP_PROXY_H_ */


