//typedef struct meteor_http_request_s meteor_http_request_t;


struct meteor_http_request_s {


//    socks_connection_t                 *connection;

    unsigned  int                  method;
    unsigned  int                  http_version;

    int                            	   proxy_mode;// 0 forword  1 reverse
/*
    meteor_str_t                       request_line;
    meteor_str_t                       uri;
    meteor_str_t                       args;
    meteor_str_t                       exten;
    meteor_str_t                       unparsed_uri;

    meteor_str_t                       method_name;
    meteor_str_t                       http_protocol;
    */
    char                                buf_method[10];
    int                                at_flag;
    int                                domain_flag;
    int                                auth_mode;

    //char                               auth_info[MAXSIZE];                                
    //char                               urlstr[MAXSIZE];

    char                               *method_start;
    char                               *method_end;

    char                               *meteorq_start;

    char                               *auth_info_start;
    char                               *auth_info_token_start;
    char                               *auth_info_token_end;
    char                               *auth_info_app_start;
    char                               *auth_info_app_end;
    char                               *auth_info_passwd_start;
    char                               *auth_info_passwd_end;
    char                               *real_uri_start;
    char                               *real_uri_end;
    char                               *uri_start;
    char                               *uri_end;
    char                               *schema_start;
    char                               *schema_end;
    char                               *host_start;
    char                               *host_end;
    char                               *port_start;
    char                               *port_end;
    char                               *dest_host_start;
    char                               *dest_host_end;
    char                               *dest_port_start;
    char                               *dest_port_end;


  
    char                               *request_end;
    char                               *request_header_start;

    /*request header*/
    char                               *x_meteorq;
    char                               *header_host;
    char                               *header_content_length;
    char                               *header_host_start;
    char                               *header_host_end;
    char                               *header_port_start;
    char                               *header_port_end;
    char                               *header_content_length_start;
    char                               *header_content_length_end;
};

long int meteor_http_parse_request_line(char *b ,int length,struct meteor_http_request_s  *r);
