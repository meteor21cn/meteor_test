#include "http_parse.h"

static char *_stristr(const char *String, const char *Pattern);
static int str_to_int(char *start,char *end);


int http_parse_request_header_line( char *b ,int length, http_request_t  *r)
{
	char   c, ch, *p, *m, *d;
	int i ,j = 0, k = 0;
	char buf_meteorq[1024]="";
	enum {
		sw_start = 0,
		sw_method,
		sw_spaces_before_uri,
		sw_schema,
		sw_schema_slash,
		sw_host_start,
		sw_host,
		sw_host_end,
		sw_host_ip_literal,
		sw_port,
		sw_after_slash_in_uri,
		sw_at_flag,
		sw_domian_flag,
		sw_auth_mode,
		sw_before_auth_token,
		sw_before_auth_APP,
		sw_before_auth_passwd,
		sw_before_real_uri,
		sw_before_version,

		sw_before_dest_host_start,
		sw_dest_host,
		sw_dest_host_end,
		sw_behand_dest_host,
		sw_dest_host_ip_literal,
		sw_dest_port,
		sw_behand_dest_port,

		sw_version_H,
		sw_version_HT,
		sw_version_HTT,
		sw_version_HTTP,
		sw_version_1,
		sw_dot_before_version,
		sw_version,
		sw_almost_done

	} state;
	

	p=b;
	state =0;

	if (strstr(b,HTTP_REQUSET_FIELD_METEORQ)!=NULL){
		r->proxy_mode= HTTP_PROXY_MODE_REVERSE;
	}
	else{
		r->proxy_mode= HTTP_PROXY_MODE_FORWORD;
	}

	for(i=0;i<length+1;i++){
		ch = b[i];
		switch (state){
			case sw_start:
				m = r->method_start;
				if (ch == CR   || ch == LF  ){
					break;
				}

				if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-'){

					return HTTP_PARSE_ERROR;
				}
				state = sw_method;
				r->method_start = &(b[i]);
				d=&(b[i]);
				break; 
			case sw_method:
				if(ch == ' '){
					r->method_end = &(b[i-1]);
					for (d;d<=&(b[i-1]);d++){
						r->buf_method[k]=*d;
						k++;
					}
					if (strcmp(r->buf_method,"GET")==0){
						r->method = MET_HTTP_GET;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"HEAD")==0){
						r->method = MET_HTTP_HEAD;
						state = sw_spaces_before_uri;
						break;
						
					}
					else if (strcmp(r->buf_method,"POST")==0){
						r->method = MET_HTTP_POST ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"PUT")==0){
						r->method = MET_HTTP_PUT ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"DELETE")==0){
						r->method = MET_HTTP_DELETE ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"MKCOL")==0){
						r->method = MET_HTTP_MKCOL ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"COPY")==0){
						r->method = MET_HTTP_COPY ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"MOVE")==0){
						r->method = MET_HTTP_MOVE ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"OPTIONS")==0){
						r->method = MET_HTTP_OPTIONS ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"PROPFIND")==0){
						r->method = MET_HTTP_PROPFIND ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"PROPPATCH")==0){
						r->method = MET_HTTP_PROPPATCH ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"LOCK")==0){
						r->method = MET_HTTP_LOCK ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"UNLOCK")==0){
						r->method = MET_HTTP_UNLOCK ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"PATCH")==0){
						r->method = MET_HTTP_PATCH ;
						state = sw_spaces_before_uri;
						break;
					}
					else if (strcmp(r->buf_method,"TRACE")==0){
						r->method = MET_HTTP_TRACE ;
						state = sw_spaces_before_uri;
						break;
					}
					else{
						r->method = MET_HTTP_UNKNOWN;
						return HTTP_PARSE_ERROR ;
					}
				}
				if ((ch < 'A' || ch > 'Z') && ch != '_' && ch != '-') {

				return HTTP_PARSE_ERROR;
				}   
				break;

			/* space * before URI */
			case sw_spaces_before_uri:

				r->uri_start = &(b[i]);
				if(ch =='/'){

						//                        r->uri_start=&(p[i]);
						state=sw_after_slash_in_uri;
						m = &(b[i+1]);
						break;
					}     

				if (ch >= 'a' && ch <= 'z') {
					r->schema_start = &(b[i]);
					//                    r->uri_start = &(b[i]);
					r->real_uri_start=&(b[i]);   
					state = sw_schema;
					break;
				}   
				switch (ch){
				case ' ':
					break;
				default:
					return HTTP_PARSE_ERROR;
				}
				break;

			case sw_schema:

				if(ch >='a' && ch <='z'){
					break;
				} 

				switch(ch){
				case ':':
					r->schema_end = &(b[i]);
					state = sw_schema_slash;
					break;
				default:
					return HTTP_PARSE_ERROR;
				}
			break;

			case sw_schema_slash:
				switch(ch){
				case '/':
					state = sw_host_start;
					break;
				default:
					return HTTP_PARSE_ERROR;
				}
				break;

			case sw_host_start:
				if (ch == '/'){
				r->host_start=&(b[i+1]);
				//                r->uri_start=&(b[i+1]);
				break;
				}
				if(ch == '['){
					state = sw_host_ip_literal;
					break;
				}
				state = sw_host;

				/* fall through */
			case sw_host:

				if(ch >= 'a' && ch <= 'z'){
					break;

				}

				if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-'){
					break;
				}
				if (ch == ':'){
					r->host_end = &(b[i-1]);
					state = sw_port;
					r->port_start=&(b[i+1]);
					break;
				}
				if (ch == '/'){
					r->meteorq_start = &(b[i+1]);
					r->host_end = &(b[i-1]);
					state = sw_after_slash_in_uri; 
					m = &(b[i+1]);
					//                	r->uri_start = &(b[i-1]);
					break;
				}
				if (ch == ' '){
					r->uri_end=&(b[i-1]);
					r->host_end = &(b[i-1]);
					state = sw_version_H;
					break;
				}

				break;

			/* fall through */
			case sw_host_end: 

				if (ch == '/'){
					r->meteorq_start = &(b[i+1]);
					state = sw_after_slash_in_uri;
					m = &(b[i+1]);//jiang  jiexitiaozhengdaozhe  /meteorq.1.2.3.token.APP.passwd/www.baidu.com/index.html
				}
				if (ch >='0' && ch<='9'){
					break;
					
				}
				if (ch ==' '){
					r->uri_end=&(b[i-1]);
					r->port_end=&(b[i-1]);
					state = sw_version_H;
					break;
				}
				break;

			case sw_host_ip_literal:
				if (ch >= '0' && ch <= '9') {
					break;
				}

				if (ch >= 'a' && ch <= 'z') {
					break;
				}

				switch (ch) {
				case ':':
					break;
				case ']':
					state = sw_host_end;
					break;
				case '-':
				case '.':
				case '_':
				case '~':
					/* unreserved */
					break;
				case '!':
				case '$':
				case '&':
				case '\'':
				case '(':
				case ')':
				case '*':
				case '+':
				case ',':
				case ';':
				case '=':
					/* sub-delims */
					break;
				default:
					return HTTP_PARSE_ERROR;

				}
				break;

			case sw_port:
				if(ch >= '0' && ch <= '9'){
					break;
				}

				switch (ch){
				case '/':
					r->port_end =&(b[i+1]);
					r->meteorq_start=&(b[i-1]);
					//                    r->uri_start =&(b[i+1]);
					state = sw_after_slash_in_uri;
					m = &(b[i+1]);
					break;
			  case ' ':
					r->port_end = &(b[i-1]);
					r->uri_end = &(b[i-1]);
					state = sw_version_H;
					//                  r->r->port_end = p[i];
				default:
					return HTTP_PARSE_ERROR;                		

				}
				break;

			case sw_after_slash_in_uri:

				/*if (ch >= 'a' && ch <= 'z'){
					break;
					}*/
				if (ch == '.'){
					if (r->proxy_mode == HTTP_PROXY_MODE_REVERSE){
						state = sw_at_flag;
						break;
					}
					if (r->proxy_mode == HTTP_PROXY_MODE_FORWORD){
						state = sw_before_version;
						break;
					}
				}
				if (ch == ' '){
					state = sw_version_H;
					break;
				}
				//state = sw_before_version;
				break;
			/*
			case sw_after_slash_in_uri:

				if (ch >= 'a' && ch <= 'z'){
					break;
				}
				if (ch == '.'){

					for (m; m<=&(b[i-1]);m++){
						buf_meteorq[j]=*m;
						j++;
					}
					//            		printf("%s\n",buf_meteorq );
					if (strcmp(buf_meteorq,HTTP_REQUSET_FIELD_METEORQ)==0){
						r->proxy_mode= HTTP_PROXY_MODE_REVERSE;
						state = sw_at_flag;
						break;
					}
					else {
						r->proxy_mode= HTTP_PROXY_MODE_FORWORD;
						state = sw_before_version;
						break;
					}
				}
				
				if (ch == ' '){
					r->proxy_mode=HTTP_PROXY_MODE_FORWORD;
					state = sw_version_H;
					break;
				}
				r->proxy_mode=HTTP_PROXY_MODE_FORWORD;
				state = sw_before_version;
				break;
				*/
			case sw_at_flag:

				if (ch != '.'){ 
					if(ch >= '0' && ch <='9'){    
						r->at_flag=b[i] - '0';                   	
						break;
					}
					return HTTP_PARSE_ERROR;	  
				}               
				state = sw_domian_flag;
				break;
			case sw_domian_flag:
				
				if (ch != '.'){
					if(ch >= '0' && ch <='9'){
						r->domain_flag=b[i] - '0';
						break;
					}
					return HTTP_PARSE_ERROR;
				}
				state = sw_auth_mode;
				break;

			case sw_auth_mode:
				
				if (ch != '.'){
					if(ch >= '0' && ch <='9'){
						r->auth_mode=b[i] - '0';                     	
						r->auth_info_token_start=&(b[i+2]);      
						break;
					}
					return HTTP_PARSE_ERROR;
				}
				state = sw_before_auth_token;
				break;

			case sw_before_auth_token:

				if (ch !='|'){
					break;   
				}
					r->auth_info_token_end=&(b[i-1]);
					r->auth_info_app_start = &(b[i+1]);
					state = sw_before_auth_APP;
					break;

			case sw_before_auth_APP:

				if (ch !='|'){
					break;
				}
					r->auth_info_app_end=&(b[i-1]);
					state = sw_before_auth_passwd;
					r->auth_info_passwd_start = &(b[i+1]);
				break;

			case sw_before_auth_passwd:

				if (ch!='/') {
			   
				}
				else
				{
					r->auth_info_passwd_end=&(b[i-1]);
					state = sw_before_real_uri;
					r->real_uri_start = &(b[i+1]);
					r->dest_host_start=&(b[i+1]); 
				} 
				break;

			case sw_before_real_uri:

					if (ch != ' '){
						state = sw_before_dest_host_start;
						break; 

					}

			case sw_before_version:

					if (ch != ' '){
						break;
					}
					else 
					{
						r->real_uri_end=&(b[i-1]);
						r->uri_end=&(b[i-1]);
						state = sw_version_H;
						break;
					}    

			case sw_before_dest_host_start:
					if (ch == '[') {
						state = sw_dest_host_ip_literal;
						break;
					}

					state = sw_dest_host;

					/* fall through */
			case sw_dest_host:

					//                    c=ch;
					if (ch >= 'a' && ch <= 'z') {
						break;
					}

					if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
					break;
					}
					switch (ch){
						case ':':
						r->dest_host_end = &(b[i-1]);
						state = sw_dest_port;
						r->dest_port_start = &(b[i+1]);
						break;
						case '/':
						r->dest_host_end = &(b[i-1]);
						r->real_uri_end=&(b[i-1]);
						r->uri_end=&(b[i-1]);
						state = sw_behand_dest_host;
						break;
						case ' ':
						r->dest_host_end = &(b[i-1]);
						r->real_uri_end=&(b[i-1]);
						r->uri_end=&(b[i-1]);
						state = sw_version_H;
						break;
						default:
						break;
						return HTTP_PARSE_ERROR;
					}

			case sw_behand_dest_host:

					if(ch !=' '){
						break;
					}
					state =sw_version_H;
					break;
					/* fall through */
			case sw_dest_host_ip_literal:

					if (ch >= '0' && ch <= '9') {
					break;
					}
					if (ch >= 'a' && ch <= 'z') {
					break;
					}

					switch (ch) {
					case ':':
					break;
					case ']':
					//                    state = sw_dest_host;
					break;
					case '-':
					case '.':
					case '_':
					case '~':
					/* unreserved */
					break;
					case '!':
					case '$':
					case '&':
					case '\'':
					case '(':
					case ')':
					case '*':
					case '+':
					case ',':
					case ';':
					case '=':
					/* sub-delims */
					break;
					default:
					break;
					return HTTP_PARSE_ERROR;
					}
					break;

		case sw_dest_port:

				if (ch >= '0' && ch <= '9') {
					break;
				}
			   
				switch (ch) {
				case '/':
				r->dest_port_end = &(b[i-1]);
				// r->uri_start = p;
				state = sw_behand_dest_port;;
				break;
				case ' ':
				r->dest_port_end = &(b[i-1]);
				r->uri_end = &(b[i-1]);
				r->real_uri_end = &(b[i-1]);
				state = sw_version_H;
				//                r->dest_port_end = &(b[i]);
				/*
				 * use single "/" from request line to preserve pointers,
				 * if request line will be copied to large client buffer
				 */
				//                r->uri_start = r->schema_end + 1;
				//                r->uri_end = r->schema_end + 2;
				//                state = sw_host_http_09;
				break;
				default:
				return HTTP_PARSE_ERROR;
				}
				break;

			case sw_behand_dest_port:

				if (ch !=' '){
					break;
				}
				r->real_uri_end=&(b[i-1]);
				r->uri_end=&(b[i-1]);
				state = sw_version_H;
					 
			case sw_version_H:
					if (ch == ' '){
						break;
					}
					if (ch == 'H'){
						state = sw_version_HT;
						break;
					}
				return HTTP_PARSE_ERROR;

			case sw_version_HT:
					if (ch == 'T'){
						state = sw_version_HTT;
						break;
					}
				return HTTP_PARSE_ERROR;

			case sw_version_HTT:
					if (ch == 'T'){
						state = sw_version_HTTP;
						break;
					}
				return HTTP_PARSE_ERROR;

			case sw_version_HTTP:
					if(ch == 'P'){
						state = sw_version_1;
						break;
					}
				return HTTP_PARSE_ERROR;

			case sw_version_1:
					if (ch == '1'){
						state = sw_dot_before_version;
						break;
					}

			case sw_dot_before_version:
					if (ch == '.'){
						state = sw_version;
						break;
					}
					break;
			case sw_version:
					if (ch == '0'){
						r->http_version = HTTP_VERSION_10;
						return HTTP_PARSE_OK;
			//                        state = sw_almost_done;
			//                        break;
					}
					if(ch == '1'){
						r->http_version = HTTP_VERSION_11;
						 //                       state = sw_almost_done;
						 //                       break;
						return HTTP_PARSE_OK;
					}

					default:
						return HTTP_PARSE_ERROR;
					
		}
	}
	return HTTP_PARSE_OK;
}

int http_parse_request_header_body(char *b ,int length ,http_request_t *r)
{

		char   ch, *p,*h,*c;
		int i,request_header_flag=0;
		//    ngx_uint_t  hash, i;
		enum {
		sw_start = 0,
		sw_space_before_value,
		sw_header_value,
		sw_host,
		sw_before_port,
		sw_port,

		sw_space_before_auth_mode,
		sw_dot_before_auth_info,
		sw_before_auth_app,
		sw_before_auth_passwd,
		sw_space_after_value,

		sw_ignore_line,
		sw_almost_done,
		sw_header_done
		} state;
		/*
		if (b[length-1] == LF){
			if (b[length-2] == CR){
				if (b[length-3] == LF){
					if (b[length-4] == CR){
						request_header_flag=1;
					}
				}
			}
		}
		*/
		if (strstr(b, CRLFCRLF) != NULL)
			request_header_flag=1;
		if (request_header_flag){
			if ((p = _stristr(b,"host"))!=NULL){  
					int parse_part_flag = 1;
					r->header_host=p;
					state =sw_start;
					for (i=0;(i<length+1 && parse_part_flag==1) ;i++){
							ch=p[i];
						switch(state){

							case sw_start:
								if ((ch >='a'&& ch<='z') || (ch >='A'&& ch <='Z') || ch =='-' || ch ==':' ){
								break;
								}
								state = sw_space_before_value;
								break;
							case sw_space_before_value:
								if (ch ==' '){
								break;
								}
								r->header_host_start = &(p[i]);
								state = sw_header_value;
								break;

							case sw_header_value:

								if ((ch >='a'&& ch<='z') || (ch >='0'&& ch <='9') || ch == '.'){
								break;
								}
								switch (ch){
									case ':':
									r->header_host_end = &(p[i-1]);
									state = sw_before_port;
									break;
									case CR :
									r->header_host_end = &(p[i-1]);
									r->header_port_end = NULL;
									state = sw_almost_done;
									break;
									default:
									return HTTP_PARSE_ERROR;

								}
							case sw_before_port:
								/*if (ch == ' ')
								{
									break;
								}*/
								state = sw_port;
								r->header_port_start = &(p[i]);
								break;
							case sw_port:
								if (ch >='0' && ch <='9'){
									break;
								}
								if (ch == CR ){
									r->header_port_end = &(p[i-1]);
								//    goto done;
									state = sw_almost_done;
									break;
								}
								break;
								//return HTTP_PARSE_ERROR;

							case sw_almost_done:

								/*if (ch == CR){
									//break;
									//goto done;
									//state = sw_header_done;
									parse_part_flag = 0;
									break;
								}*/
								if (ch == LF ){
									parse_part_flag = 0;
									break;
								}
								//break;
							//    return HTTP_PARSE_ERROR;
							default:
							return HTTP_PARSE_ERROR;

						}
				
					}

				}

			if ((p = _stristr(b,"content-length"))!=NULL){
					int parse_part_flag = 1;
					r->header_content_length=p;
					state = sw_start;
					for (i=0;(i<length+1 && parse_part_flag==1);i++){
						ch = p[i];
						switch (state){
							case sw_start:
								if ((ch >='a'&& ch<='z') || (ch >='A'&& ch <='Z') || ch =='-' || ch ==':' ){
										break;
									}
									state = sw_space_before_value;
									break;
							case sw_space_before_value:
								if (ch ==' '){
										break;
									}
									r->header_content_length_start = &(p[i]);
									state = sw_header_value;
									break;
							case sw_header_value:
								if ((ch >='0'&& ch <='9')){
									break;
								}
								switch (ch){
									case CR :
									r->header_content_length_end = &(p[i-1]);
									state = sw_almost_done;
									break;
									default:
									return HTTP_PARSE_ERROR;
								}
							case sw_almost_done:
								if (ch == LF){
									parse_part_flag=0;
									break;
								}
								//return HTTP_PARSE_ERROR;
								r->request_content_length = str_to_int(r->header_content_length_start,r->header_content_length_end);
								break;

							default:
							return HTTP_PARSE_ERROR;
						}

					}       
				}
				
			if (r->proxy_mode == 0){
				if ((p = strstr(b,"X-Meteorq"))!=NULL){
					int parse_part_flag = 1;
					r->x_meteorq=p;
					r->x_meteorq_start=p;
					state = sw_start;
					for (i=0;(i<length+1 && parse_part_flag==1);i++){
						ch = p[i];
						switch (state){

						case sw_start :
							if ((ch >='a'&& ch<='z') || (ch >='A'&& ch <='Z') || ch =='-' || ch ==':'){
								break;
							}
							r->x_meteorq_end=&(p[i-1]);
							state = sw_space_before_auth_mode;
							break;
						case sw_space_before_auth_mode:
							if (ch !='.'){
								break;
							}
						   //r->x_meteorq_start = &(p[i]);
							r->auth_mode = p[i-1]-'0';
							r->auth_info_token_start=&(p[i+1]);
							state = sw_dot_before_auth_info;
							break;

						case sw_dot_before_auth_info:
							if (ch !='|'){
								break;
							}
							r->auth_info_token_end=&(p[i-1]);
							r->auth_info_app_start=&(p[i+1]);
							state=sw_before_auth_app;
							break;

						case sw_before_auth_app:
							if (p[i]!='|'){
								break;
							}
							r->auth_info_app_end=&(p[i-1]);
							r->auth_info_passwd_start=&(p[i+1]);
							state=sw_before_auth_passwd;
							break;

						case sw_before_auth_passwd:

							if (p[i]!= CR ){
								break;
							}
							r->x_meteorq_end=&(p[i-1]);
							r->auth_info_passwd_end=&(p[i-1]);
							state=sw_almost_done;
							break;
						 case sw_almost_done:

								if (ch == LF){
									parse_part_flag = 0;
									break;
								}
								return HTTP_PARSE_ERROR;

						default:
						return HTTP_PARSE_ERROR;
						}
					}
				}
			}
			return HTTP_PARSE_OK;
		}
		return HTTP_PARSE_ERROR;
}

int http_parse_response_header_line(char *b, int length, http_response_t *r)
{
	char ch;
	char m[3] = {0};
	int i,j=0;

	enum {
		sw_start = 0,
		sw_H,
		sw_HT,
		sw_HTT,
		sw_HTTP,
		sw_first_major_digit,
		sw_major_digit,
		sw_first_minor_digit,
		sw_minor_digit,
		sw_second_major_digit,
		sw_status,
		sw_space_after_status,
		sw_status_text,
		sw_almost_done
	} state;

	state =0;

	for (i=0; i<length+1; i++){
		ch =b[i];

		switch (state){
			/* "HTTP/" */
		case sw_start:
			switch (ch) {
			case 'H':
				state = sw_H;
				break;
			default:
				return HTTP_PARSE_ERROR;
			}
			break;

		case sw_H:
			switch (ch) {
			case 'T':
				state = sw_HT;
				break;
			default:
				return HTTP_PARSE_ERROR;
			}
			break;

		case sw_HT:
			switch (ch) {
			case 'T':
				state = sw_HTT;
				break;
			default:
				return HTTP_PARSE_ERROR;
			}
			break;

		case sw_HTT:
			switch (ch) {
			case 'P':
				state = sw_HTTP;
				break;
			default:
				return HTTP_PARSE_ERROR;
			}
			break;
		case sw_HTTP:
			switch (ch) {
			case '/':
				state = sw_first_major_digit;
				break;
			default:
				return HTTP_PARSE_ERROR;
			}
			break;
		case sw_first_major_digit:
			if (ch < '0' || ch > '9') {
				return HTTP_PARSE_ERROR;
			}

			//r->http_minor = ch - '0';
			state = sw_minor_digit;
			break;
		/* the minor HTTP version or the end of the reponse line */
		case sw_minor_digit:
			if (ch == '.'){
				state = sw_second_major_digit ;
				break;
			}
			return HTTP_PARSE_ERROR;
		case sw_second_major_digit:
			switch (ch){
				case '0':
				r->response_http_version = HTTP_VERSION_10;
				state = sw_status;
				break;
				case '1':
				r->response_http_version = HTTP_VERSION_11;
				state = sw_status;
				break;
				default:
				return HTTP_PARSE_ERROR;
			}
			break;
		case sw_status:
			if (ch == ' '){
				break;
			}
			if (ch < '0' || ch > '9'){
				return HTTP_PARSE_ERROR;
			}
			m[j]=b[i];
			j++;
			if (j==3){
				r->http_response_status_code = (m[0]-'0')*100 + (m[1]-'0')*10 + (m[2] - '0');
				state = sw_status_text;
			}
			break;
		/* any text until end of line */
		case sw_status_text:
			switch (ch) {
			case CR:
				state = sw_almost_done;
				break;
			case LF:
				return HTTP_PARSE_OK;
			}
			break;

		/* end of status line */
		case sw_almost_done:
			switch (ch) {
			case LF:
				return HTTP_PARSE_OK;
			default:
				return HTTP_PARSE_ERROR;
			}
		default :
		return HTTP_PARSE_ERROR;
		}
	}
}

static char *_stristr(const char *String, const char *Pattern)
{
	  char *pptr, *sptr, *start;
	  unsigned int  slen, plen;
	  for (start = (char *)String,
		   pptr  = (char *)Pattern,
		   slen  = strlen(String),
		   plen  = strlen(Pattern);
		   /* while string length not shorter than pattern length */
		   slen >= plen;
		   start++, slen--)
	  {
			/* find start of pattern in string */
			while (toupper(*start) != toupper(*Pattern))
			{
				  start++;
				  slen--;
				  /* if pattern longer than string */
				  if (slen < plen)
						return(NULL);
			}
			sptr = start;
			pptr = (char *)Pattern;
			while (toupper(*sptr) == toupper(*pptr))
			{
				  sptr++;
				  pptr++;
				  /* if end of pattern then pattern was found */
				  if ( strlen(pptr) == 0 )
						return (start);
			}
	  }
	  return(NULL);
}

static int str_to_int(char *start,char *end){
	unsigned int i=0;
	while (start <= end){
		i = 10 * i + (*start - '0');
		start++;
	}
	return i;

}

static struct table_value_s formal_parse_header (struct table_value_s *t)
{
		char   ch, *h,*c;
		enum {
		sw_start = 0,
		sw_space_before_value,
		sw_header_value
		} state;

		state = sw_start;
		for (; !(*(t->tmp) == '\n'); t->tmp++ ){
			ch = *t->tmp;
			switch (state){
				case sw_start:
					if ((ch >='a'&& ch<='z') || (ch >='A'&& ch <='Z') || ch =='-' || ch ==':' ){
						break;
					}
						state = sw_space_before_value;
						break;
				case sw_space_before_value:
					if (ch ==' '){
						break;
					}
						t->value_start = t->tmp;
						state = sw_header_value;
						break;
				case sw_header_value:
					if (ch !='\r'){
						break;
					}
					switch (ch){
						case '\r' :
							t->value_end = --t->tmp;
							return *t;
					}
			}

		}       
}


static int parse_content_type_line(char *conten_type_value_top,char *conten_type_value_end){

	char *ptmp,content_type_buf[100]="";
	int i=0;
	ptmp = conten_type_value_top;
	for (ptmp; ptmp <= conten_type_value_end; ptmp++){
		content_type_buf[i]=*ptmp;
		i++;
	}
	if (_stristr(content_type_buf,"text/html")){
		return CONTENT_TYPE_HTML;
	}
	if (_stristr(content_type_buf,"application/vnd.apple.mpegurl")){
		return CONTENT_TYPE_M3U8;
	}
	return CONTENT_TYPE_OTHER;
}

static int parse_connection_type_line(char *connection_value_top,char *connection_value_end){

	char *ptmp,connection_buf[100]="";
	int i=0;
	ptmp = connection_value_top;
	for (ptmp; ptmp <= connection_value_end; ptmp++){
		connection_buf[i]=*ptmp;
		i++;
	}
	if (_stristr(connection_buf,"keep-alive")){
		return CONNECTION_KEEP_ALIVE;
	}
	if (_stristr(connection_buf,"close")){
		return CONNECTION_CLOSE;
	}
	return CONNECTION_UNKOWN;
}



int http_parse_response_header_body(char *b,struct http_response_s *r){
	struct  table_value_s   table ;
	memset(&table, 0, sizeof(struct table_value_s));
	if ((table.tmp=_stristr (b,"content-length"))!=NULL){
		formal_parse_header (&table);
		r->response_header_content_length_start = table.value_start;
		r->response_header_content_length_end = table.value_end;
		r->response_content_length = str_to_int(r->response_header_content_length_start,r->response_header_content_length_end);

	}
	if((table.tmp=_stristr (b,"content-type"))!=NULL){
		formal_parse_header (&table);
		r->response_header_content_type_start = table.value_start;
     	r->response_header_content_type_end = table.value_end;
     	r->content_type=parse_content_type_line(r->response_header_content_type_start,r->response_header_content_type_end);
     	/*for (ptmp = r->response_header_content_type_start;ptmp <= r->response_header_content_type_end;ptmp++){
     	}*/
	}
	if((table.tmp=_stristr (b,"transfer-encoding"))!=NULL){
		formal_parse_header (&table);
		r->response_header_transfer_encoding_start = table.value_start;
     	r->response_header_transfer_encoding_end = table.value_end;
	}
	if((table.tmp=_stristr (b,"connection"))!=NULL){
		formal_parse_header (&table);
		r->response_header_connection_start = table.value_start;
     	r->response_header_connection_end = table.value_end;
     	r->connection = parse_connection_type_line(r->response_header_connection_start,r->response_header_connection_end);
	}
	return 0;
}