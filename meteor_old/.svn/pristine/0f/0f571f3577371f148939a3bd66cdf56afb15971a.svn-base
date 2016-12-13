#include <sys/types.h> 
#include <sys/stat.h> 
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h> // off_t   eff??
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <pwd.h>

#include "meteor.h"  
#include "sockd.h"  
#include "meteor_conf.h"

//#define offsetof(TYPE, MEMBER) ((size_t) (&((TYPE *)0)->MEMBER))
#define cf_offset(cmd) \
        offsetof(socks_module_config_t,cmd)
#define wk_offset(cmd) \
        (offsetof(socks_module_config_t,worker_config) + \
            offsetof(socks_worker_config_t,cmd))       
#define NO_DEFINED_CMD_OFFSET 0

#define copy_conf_value(member)          \
    meteor_conf_copy_value(cf->member,setconfig->member)
#define copy_conf_str_value(member)      \
    meteor_conf_copy_str_value(cf->member,setconfig->member)
#define copy_worker_value(member)        \
    meteor_conf_copy_value(wc->member,setworker->member)
#define copy_worker_str_value(member)    \
    meteor_conf_copy_str_value(wc->member,setworker->member)

#define copy_worker_outer_addr(member1,cp_member)         \
    if (strcmp(wc->member1,METEOR_CONF_STR_UNSET))  {     \
        wc->cp_member = setworker->cp_member;             \
    }   
#define DEBUG  0

static int get_domain(char *token_str);
static int conf_handle(meteor_conf_t *cf);

char* meteor_conf_set_worker_block(meteor_conf_t *cf);
char* meteor_conf_set_flag(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);
char* meteor_conf_set_enum(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);
char* meteor_conf_set_num(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);
char* meteor_conf_set_msec(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);
char* meteor_conf_set_str(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);
char* meteor_conf_set_host(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);
char* meteor_conf_set_user(meteor_conf_t *cf, meteor_command_t *cmd, void *conf);
char* meteor_conf_set_worker_listen_port(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);

static unsigned int argument_number[] = {
    METEOR_CONF_NOARGS,
    METEOR_CONF_TAKE1,
    METEOR_CONF_TAKE2,
    METEOR_CONF_TAKE3,
    METEOR_CONF_TAKE4,
    METEOR_CONF_TAKE5,
    METEOR_CONF_TAKE6,
    METEOR_CONF_TAKE7
};

static post_num_t port_number = {"port number",1024,65535};

// the end should be NULL 
static meteor_conf_enum_t  daemon_modes[] = {
    {"on",1},
    {"off",0},
    {NULL,-1} //
};

static meteor_conf_enum_t  log_modes[] = {
    {"file",LOG_MODE_FILE},
    {"console",LOG_MODE_CONSOLE},
    {NULL,-1} //
};

static meteor_conf_enum_t  log_levels[] = {
    {"error",LL_ERROR},
    {"warning",LL_WARNING},
    {"notice",LL_NOTICE},
    {"info",LL_INFO},
    {"debug",LL_DEBUG},
    {NULL,-1} //
};

static meteor_conf_enum_t domains[] = {
    {"sys_log",DOMAIN_SYS_LOG}, 
    {"flow_log",DOMAIN_FLOW_LOG},
    {"redis_server",DOMAIN_REDIS_SERVER},
    {"timer",DOMAIN_TIMER},
    {"worker",DOMAIN_WORKER},
    {NULL,ERROR_DOMAIN}
};

static meteor_command_t meteor_main_commands[] = {
    {"daemon_mode",
    METEOR_CONF_TAKE1,
    meteor_conf_set_flag,
    cf_offset(daemon_mode),
    NULL},

    {"worker_processes",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    cf_offset(workers),
    NULL},

    {"worker_max_sessions",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    cf_offset(worker_max_sessions),
    NULL},

    {"user",
    METEOR_CONF_TAKE1,
    meteor_conf_set_user,
    cf_offset(user_name),
    NULL},

    {"pid",
    METEOR_CONF_TAKE1,
    meteor_conf_set_str,
    cf_offset(pid_file_name),
    NULL},

    meteor_null_command
};

static meteor_command_t meteor_sys_log_commands[] = {
    {"mode",
    METEOR_CONF_TAKE1,
    meteor_conf_set_enum,
    cf_offset(sys_log_mode),
    log_modes},

    {"level",
    METEOR_CONF_TAKE1,
    meteor_conf_set_enum,
    cf_offset(sys_log_level),
    log_levels},

    {"file",
    METEOR_CONF_TAKE1,
    meteor_conf_set_str,
    cf_offset(sys_log_file_name),
    NULL},

    {"rotate",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(sys_log_rotate_interval),
    METEOR_CONF_IS_SEC},

    meteor_null_command
};

static meteor_command_t meteor_flow_log_commands[] = {
    {"file",
    METEOR_CONF_TAKE1,
    meteor_conf_set_str,
    cf_offset(flow_log_file_name),
    NULL},

    {"rotate",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(flow_log_rotate_interval),
    METEOR_CONF_IS_SEC},

    meteor_null_command
};

static meteor_command_t meteor_redis_server_commands[] = {
    {"host",
    METEOR_CONF_TAKE1,
    meteor_conf_set_host,
    cf_offset(redis_host),
    NULL},

    {"port",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    cf_offset(redis_port),
    &port_number},

    meteor_null_command
};

static meteor_command_t meteor_timer_commands[] = {
    {"order_check",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(order_check_interval),
    METEOR_CONF_IS_MSEC},

    {"order_update",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(order_update_interval),
    METEOR_CONF_IS_MSEC},

    {"order_event_check",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(order_event_check_interval),
    METEOR_CONF_IS_MSEC},

    {"order_frozen",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(order_frozen_timeout),
    METEOR_CONF_IS_MSEC},

    {"order_idle",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(order_idle_timeout),
    METEOR_CONF_IS_MSEC},

    {"session_idle",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(session_idle_timeout),
    METEOR_CONF_IS_MSEC},

    {"activity_check",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(activity_check_interval),
    METEOR_CONF_IS_MSEC},

    {"activity_update",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(activity_update_interval),
    METEOR_CONF_IS_MSEC},

    {"pool_defrag",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(pool_defrag_interval),
    METEOR_CONF_IS_MSEC},

    {"pool_defrag_size",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    cf_offset(pool_defrag_size),
    NULL}, 

    {"worker_stat_update",
    METEOR_CONF_TAKE1,
    meteor_conf_set_msec,
    cf_offset(worker_stat_update_interval),
    METEOR_CONF_IS_SEC},

    meteor_null_command
};

 static meteor_command_t meteor_worker_commands[] = {
    {"name",
    METEOR_CONF_TAKE1,
    meteor_conf_set_str,
    wk_offset(worker_name),
    NULL},

    {"outer_host",
    METEOR_CONF_TAKE1,
    meteor_conf_set_host,
    wk_offset(outer_host),
    NULL},

    {"listen_host",
    METEOR_CONF_TAKE1,
    meteor_conf_set_host,
    wk_offset(listen_host),
    NULL},

    {"listen_port",
    METEOR_CONF_1MORE,
    meteor_conf_set_worker_listen_port,
    wk_offset(listen_port),
    &port_number},

    {"backlog",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    wk_offset(listen_backlog),
    NULL},

    {"recv_buf",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    wk_offset(recv_buf_size),
    NULL},

    {"send_buf",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    wk_offset(send_buf_size),
    NULL},

    {"reuseaddr",
    METEOR_CONF_TAKE1,
    meteor_conf_set_flag,
    wk_offset(reuseaddr),
    NULL},

    {"keepalive",
    METEOR_CONF_TAKE1,
    meteor_conf_set_flag,
    wk_offset(keepalive),
    NULL},

    {"max_sessions",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    wk_offset(max_sessions),
    NULL},

    {"udp_port_start",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    wk_offset(udp_port_start),
    &port_number},

    {"udp_port_end",
    METEOR_CONF_TAKE1,
    meteor_conf_set_num,
    wk_offset(udp_port_end),
    &port_number},

    meteor_null_command
};

// see the DOMAIN_MAIN seq... 
static meteor_command_t *meteor_conf_all_commands[] = {
    meteor_main_commands,
    meteor_sys_log_commands,
    meteor_flow_log_commands,
    meteor_redis_server_commands,
    meteor_timer_commands,
    meteor_worker_commands
};


int meteor_token_array_create(meteor_conf_t *cf) // TODO:change to meteor_array_t
{
    void *arry = malloc(  sizeof(meteor_array_t) +
        METEOR_CONF_INIT_TOKEN_NUM * (METEOR_CONF_MAX_TOKEN_LEN+1) );
    if ( arry == NULL ) 
    {   
        return -1;
    }

    cf->args = (meteor_array_t *)arry;
    cf->args->elts = arry + sizeof(meteor_array_t); 
    cf->args->nalloc = METEOR_CONF_INIT_TOKEN_NUM ;
    cf->args->nelts = 0;
    //cf->args->size = sizeof(char *); 
    cf->domain = DOMAIN_MAIN;

    return 0;
}

void meteor_token_array_destroy(meteor_conf_t *cf) // cf FROM _create
{
    if (cf->args)
    {
        free(cf->args);
        cf->args = NULL;
    }
}

void meteor_conf_log_error(int level,meteor_conf_t *cf, const char *fmt, ...)
{
    //level not used now
    char errstr[1024];
    va_list ap;
    va_start(ap,fmt);
    vsnprintf(errstr,sizeof(errstr),fmt,ap);
    va_end(ap);
    if (cf)
    {
        fprintf(stderr,"\033[1m %s in %s:%d\033[0m\n",errstr,cf->conf_file->file.name,cf->conf_file->line);  
    }
    else
    {
        fprintf(stderr, "\033[1m %s\033[0m\n", errstr);
    }
}

static uintptr_t
meteor_conf_read_token(meteor_conf_t *cf)
{
//TODO: check (len<MAX_TOKEN_LEN && nelts < MAX_TOKEN_NUM)
    u_char      *start, ch, *src, *dst;
    off_t        file_size;
    size_t       len;
    ssize_t      n, size;
    int  		 found, need_space, last_space, sharp_comment;
    int   		 quoted, s_quoted, d_quoted, start_line;
    char        *token_str; 
    meteor_conf_buf_t   *b, *dump;
    void        *rcf;

    found = 0;
    need_space = 0;
    last_space = 1;
    sharp_comment = 0;
    quoted = 0;
    s_quoted = 0;
    d_quoted = 0;

    cf->args->nelts = 0;
    b = cf->conf_file->buf; 
    start = b->pos;
    start_line = cf->conf_file->line;

    //bug??? ---if fstat() failed??
    file_size = (&cf->conf_file->file.info)->st_size; 

    for ( ;; ) {        

        if (b->pos >= b->last) { 

            if (cf->conf_file->file.offset >= file_size) {

                if (cf->args->nelts > 0 || !last_space) {

                    if (cf->conf_file->file.fd == -1){
                        meteor_conf_log_error(LL_ERROR,NULL,"wrong file fd");
                        return METEOR_ERROR;
                    }
                    meteor_conf_log_error(LL_ERROR,cf,"unexpected end of file, expecting \";\" or \"}\"");
                    return METEOR_ERROR;
                }

                return METEOR_CONF_FILE_DONE;
            }

            len = b->pos - start;

            if (len == METEOR_CONF_BUFFER) {
                cf->conf_file->line = start_line;  // reset 

                if (d_quoted) {
                    ch = '"';

                } else if (s_quoted) {
                    ch = '\'';

                } else {
                    meteor_conf_log_error(LL_ERROR,cf,"too long parameter \"%*s...\" started",
                                       10, start);
                    return METEOR_ERROR;
                }
                meteor_conf_log_error(LL_ERROR,cf,"too long parameter, probably "
                              "missing terminating \"%c\" character", ch);
                return METEOR_ERROR;
            }

            if (len) {
                memmove(b->start, start, len);
            }

            size = (ssize_t) (file_size - cf->conf_file->file.offset);

            if (size > b->end - (b->start + len)) {
                size = b->end - (b->start + len);
            }

            n = pread(cf->conf_file->file.fd, b->start + len, size,
                              cf->conf_file->file.offset);
            if ( n == -1 )
            {
            	meteor_conf_log_error(LL_ERROR,cf,"read file failed");
            	return METEOR_ERROR;
            }

            cf->conf_file->file.offset += n;

            if (n != size) {
                meteor_conf_log_error( LL_ERROR,cf," pread() returned "
                                   "only %d bytes instead of %d",
                                   n, size);
                return METEOR_ERROR;
            }

            b->pos = b->start + len;
            b->last = b->pos + n;
            start = b->start;
        }

        ch = *b->pos++;

        if (ch == LF) {
            cf->conf_file->line++;

            if (sharp_comment) {
                sharp_comment = 0;
            }
        }

        if (sharp_comment) {
            continue;
        }

        if (quoted) {
            quoted = 0;
            continue;
        }

        if (need_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                last_space = 1;
                need_space = 0;
                continue;
            }

            if (ch == ';') {
                return METEOR_OK;
            }

            if (ch == '{') {
                return METEOR_CONF_BLOCK_START;
            }

            if (ch == ')') {
                last_space = 1;
                need_space = 0;

            } else {
                meteor_conf_log_error(LL_ERROR,cf,"unexpected \"%c\"", ch);
                return METEOR_ERROR;
            }
        }

        if (last_space) {
            if (ch == ' ' || ch == '\t' || ch == CR || ch == LF) {
                continue;
            }

            start = b->pos - 1;
            start_line = cf->conf_file->line;

            switch (ch) {

            case ';':
            case '{':
                if (cf->args->nelts == 0) {
                    meteor_conf_log_error(LL_ERROR,cf, "unexpected \"%c\"", ch);
                    return METEOR_ERROR;
                }

                if (ch == '{') {
                    if (cf->args->nelts == 1)
                    {
                        return METEOR_CONF_BLOCK_START;
                    }
                    else
                    {
                        meteor_conf_log_error(LL_ERROR,cf,"unexpected \"{\",may lose a \";\"");
                        return METEOR_ERROR;
                    }
                }

                return METEOR_OK;

            case '}':
                if (cf->args->nelts != 0) {
                    meteor_conf_log_error(LL_ERROR,cf,"unexpected \"}\"");
                    return METEOR_ERROR;
                }

                return METEOR_CONF_BLOCK_DONE;

            case '#':
                sharp_comment = 1;
                continue;

            case '\\':
                quoted = 1;
                last_space = 0;
                continue;

            case '"':
                start++;
                d_quoted = 1;
                last_space = 0;
                continue;

            case '\'':
                start++;
                s_quoted = 1;
                last_space = 0;
                continue;

            default:
                last_space = 0;
            }

        } else {

            if (ch == '\\') {
                quoted = 1;
                continue;
            }

            if (d_quoted) {
                if (ch == '"') {
                    d_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (s_quoted) {
                if (ch == '\'') {
                    s_quoted = 0;
                    need_space = 1;
                    found = 1;
                }

            } else if (ch == ' ' || ch == '\t' || ch == CR || ch == LF
                       || ch == ';' || ch == '{')
            {
                last_space = 1;
                found = 1;
            }

            if (found) {

                token_str = cf->args->elts + cf->args->nelts * METEOR_CONF_MAX_TOKEN_LEN; // idle token slot
                cf->args->nelts++;
                if ( cf->args->nelts > cf->args->nalloc )
                {
                    #if 0
                    meteor_conf_log_error(LL_ERROR,cf,"excessive number of arguments for \"%s\"",cf->args->elts);
                    return METEOR_ERROR;
                    #else

                    void *rarry =  realloc(cf->args,sizeof(meteor_array_t) +
                            (cf->args->nalloc + METEOR_CONF_NEW_ALLOC_NUM) * 
                            (METEOR_CONF_MAX_TOKEN_LEN+1) );

                    if ( rarry == NULL ) 
                    {   
                        meteor_conf_log_error(LL_ERROR,cf, "realloc() failed");
                        return METEOR_ERROR;
                    }

                    cf->args = (meteor_array_t *)rarry;
                    cf->args->elts = rarry + sizeof(meteor_array_t); 
                    cf->args->nalloc += METEOR_CONF_NEW_ALLOC_NUM;
                    #endif
                }

                if (token_str == NULL) {
                    return METEOR_ERROR;
                }
                for (dst = token_str, src = start, len = 0;
                     src < b->pos - 1 ;
                     len++)
                {
                    if ( len > METEOR_CONF_MAX_TOKEN_LEN)
                    {
                        token_str[len>21?21:len] = '\0';
                        meteor_conf_log_error(LL_ERROR,cf,"too long token \"%s....\""
                            "(length should less than %d)",token_str,METEOR_CONF_MAX_TOKEN_LEN);
                        return METEOR_ERROR;
                    }
                    if (*src == '\\') {
                        switch (src[1]) {
                        case '"':
                        case '\'':
                        case '\\':
                            src++;
                            break;

                        case 't':
                            *dst++ = '\t';
                            src += 2;
                            continue;

                        case 'r':
                            *dst++ = '\r';
                            src += 2;
                            continue;

                        case 'n':
                            *dst++ = '\n';
                            src += 2;
                            continue;
                        }

                    }
                    *dst++ = *src++;
                }
                *dst = '\0';

                if (ch == ';') {
                    return METEOR_OK;
                }
                if (ch == '{') {
                    return METEOR_CONF_BLOCK_START;
                }
                found = 0;
            }
        }
    }
}


char* meteor_conf_parse(meteor_conf_t *cf,const char* config_file_name)
{
	char 	*rv;
	u_char  *p;
	off_t 	size;
	int 	fd;
	int  	rc,rd;

	meteor_conf_buf_t   buf,*tbuf;
	meteor_conf_file_t  conf_file;

    int block_appeared[] = {1,0,0,0,0,0};//TODO: opt...

	enum {
		parse_file = 0,
		parse_block,
		//parse_param
	} type;

	if (config_file_name)
	{

		fd = open(config_file_name,O_RDONLY);  // open param??
		if ( fd < 0)
		{
			meteor_conf_log_error(LL_ERROR,NULL,"open file:%s failed",config_file_name);
			return METEOR_CONF_ERROR;  
		}
        
		cf->conf_file = &conf_file;

 		if ( fstat(fd,&cf->conf_file->file.info) == -1 )
 		{
 			meteor_conf_log_error(LL_ERROR,NULL,"[%s:%d]:fstat() \"%s\" failed", __FILE__,__LINE__,config_file_name);
 		}

		cf->conf_file->buf = &buf;

		buf.start = (u_char *)malloc(METEOR_CONF_BUFFER); // 4KB
		if (buf.start == NULL )
		{
			goto failed;
		}

		buf.pos = buf.start;
		buf.last = buf.start;
		buf.end = buf.last + METEOR_CONF_BUFFER;

        cf->worker_index = 0;
		cf->conf_file->file.fd = fd;
		cf->conf_file->file.name = config_file_name; //const?
		cf->conf_file->file.offset = 0;
		cf->conf_file->line = 1;
		type = parse_file;
	}
	else  // config_file_name == NULL
	{
		type = parse_block;
	}

    int old_worker_index = 0;
		for (;;) 
		{
			rc = meteor_conf_read_token(cf);
#if  0
            printf("rc=%d,nelts=%d,domain=%d: ",rc,cf->args->nelts,cf->domain);
                int i;
                tokens_array_t tokens;
                tokens = cf->args->elts;
                for (i = 0;i< cf->args->nelts; i++)
                {
                  
                    printf("%s\t",tokens[i]);

                }
                printf("\n");
#endif
            switch (rc)
			{
				case METEOR_ERROR:
						goto done;
				case METEOR_CONF_BLOCK_DONE:
                    if (cf->args->nelts != 0)
                    {
                        meteor_conf_log_error(LL_ERROR,cf,"unexpected \"}\",probably lose a \";\"");
                        goto failed;
                    }
					if (type != parse_block)
					{
						meteor_conf_log_error(LL_ERROR,cf,"unexpected \"}\"");
						goto failed;
					}
					else
					{
						goto done;
                        //break; 
					}
				case METEOR_CONF_FILE_DONE:
					if (type == parse_block)
					{
						meteor_conf_log_error(LL_ERROR,cf,"unexpected end of file,expecting \"}\"");
						goto failed;
					}
					else
					{
						goto done;
					}
				case METEOR_CONF_BLOCK_START:
                    ASSERT(cf->args->nelts == 1);
                    if ( type == parse_block )
                    {
                        meteor_conf_log_error(LL_ERROR,cf,"unexpected \"{\",not allowed nesting block");
                        goto failed;
                    }
                    rd = get_domain((char*)cf->args->elts);

                    if ( rd != ERROR_DOMAIN )
                    {
                       
                        if (rd == DOMAIN_WORKER)
                        {
                            rv = meteor_conf_set_worker_block(cf);
                        }
                        else 
                        {
                            ASSERT( rd < sizeof(block_appeared));
                            if ( block_appeared[rd] != 0 )
                            {
                                meteor_conf_log_error(LL_ERROR,cf,"\"%s\" is duplicate",cf->args->elts);
                                goto failed;
                            }
                            else
                            {
                                block_appeared[rd] = 1;
                            }

                            int old_domain  = cf->domain;
                            cf->domain = rd;

                            rv = meteor_conf_parse(cf,NULL);

                            cf->domain = old_domain;
                        }

                        if (rv != METEOR_CONF_OK) 
                        {
                            goto failed; 
                        }

                        break;  // continue read token
                    }
                    else // false domain
                    {
                        meteor_conf_log_error(LL_ERROR,cf,"directive \"%s\" has no opening \"{\"",(char*)cf->args->elts);
                        goto failed;
                    }
                    break;
                case METEOR_OK:  // set tokens end of ";"
                     rc = conf_handle(cf);
                     if ( rc == METEOR_ERROR)
                     {
                        goto failed; 
                     }
                    break; // the next for loop
    			default:
    				meteor_conf_log_error(LL_ERROR,cf,"code [%s:%d] false rc",__FILE__,__LINE__);
                    goto failed;
    		}
    	}

	failed:
		rc = METEOR_ERROR;
	done:
		if (config_file_name)
		{
            if (cf->worker_index)
            {   
                //to fix the bug --set worker error-- 
                //when call _conf_parse( or read_config() ) more than once
                meteor_command_t *cmd = meteor_worker_commands;
                for (;cmd->name;cmd++)
                {
                    cmd->offset -= cf->worker_index * sizeof(socks_worker_config_t);
                }
            }
			if (cf->conf_file->buf->start)
			{
                free(cf->conf_file->buf->start);
				cf->conf_file->buf->start = NULL;
			}
			if (close(fd) < 0)
			{
				meteor_conf_log_error(LL_ERROR,cf,"close %s failed",config_file_name);
				rc = METEOR_ERROR;
			}
		}

		if (rc == METEOR_ERROR) 
		{
			return METEOR_CONF_ERROR;
		}

		return METEOR_CONF_OK;

}

static int get_domain(char *token_str)
{
    int i;
    for (i = 0;domains[i].name;i++)
    {
        if (!strcmp(domains[i].name,token_str))
            return domains[i].value;
    }
    return ERROR_DOMAIN;
}

int meteor_atoi(u_char *num_str)
{
    int  value, cutoff, cutlim;
    int n = strlen(num_str);
    if (n == 0) {
        return METEOR_ERROR;
    }

    cutoff = METEOR_MAX_INT_T_VALUE / 10;
    cutlim = METEOR_MAX_INT_T_VALUE % 10;

    for (value = 0; n--; num_str++) {
        if (*num_str < '0' || *num_str > '9') {
            return METEOR_ERROR;
        }

        if (value >= cutoff && (value > cutoff || *num_str - '0' > cutlim)) {
            return METEOR_ERROR;
        }

        value = value * 10 + (*num_str - '0');
    }

    return value;
}

int isValidhost(char *host)
{
    unsigned char buf[sizeof(struct in6_addr)];
    char str[INET6_ADDRSTRLEN];
    int s;

    if( inet_pton(AF_INET,host,buf) != 1 &&
        // inet_pton(AF_INET6,host,buf) != 1 &&
        gethostbyname(host) == NULL ) 
    {
        return METEOR_ERROR;
    }
    return METEOR_OK;
}

char *
meteor_conf_set_worker_block(meteor_conf_t *cf)
{
    char *rv;
    int old_worker_index = cf->worker_index++;

    if(cf->worker_index>MAX_WORKERS)
    {
        meteor_conf_log_error(LL_ERROR,cf,"too much worker block");
        return METEOR_CONF_ERROR;
    } 

    int old_domain  = cf->domain;
    cf->domain = DOMAIN_WORKER;

    rv = meteor_conf_parse(cf,NULL);

    cf->domain = old_domain;

     // num of listen_port in a worker block
    int workers = cf->worker_index - old_worker_index;
    if ( workers > 1 ) // listen_port more 1 param -> memcpy the parms
    {
        //set Worker_config_t,listen port
        int i;
        socks_worker_config_t *wc,*prev_wc;
        wc =(socks_worker_config_t*)&(cf->config->worker_config[old_worker_index]);
        prev_wc = NULL;
        for (i=0;i<(workers-1);i++)
        {
            int tmp_port;
            prev_wc = wc++;
            tmp_port = wc->listen_port;
            memcpy(wc,prev_wc,sizeof(socks_worker_config_t));
            wc->listen_port = tmp_port;
        }
    }

    meteor_command_t *cmd = meteor_worker_commands;

    for (;cmd->name;cmd++)
    {
        cmd->offset += workers * sizeof(socks_worker_config_t);
    }

    return rv; 
}

char *
meteor_conf_set_worker_listen_port(meteor_conf_t *cf,meteor_command_t *cmd,void *conf)
{
    tokens_array_t tokens = cf->args->elts;
    int *val = conf + cmd->offset;
    //int *val = &cf->config->worker_config[cf->worker_index-1].listen_port;
    int listen_port_num = cf->args->nelts - 1;
    int i,j;
    if ( cf->worker_index > 1 )
    {
        if ( listen_port_num > 1)
        {
            return "listen_port only 1 parameter,when 1 \"worker{}\" block";
        }
    }
    ASSERT(listen_port_num > 0);
    cf->worker_index += listen_port_num - 1;
    if(cf->worker_index>MAX_WORKERS) // num of workers
    {
        meteor_conf_log_error(LL_ERROR,cf,"too much workers");
        return METEOR_CONF_ERROR;
    }
    for (i = 1;i <= listen_port_num;i++)
    {
        *val = meteor_atoi(tokens[i]);
        if( *val == METEOR_ERROR )
            return "invalid number";
        if( *val > 65535 || *val<1024 )
        {      
            return "invalid port number which should be in (1024-65535)";
        }

        socks_worker_config_t *tmp = &(cf->config->worker_config[0]);

        for (j = 0;&tmp[j].listen_port < val;j++)
        {
            if ( *val == tmp[j].listen_port )
            {
                meteor_conf_log_error(LL_ERROR,cf,"duplicate port num \"%s\"",tokens[i]);
                return METEOR_CONF_ERROR;
            }
        }

        val = (int *)((char*)val + sizeof(socks_worker_config_t));
    }
    return METEOR_CONF_OK;   
}

char *
meteor_conf_set_flag(meteor_conf_t *cf,meteor_command_t *cmd, void *conf)
{
    
    tokens_array_t tokens = cf->args->elts;
    int *flag = conf + cmd->offset;
    if (*flag != METEOR_CONF_FLAG_UNSET ) 
    {
        return "is duplicate";
    }
    if ( strcmp(tokens[1], "on") == 0) {
        *flag = 1;
    } else if (strcmp(tokens[1], "off") == 0) {
        *flag = 0;
    } else {
       meteor_conf_log_error(LL_ERROR,cf,"invalid value \"%s\" in \"%s\" directive, "
                     "it must be \"on\" or \"off\"",
                     tokens[1], tokens[0]);
        return METEOR_CONF_ERROR;
    }
    return METEOR_CONF_OK;
}

char *
meteor_conf_set_enum(meteor_conf_t *cf,meteor_command_t *cmd, void *conf)
{
    tokens_array_t tokens = cf->args->elts ;
    int *val = conf + cmd->offset;
        
    if (*val != METEOR_CONF_ENUM_UNSET) 
    {
        return "is duplicate";
    }
    
    if (cmd->post == NULL)
    {
        meteor_conf_log_error(LL_ERROR,cf,"set enum failed");
        return METEOR_CONF_ERROR;
    }  

    meteor_conf_enum_t *e = cmd->post;
    int i;
    for (i = 0; e[i].name; i++) 
    {
        if ( strcmp(e[i].name, tokens[1]) != 0)
        {
            continue;
        }
        *val = e[i].value;
        return METEOR_CONF_OK;
    }
    meteor_conf_log_error(LL_ERROR,cf,"invalid value \"%s\"", tokens[1]);
    return METEOR_CONF_ERROR;
}

char * meteor_conf_set_num(meteor_conf_t *cf,meteor_command_t *cmd, void *conf)
{
    tokens_array_t tokens = cf->args->elts;
    int *val = conf + cmd->offset;
    int tmp = 0;

    int i = cf->args->nelts - 1;
    for (;i>0;i--,val++)
    {
        if (*val != METEOR_CONF_INT_UNSET)
            return "is duplicate";
        *val = meteor_atoi(tokens[i]);
        if( *val == METEOR_ERROR )
            return "invalid number";
        if (cmd->post)
        {
            post_num_t *pn = cmd->post;
            if( *val > pn->max || *val < pn->min)
            {
                meteor_conf_log_error(LL_ERROR,cf,"\"%s\" directive "
                    "invalid %s which should be in (%d,%d)",tokens[0],pn->name,pn->min,pn->max);
                return METEOR_CONF_ERROR;
            }            
        }

    }
    return METEOR_CONF_OK;  
}

char *
meteor_conf_set_host(meteor_conf_t *cf,meteor_command_t *cmd, void *conf)
{
    tokens_array_t tokens = cf->args->elts;
    char *val = conf + cmd->offset;
    if (strcmp(val,METEOR_CONF_STR_UNSET)!= 0) 
    {
        return "is duplicate";
    }
    if (METEOR_ERROR == isValidhost(tokens[1]))
        return "invalid ipv4/"
                // "ipv6/"
            "hostname";
    strcpy(val,tokens[1]);
    return METEOR_CONF_OK;
}

char *
meteor_conf_set_user(meteor_conf_t *cf, meteor_command_t *cmd, void *conf)
{
    tokens_array_t tokens = cf->args->elts;
    char *user = conf + cmd->offset;

    socks_module_config_t  *ccf = conf;

    struct passwd    *pwd;

    if (ccf->user_id != (uid_t) METEOR_CONF_UINT_UNSET) {
        return "is duplicate";
    }

    if (geteuid() != 0) {
        meteor_conf_log_error(LL_WARNING, cf,                            "the \"user\" directive makes sense only "
                           "if the master process runs "
                           "with super-user privileges, ignored");
        return METEOR_CONF_OK;
    }
    strcpy(user,tokens[1]);
    errno = 0;
    pwd = getpwnam((const char *) tokens[1]);
    if (pwd == NULL) {
        meteor_conf_log_error(LL_ERROR, cf,
                           "getpwnam(\"%s\") failed:%m", tokens[1],errno);
        return METEOR_CONF_ERROR;
    }
    ccf->user_id = pwd->pw_uid;
    return METEOR_CONF_OK;
}

char *
meteor_conf_set_str(meteor_conf_t *cf,meteor_command_t *cmd, void *conf)
{
    tokens_array_t tokens = cf->args->elts;
    char *val = conf + cmd->offset;

    if (strcmp(val,METEOR_CONF_STR_UNSET) != 0) 
    {
        return "is duplicate";
    }
    //TODO:strlen(token[1]) < path_len ??
    strcpy(val,tokens[1]);
    return METEOR_CONF_OK;
}

int
meteor_parse_time( char* line, int is_sec)  // str or line??
{
    u_char      *p, *last;
    int         value, total, scale;
    int         max, cutoff, cutlim;
    int         valid;
    enum {
        st_start = 0,
        st_year,
        st_month,
        st_week,
        st_day,
        st_hour,
        st_min,
        st_sec,
        st_msec,
        st_last
    } step;

    valid = 0;
    value = 0;
    total = 0;

    cutoff = METEOR_MAX_INT_T_VALUE / 10;
    cutlim = METEOR_MAX_INT_T_VALUE % 10;
    step = is_sec ? st_start : st_month;

    p = line;
    last = p + strlen(line);

    while (p < last) {

        if (*p >= '0' && *p <= '9') {
            if (value >= cutoff && (value > cutoff || *p - '0' > cutlim)) {
                return METEOR_ERROR;
            }

            value = value * 10 + (*p++ - '0');
            valid = 1;
            continue;
        }

        switch (*p++) {

        case 'y':
            if (step > st_start) {
                return METEOR_ERROR;
            }
            step = st_year;
            max = METEOR_MAX_INT_T_VALUE / (60 * 60 * 24 * 365);
            scale = 60 * 60 * 24 * 365;
            break;

        case 'M':
            if (step >= st_month) {
                return METEOR_ERROR;
            }
            step = st_month;
            max = METEOR_MAX_INT_T_VALUE / (60 * 60 * 24 * 30);
            scale = 60 * 60 * 24 * 30;
            break;

        case 'w':
            if (step >= st_week) {
                return METEOR_ERROR;
            }
            step = st_week;
            max = METEOR_MAX_INT_T_VALUE / (60 * 60 * 24 * 7);
            scale = 60 * 60 * 24 * 7;
            break;

        case 'd':
            if (step >= st_day) {
                return METEOR_ERROR;
            }
            step = st_day;
            max = METEOR_MAX_INT_T_VALUE / (60 * 60 * 24);
            scale = 60 * 60 * 24;
            break;

        case 'h':
            if (step >= st_hour) {
                return METEOR_ERROR;
            }
            step = st_hour;
            max = METEOR_MAX_INT_T_VALUE / (60 * 60);
            scale = 60 * 60;
            break;

        case 'm':
            if (p < last && *p == 's') {
                if (is_sec || step >= st_msec) {
                    return METEOR_ERROR;
                }
                p++;
                step = st_msec;
                max = METEOR_MAX_INT_T_VALUE;
                scale = 1;
                break;
            }

            if (step >= st_min) {
                return METEOR_ERROR;
            }
            step = st_min;
            max = METEOR_MAX_INT_T_VALUE / 60;
            scale = 60;
            break;

        case 's':
            if (step >= st_sec) {
                return METEOR_ERROR;
            }
            step = st_sec;
            max = METEOR_MAX_INT_T_VALUE;
            scale = 1;
            break;

        case ' ':
            if (step >= st_sec) {
                return METEOR_ERROR;
            }
            step = st_last;
            max = METEOR_MAX_INT_T_VALUE;
            scale = 1;
            break;

        default:
            return METEOR_ERROR;
        }

        if (step != st_msec && !is_sec) {
            scale *= 1000;
            max /= 1000;
        }

        if (value > max) {
            return METEOR_ERROR;
        }

        value *= scale;

        if (total > METEOR_MAX_INT_T_VALUE - value) {
            return METEOR_ERROR;
        }

        total += value;

        value = 0;

        while (p < last && *p == ' ') {
            p++;
        }
    }

    if (!valid) {
        return METEOR_ERROR;
    }

    if (!is_sec) {
        if (value > METEOR_MAX_INT_T_VALUE / 1000) {
            return METEOR_ERROR;
        }

        value *= 1000;
    }

    if (total > METEOR_MAX_INT_T_VALUE - value) {
        return METEOR_ERROR;
    }

    return total + value;
}

char *
meteor_conf_set_msec(meteor_conf_t *cf,meteor_command_t *cmd, void *conf)
{
    tokens_array_t tokens = cf->args->elts;
    int *val = conf + cmd->offset;
    if (*val != METEOR_CONF_MSEC_UNSET)
        return "is duplicate";
    // cmd->post:METEOR_CONF_IS_MSEC?METEOR_CONF_IS_SEC?
    int is_sec = cmd->post?1:0;
    *val = meteor_parse_time(tokens[1], is_sec);
    if (*val == METEOR_ERROR) {
        return "invalid value";
    }
    return METEOR_CONF_OK;
}

static int conf_handle(meteor_conf_t *cf) //deal with token end of ";"
{
    ASSERT( cf != NULL && cf->args->nelts > 0);
    tokens_array_t tokens;
    tokens = cf->args->elts;
    int found = 0;
    char *rv;
    meteor_command_t *cmd = meteor_conf_all_commands[cf->domain];

    for (;cmd->name;cmd++)
    {
        if ( !strcmp(tokens[0],cmd->name))
        {
            found = 1;
            switch(cmd->type)
            {
                case METEOR_CONF_1MORE:
                    if(cf->args->nelts < 2)
                    {
                        goto invalid;
                    }
                    break;
                case METEOR_CONF_2MORE:
                    if(cf->args->nelts < 3)
                    {
                        goto invalid;
                    }
                    break;
                default:
                    if (cf->args->nelts > METEOR_CONF_MAX_ARGS + 1)
                    {
                        goto invalid;
                    }
                    else if(!(argument_number[cf->args->nelts - 1] & cmd->type ))
                    {
                        goto invalid;
                    }
                    else
                    {
                       break;
                    }
            }                 

            rv = cmd->set(cf,cmd,cf->config);

            if (rv == METEOR_CONF_OK)
            {
                return METEOR_OK;
            }
            else if( rv == METEOR_CONF_ERROR)
            {
                return METEOR_ERROR;
            }
            else
            {
                meteor_conf_log_error(LL_ERROR,cf,"\"%s\" directive %s",tokens[0],rv);
                return METEOR_ERROR;
            }           
            return METEOR_ERROR;
        invalid:
                meteor_conf_log_error(LL_ERROR,cf,"invalid number of arguments in \"%s\" directive,may lose a \";\"",tokens[0]);
                return METEOR_ERROR;  
        }
    }

    if (found)
    {
        meteor_conf_log_error(LL_ERROR,cf,"\"%s\" directive is not allowed here",tokens[0]);
    }
    else
    {
        meteor_conf_log_error(LL_ERROR,cf,"unknown directive \"%s\"",tokens[0]);
    }                         
    return METEOR_ERROR;
}

void print_conf_time_value( char *name, int value )
{
	if( value >=1000*24*3600 ){
		printf( "\t%-16s\t= %d days(%dms)\n", name, value/(1000*24*3600), value);
		return;
	}
	if( value >=1000*3600 ){
		printf( "\t%-16s\t= %d hours(%dms)\n", name, value/(1000*3600), value);
		return;
	}
	if( value >=1000*60 ){
		printf( "\t%-16s\t= %d minutes(%dms)\n", name, value/(1000*60), value);
		return;
	}
	if( value >=1000 ){
		printf( "\t%-16s\t= %d seconds(%dms)\n", name, value/(1000), value);
		return;
	}
	printf( "\t%-16s\t= %d seconds\n", name, value);
}

void print_conf_int_value( char *name, int value )
{
	if( value>0 ){
		printf( "\t%-16s\t= %d\n", name, value );
		return;
	}
	printf( "\t%-16s\t= %s\n", name, "(default)" );
}

void print_conf_enum_value( meteor_conf_enum_t *enum_name, char *name, int value )
{
	meteor_conf_enum_t *e = enum_name;
	for( ; e->name; e++ ){
		if( e->value == value )
			break;
	}
	if( e->name ){
		printf( "\t%-16s\t= %s\n", name, e->name );
		return;
	}
	printf( "\t%-16s:\t= %s\n", name, "default" );
}

void print_config(socks_module_config_t *cf)
{
    printf("\033[1mmain:\033[0m\n");
    print_conf_str_value(user,cf->user_name);
    print_conf_enum_value( daemon_modes, "daemon_mode",cf->daemon_mode);
    print_conf_int_value("worker_processes",cf->workers);
    print_conf_int_value("worker_max_sessions",cf->worker_max_sessions);
    print_conf_str_value(pid,cf->pid_file_name);

    print_new_line(sys_log);
    print_conf_enum_value( log_modes, "mode",cf->sys_log_mode);
    print_conf_enum_value( log_levels, "level",cf->sys_log_level);
    print_conf_str_value(file,cf->sys_log_file_name);
    print_conf_time_value( "rotate",cf->sys_log_rotate_interval*1000);

    print_new_line(flow_log);
    print_conf_str_value(file,cf->flow_log_file_name);
    print_conf_time_value( "rotate",cf->flow_log_rotate_interval*1000);

    print_new_line(redis_server);
    print_conf_str_value(host,cf->redis_host);
    print_conf_int_value("port",cf->redis_port);

    print_new_line(timer);
    print_conf_time_value("order_check",cf->order_check_interval);              
    print_conf_time_value("order_update",cf->order_update_interval);            
    print_conf_time_value("order_event_check",cf->order_event_check_interval);  
    print_conf_time_value("order_frozen_timeout",cf->order_frozen_timeout);             
    print_conf_time_value("order_idle_timeout",cf->order_idle_timeout);                 
    print_conf_time_value("session_idle_timeout",cf->session_idle_timeout);             
    print_conf_time_value("activity_update",cf->activity_update_interval);      
    print_conf_time_value("activity_check",cf->activity_check_interval);        
    print_conf_time_value("pool_defrag",cf->pool_defrag_interval);              
    print_conf_int_value ("pool_defrag_size",cf->pool_defrag_size);             
    print_conf_time_value("worker_stat_update",cf->worker_stat_update_interval*1000);

    int i;
    socks_worker_config_t *wc = &(cf->worker_config[0]);
    for(i = 0;i<cf->workers;i++,wc++)
    {
        printf("\033[1mworker[%d]:\033[0m\n",i);
        print_conf_str_value(name,wc->worker_name);
        print_conf_str_value(outer_host,wc->outer_host);
        print_conf_int_value("listen_port",wc->listen_port);
        print_conf_int_value("backlog",wc->listen_backlog);
        print_conf_int_value("recv_buf",wc->recv_buf_size);
        print_conf_int_value("send_buf",wc->send_buf_size);
        print_conf_int_value("reuseaddr",wc->reuseaddr);
        print_conf_int_value("keepalive",wc->keepalive);
        print_conf_int_value("max_sessions",wc->max_sessions);
    }
}

void meteor_conf_unset(socks_module_config_t *config)
{

    strcpy(config->user_name,METEOR_CONF_STR_UNSET);
    strcpy(config->pid_file_name,METEOR_CONF_STR_UNSET);
    strcpy(config->working_dir,METEOR_CONF_STR_UNSET);
    config->daemon_mode = METEOR_CONF_FLAG_UNSET;
    config->workers = METEOR_CONF_INT_UNSET;
    config->worker_max_sessions = METEOR_CONF_INT_UNSET;
    config->user_id = METEOR_CONF_UINT_UNSET;

    //redis-server
    strcpy(config->redis_host,METEOR_CONF_STR_UNSET);
    config->redis_port = METEOR_CONF_INT_UNSET;

    //timer
    config->order_check_interval = METEOR_CONF_MSEC_UNSET;
    config->order_update_interval = METEOR_CONF_MSEC_UNSET;
    config->order_idle_timeout = METEOR_CONF_MSEC_UNSET;
    config->order_frozen_timeout = METEOR_CONF_MSEC_UNSET;
    config->order_event_check_interval = METEOR_CONF_MSEC_UNSET;

    config->activity_update_interval = METEOR_CONF_MSEC_UNSET;
    config->activity_check_interval = METEOR_CONF_MSEC_UNSET;

    config->session_idle_timeout = METEOR_CONF_MSEC_UNSET;
    config->worker_stat_update_interval = METEOR_CONF_MSEC_UNSET;
    config->pool_defrag_interval = METEOR_CONF_MSEC_UNSET;

    config->pool_defrag_size = METEOR_CONF_INT_UNSET;

    //sys_log
    config->sys_log_mode = METEOR_CONF_INT_UNSET;
    config->sys_log_level = METEOR_CONF_INT_UNSET;
    config->sys_log_rotate_interval = METEOR_CONF_MSEC_UNSET;
    strcpy(config->sys_log_file_name,METEOR_CONF_STR_UNSET);

    //flow_log
    config->flow_log_rotate_interval = METEOR_CONF_MSEC_UNSET;
    strcpy(config->flow_log_file_name,METEOR_CONF_STR_UNSET);


    //workers
    int i;
    socks_worker_config_t *wc = &config->worker_config[0];
    for (i = 0;i<MAX_WORKERS;i++,wc++)
    {
        strcpy(wc->worker_name,METEOR_CONF_STR_UNSET);

        strcpy(wc->outer_host,METEOR_CONF_STR_UNSET);
        strcpy(wc->listen_host,METEOR_CONF_STR_UNSET);

        wc->listen_port = METEOR_CONF_INT_UNSET;
        wc->listen_backlog = METEOR_CONF_INT_UNSET;
        wc->max_sessions = METEOR_CONF_INT_UNSET;

        wc->recv_buf_size = METEOR_CONF_INT_UNSET;
        wc->send_buf_size = METEOR_CONF_INT_UNSET;

        wc->reuseaddr = METEOR_CONF_INT_UNSET;
        wc->keepalive = METEOR_CONF_INT_UNSET;

		wc->udp_port_start = METEOR_CONF_INT_UNSET;
		wc->udp_port_end = METEOR_CONF_INT_UNSET;     
    }
}

//default value in "setconfig"; if conf_file_val set,override "setconfig"
static int copy_conf_file_val(meteor_conf_t *conf_val,socks_module_config_t *setconfig)
{
    
    if(conf_val->worker_index <= 0)
    {
        meteor_conf_log_error(LL_ERROR,NULL,"there is no worker block");  //TODO: not equal?? more detail???
        return METEOR_ERROR;
    }

    socks_module_config_t *cf = conf_val->config;

    // should before the next if (condition)
    copy_conf_value(workers);

    //can't be in check_config(setconfig) cause "conf_val" used. looks not well
    if (conf_val->worker_index != setconfig->workers ) //check after _parse() done
    {
        meteor_conf_log_error(LL_ERROR,NULL,"num(%d) of worker block"
            " not equal to worker_processes(%d)",conf_val->worker_index,setconfig->workers); 
        return METEOR_ERROR;
    }

    copy_conf_str_value(user_name);
    copy_conf_value(user_id);
    copy_conf_str_value(working_dir);
    copy_conf_value(daemon_mode);
    
    copy_conf_value(worker_max_sessions);
    copy_conf_str_value(pid_file_name);

    copy_conf_value(sys_log_mode);
    copy_conf_value(sys_log_level);
    copy_conf_str_value(sys_log_file_name);
    copy_conf_value(sys_log_rotate_interval);

    copy_conf_str_value(flow_log_file_name);
    copy_conf_value(flow_log_rotate_interval);

    copy_conf_str_value(redis_host);
    copy_conf_value(redis_port);

    copy_conf_value(order_check_interval);
    copy_conf_value(order_update_interval);
    copy_conf_value(order_event_check_interval);
    copy_conf_value(order_frozen_timeout);
    copy_conf_value(order_idle_timeout);
    copy_conf_value(session_idle_timeout);
    copy_conf_value(activity_update_interval);
    copy_conf_value(activity_check_interval);
    copy_conf_value(pool_defrag_interval);
    copy_conf_value(pool_defrag_size);
    copy_conf_value(worker_stat_update_interval);
    int i;
    socks_worker_config_t *wc          = &(cf->worker_config[0]);
    socks_worker_config_t *setworker   = &(setconfig->worker_config[0]);
    // i < ???
    for(i = 0;i < conf_val->worker_index ;i++,wc++,setworker++)
    {
        copy_worker_str_value(worker_name);
        copy_worker_str_value(outer_host);
        
        copy_worker_str_value(listen_host);
        copy_worker_value(listen_port);
        copy_worker_value(listen_backlog);
        copy_worker_value(recv_buf_size);
        copy_worker_value(send_buf_size);
        copy_worker_value(reuseaddr);
        copy_worker_value(keepalive);

        copy_worker_value(udp_port_start);
        copy_worker_value(udp_port_end);


        //copy_worker_value(max_sessions);
        // default the golobal worker_max_sessions
        if ( wc->max_sessions == METEOR_CONF_INT_UNSET )
            setworker->max_sessions = setconfig->worker_max_sessions; 
        else
            setworker->max_sessions = wc->max_sessions;

        //copy_worker_outer_addr(outer_host,outer_addr_cache);
        struct hostent *hnet = gethostbyname(setworker->outer_host);
        if(hnet)
        {
            setworker->outer_addr_cache = *(struct in_addr*)(hnet->h_addr_list[0]);            
        } 
        else
        {
            meteor_conf_log_error(LL_ERROR,NULL,"worker \"%s\" error",wc->outer_host);
            return METEOR_ERROR;
        }
    }

    return METEOR_OK;
}

int check_config(socks_module_config_t *config)
{
    //TODO: should check  value>=0 ??
    if ( config->order_check_interval > config->order_update_interval)
    {
        meteor_conf_log_error(LL_ERROR,NULL,"order_update shouldn't less than order_check");
        return METEOR_ERROR;
    } 
    if ( config->order_idle_timeout > config->order_frozen_timeout)
    {
        meteor_conf_log_error(LL_ERROR,NULL,"order_frozen shouldn't less than order_idle");
        return METEOR_ERROR;
    } 
    if (config->order_idle_timeout < config->session_idle_timeout  )
    {
        meteor_conf_log_error(LL_ERROR,NULL,"order_idle shouldn't less than session_idle");
        return METEOR_ERROR;
    } 
    if (config->activity_check_interval > config->activity_update_interval)
    {
        meteor_conf_log_error(LL_ERROR,NULL,"activity_update shouldn't less than activity_check");
        return METEOR_ERROR;
    }

    int i;
    for (i = 0; i < config->workers; i++)
    {
    	if ( config->worker_config[i].udp_port_start > config->worker_config[i].udp_port_end )
    	{
    		meteor_conf_log_error(LL_ERROR,NULL,"udp_port_end shouldn't less than udp_port_start");
        	return METEOR_ERROR;
    	}
    }



    return METEOR_OK;
}

int read_config(const char* config_file_name,socks_module_config_t *setconfig) // setconfig name?
{
    ASSERT ( setconfig != NULL);
    char            *rv;
    meteor_conf_t   cf;
    socks_module_config_t tmp_config;


    if (access(config_file_name,R_OK) == -1)
    {
        fprintf( stderr, "read_config(\"%s\") failed, %s", config_file_name, strerror(errno) );
        return METEOR_ERROR;
    }
    if (meteor_token_array_create(&cf) < 0)
    {
        meteor_conf_log_error(LL_ERROR,NULL,"meteor_token_array_create() failed");
        return METEOR_ERROR;
    }

    cf.config = &tmp_config; 
    meteor_conf_unset(cf.config);

    rv = meteor_conf_parse(&cf,config_file_name);

    meteor_token_array_destroy(&cf); //not well name 

    if ( rv == METEOR_CONF_ERROR)
    {
        meteor_conf_log_error(LL_ERROR,NULL,"parse \"%s\" failed",config_file_name);
        return METEOR_ERROR;
    }
    
    return copy_conf_file_val(&cf,setconfig); 
}
