
#ifndef METEOR_CONF_H_
#define METEOR_CONF_H_

#include <unistd.h>
#include "sockd.h"
//#include <types.h>
typedef  struct  stat  file_info_t;

#define METEOR_CONF_BUFFER  4096
#define METEOR_CONF_MAX_TOKEN_LEN 	60  // single token_str length(daemon  ...)
#define METEOR_CONF_INIT_TOKEN_NUM	17  // 
#define METEOR_CONF_NEW_ALLOC_NUM 	4  // TODO：mem

#define METEOR_CONF_OK NULL  
#define METEOR_CONF_ERROR (void *)-1 

#define METEOR_OK  0     // ';' found
#define METEOR_ERROR -1

#define METEOR_CONF_BLOCK_START 1
#define METEOR_CONF_BLOCK_DONE 2
#define METEOR_CONF_FILE_DONE 3

#define LF 		(u_char) '\n'
#define CR 		(u_char) '\r'
#define CRLF 			"\r\n"

#define DOMAIN_MAIN  0
#define DOMAIN_SYS_LOG 1
#define	DOMAIN_FLOW_LOG 2
#define DOMAIN_REDIS_SERVER 3
#define DOMAIN_TIMER 4
#define DOMAIN_WORKER 5

#define ERROR_DOMAIN  -1  // unsigned:0xffffff... ? or Ox00 | 


#define METEOR_CONF_NOARGS      0x00000001
#define METEOR_CONF_TAKE1       0x00000002
#define METEOR_CONF_TAKE2       0x00000004
#define METEOR_CONF_TAKE3       0x00000008
#define METEOR_CONF_TAKE4       0x00000010
#define METEOR_CONF_TAKE5       0x00000020
#define METEOR_CONF_TAKE6       0x00000040
#define METEOR_CONF_TAKE7       0x00000080

#define METEOR_CONF_1MORE		0x00000100
#define METEOR_CONF_2MORE		0x00000200

#define METEOR_CONF_MAX_ARGS    16 // max_workers listen_port??

#define METEOR_CONF_TAKE12      (METEOR_CONF_TAKE1|METEOR_CONF_TAKE2)
#define METEOR_CONF_TAKE13      (METEOR_CONF_TAKE1|METEOR_CONF_TAKE3)

#define METEOR_CONF_TAKE23      (METEOR_CONF_TAKE2|METEOR_CONF_TAKE3)

#define METEOR_CONF_TAKE123     (METEOR_CONF_TAKE1|METEOR_CONF_TAKE2|METEOR_CONF_TAKE3)
#define METEOR_CONF_TAKE1234    (METEOR_CONF_TAKE1|METEOR_CONF_TAKE2|METEOR_CONF_TAKE3   \
                              |METEOR_CONF_TAKE4)

#if 1
#define METEOR_MAX_INT_T_VALUE  2147483647
#else
#define METEOR_MAX_INT_T_VALUE  9223372036854775807
#endif

#define NOT_NULL			""	
#define METEOR_CONF_IS_MSEC	NULL
#define METEOR_CONF_IS_SEC 	NOT_NULL 

#define METEOR_CONF_UNSET  		-1
#define METEOR_CONF_FLAG_UNSET	-1
#define METEOR_CONF_ENUM_UNSET	-1
#define METEOR_CONF_UINT_UNSET	(unsigned int)-1
#define METEOR_CONF_MSEC_UNSET	-1
#define METEOR_CONF_INT_UNSET 	-1
#define METEOR_CONF_STR_UNSET 	""

#define print_conf_str_value(config,str) 	\
printf("\t%-16s\t= %s\n",#config,str)

#define print_new_line(description) 		\
printf("\033[1m%s:\033[0m\n",#description)

#define meteor_conf_copy_value(conf_file_val, set_conf)      \
    if (conf_file_val != METEOR_CONF_UNSET) {                \
        set_conf = conf_file_val;                            \
    }

#define meteor_conf_copy_str_value(conf_file_val, set_conf)   \
    if (strcmp(conf_file_val,METEOR_CONF_STR_UNSET)) {        \
        strcpy(set_conf,conf_file_val);                       \
    }

// #define meteor_conf_copy_ptr_value(conf_file_val, set_conf)                            \
//     if (conf_file_val == METEOR_CONF_PTR_UNSET) {                                  \
//         set_conf = conf_file_val;                                                      \
//     }

// #define meteor_conf_copy_uint_value(conf_file_val, set_conf)                           \
//     if (conf_file == METEOR_CONF_UINT_UNSET) {                                 \
//         set_conf = conf_file_val;                                                      \
//     }

// #define meteor_conf_copy_msec_value(conf_file_val, set_conf)                           \
//     if (conf_file_val == METEOR_CONF_MSEC_UNSET) {                                 \
//         set_conf = conf_file_val;                                                      \
//     }

typedef struct meteor_conf_s meteor_conf_t;
typedef struct meteor_conf_file_s meteor_conf_file_t;
typedef struct meteor_file_s  meteor_file_t; 
typedef struct meteor_conf_buf_s meteor_conf_buf_t;
typedef struct meteor_array_s meteor_array_t;
typedef struct meteor_command_s meteor_command_t;


typedef char  token[METEOR_CONF_MAX_TOKEN_LEN]; 
typedef token *tokens_array_t;

typedef struct 
{
	char 	*name;
	int   	value;
}meteor_conf_enum_t;

struct meteor_conf_s
{
	char 				*name; // ???
	meteor_array_t	   	*args; //TODO: type
	meteor_conf_file_t 	*conf_file;
	int 				 domain;

	socks_module_config_t *config;
	int 				worker_index;
};	

struct meteor_array_s
{
	size_t 	 size; // 1 elts size
	int 	nelts; // nums of elts
	int 	nalloc;
	void	*elts;
} ;

struct meteor_file_s
{
	int			fd;
	const char 	*name;
	file_info_t info;
	off_t 		offset;
	off_t 		sys_offset;
};

struct meteor_conf_file_s 
{
	meteor_file_t  		file;
	meteor_conf_buf_t   *buf;
	int 				line;
};



struct meteor_conf_buf_s 
{
	u_char *pos;
	u_char *last;

	u_char *start; // start of the buf
	u_char *end;

	meteor_conf_file_t *file;
	off_t file_pos;   
	off_t file_last;
};

struct meteor_command_s{
	char	*name;
	int  	type;
	char 	*(*set)(meteor_conf_t *cf,meteor_command_t *cmd, void *conf);
	int 	offset;
	void	*post;
}; 

typedef struct {
	char 	*name;
	int 	min;
	int 	max;
}post_num_t;

#define meteor_null_command  { NULL, 0, NULL, 0, NULL }


int read_config(const char* config_file_name,socks_module_config_t *setconfig);
int check_config(socks_module_config_t *config);
void print_config(socks_module_config_t *cf);
int meteor_parse_time(char *str, int is_sec); // 1:sec 0:msec, "1y2M3d4h5m6s7ms"

#endif