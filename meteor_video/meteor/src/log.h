#ifndef _LOG_H
#define _LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* the log mode */
#define LOG_MODE_NONE       0x00
#define LOG_MODE_CONSOLE    0x01
#define LOG_MODE_SYSTEM     0x02
#define LOG_MODE_FILE       0x03

/*
* the log level.
*/
#define LL_NONE     0x00
#define LL_FLOW     0x01
#define LL_ERROR    0x02
#define LL_WARNING  0x03
#define LL_NOTICE   0x04
#define LL_INFO     0x05
#define LL_DEBUG    0x06


#define SYS_LOG_DEFAULT_PATH        "../logs/sys.log"
#define FLOW_LOG_DEFAULT_PATH       "../logs/flow.log"

struct log_struct {
    int mode;
    int level;
    pthread_mutex_t lock;
    pthread_mutexattr_t lock_attr; 

    char path[512];

    int fd;
    long rotate_interval;   //日志轮换的间隔时间,单位秒
    long rotate_last_stamp; //日志轮换的时间,单位秒
    long disk_full_stamp;
};

#include <assert.h>
#define ASSERT assert

int log_init( int listen_port );

void log_exit(void);

int sys_log( int level, const char *format, ...);

int flow_log( const char *format, ...);

long get_disk_full_stamp_of_flow_log();

long get_disk_full_stamp_of_sys_log();

long get_disk_full_stamp_of_log();


#endif /* _LOG_H */

