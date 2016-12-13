#ifndef CLIENT_PROCESS_H_
#define CLIENT_PROCESS_H_

#include <signal.h>

#define PROCESS_SINGLE     0
#define PROCESS_MASTER     1
#define PROCESS_SIGNALLER  2
#define PROCESS_WORKER     3
#define WORKER_NAME_LEN	   32  

#define PROCESS_RESPAWN       -3
#define PROCESS_JUST_RESPAWN  -4

#define MAX_PROCESS_NUM		1024
#define INVALID_PID			-1

typedef struct process_signal_status_s process_signal_status_t;
typedef struct socks_signal_s socks_signal_t;

struct socks_signal_s{
    int    signo;
    char   *signame;
    char   *name;
    void  (*handler)(int signo);
};

// linux process info and status
struct process_signal_status_s
{
	pid_t pid;
	char name[WORKER_NAME_LEN];
	int worker;
	int status;
	
	unsigned int to_quit:1;
	unsigned int to_terminate:1;
	unsigned int to_respawn:1;
	
	unsigned int status_exiting:1;
	unsigned int status_exited:1;
};

int send_signal_to_master_process(char *signame);
void send_signal_to_worker_process(int signo) ;
void  signal_handler(int signo);
void block_process_signal_mask(sigset_t *set);
void socks_init_signals();
void print_stack_of_signal( int no );
char *get_name_of_signal( int signo );
pid_t spawn_process(int worker, int respawn);
void wait_child_process_get_status(void);
int reap_children();
int meteor_daemon();
void meteor_set_master_process_title(int argc, char *const *argv);
void meteor_set_process_title(char *title);
int meteor_init_set_proc_title();
int meteor_save_argv( int argc, char *const *argv);
u_char *meteor_cpystrn(u_char *dst, u_char *src, size_t n);
void func_stack_dump(int err);

#endif

