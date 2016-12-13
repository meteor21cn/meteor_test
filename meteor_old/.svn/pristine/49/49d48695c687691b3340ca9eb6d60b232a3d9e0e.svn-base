
#include <sys/types.h>
#include <sys/socket.h>    
#include <sys/epoll.h>    
#include <sys/ioctl.h>
#include <sys/timeb.h>
#include <netinet/in.h>    
#include <arpa/inet.h>
#include <net/if.h>
#include <math.h>
#include <fcntl.h>    
#include <unistd.h>    
#include <stdio.h>    
#include <errno.h>  
#include <stdlib.h>  
#include <netdb.h>  
#include <string.h> 
#include <signal.h>

#include "client.h"
#include "client_process.h"

sig_atomic_t  to_reap;
sig_atomic_t  to_terminate;
sig_atomic_t  to_quit;
sig_atomic_t  to_reload;

int process_slot;
int last_process;
int	status_exiting;

static process_signal_status_t processes[MAX_PROCESS_NUM];
static u_char  master_process[] = "client:master process";

static int  g_argc;
static char **g_argv;
static char **g_os_argv;
static char *g_os_argv_last;

extern char **environ;

extern socks_client_process_t client_workers[32];
extern int process_type;

static socks_signal_t  signals[] = {
    { SIGSYS,  "SIGSYS", "", print_stack_of_signal },
    { SIGPIPE, "SIGPIPE", "", print_stack_of_signal },
	{ SIGHUP,  "SIGHUP", "reload", signal_handler },	
    { SIGQUIT, "SIGQUIT", "quit", signal_handler },        /* slowly */
    { SIGTERM, "SIGTERM", "stop", signal_handler },        /* fast   */
    { SIGCHLD, "SIGCHLD", "sigchld", signal_handler },
    { 0, NULL, "", NULL }
};

static char _signal_name[64][32] = {
	"1: SIGHUP", "2: SIGINT", "3: SIGQUIT", "4: SIGILL",
	"5: SIGTRAP", "6: SIGABRT", "7: SIGBUS", "8: SIGFPE",
	"9: SIGKILL", "10: SIGUSR1", "11: SIGSEGV", "12: SIGUSR2",
	"13: SIGPIPE", "14: SIGALRM", "15: SIGTERM", "16: SIGSTKFLT",
	"17: SIGCHLD", "18: SIGCONT", "19: SIGSTOP", "20: SIGTSTP",
	"21: SIGTTIN", "22: SIGTTOU", "23: SIGURG", "24: SIGXCPU",
	"25: SIGXFSZ", "26: SIGVTALRM", "27: SIGPROF", "28: SIGWINCH",
	"29: SIGIO", "30: SIGPWR", "31: SIGSYS", "34: SIGRTMIN",
	"35: SIGRTMIN+1", "36: SIGRTMIN+2", "37: SIGRTMIN+3", "38: SIGRTMIN+4",
	"39: SIGRTMIN+5", "40: SIGRTMIN+6", "41: SIGRTMIN+7", "42: SIGRTMIN+8",
	"43: SIGRTMIN+9", "44: SIGRTMIN+10", "45: SIGRTMIN+11", "46: SIGRTMIN+12",
	"47: SIGRTMIN+13", "48: SIGRTMIN+14", "49: SIGRTMIN+15", "50: SIGRTMAX-14",
	"51: SIGRTMAX-13", "52: SIGRTMAX-12", "53: SIGRTMAX-11", "54: SIGRTMAX-10",
	"55: SIGRTMAX-9", "56: SIGRTMAX-8", "57: SIGRTMAX-7", "58: SIGRTMAX-6",
	"59: SIGRTMAX-5", "60: SIGRTMAX-4", "61: SIGRTMAX-3", "62: SIGRTMAX-2",
	"63: SIGRTMAX-1", "64: SIGRTMAX" };

// http://blog.csdn.net/yusiguyuan/article/details/31378029
void block_process_signal_mask(sigset_t *set)
{
	sigemptyset(set);
	sigaddset(set, SIGCHLD);
	sigaddset(set, SIGALRM);
	sigaddset(set, SIGIO);
	sigaddset(set, SIGINT);
	sigaddset(set, SIGHUP);		// reload
	sigaddset(set, SIGWINCH);	// noaccept
	sigaddset(set, SIGQUIT);	// shutdown
	sigaddset(set, SIGTERM);	// terminate
   
	if (sigprocmask(SIG_BLOCK, set, NULL) == -1) {
		printf( "sigprocmask error\n");
		exit(-1);
	}
}
pid_t spawn_process( int worker, int respawn)
{
    pid_t  pid;
    int  s;
    
	if (respawn >= 0) {
		s = respawn;
	}
	else {
		for (s = 0; s < last_process; s++) {
			if (processes[s].pid == -1) {
				break;
			}
		}

		if (s == MAX_PROCESS_NUM) { 	 
			return INVALID_PID;
		}
	}

    process_slot = s;
    pid = fork();
    switch (pid) {
	    case -1:
			printf( "fork() failed while spawning worker process, port:%d, %s", 
				client_workers[worker].sockd_port, strerror(errno) );
	        return INVALID_PID;

	    case 0:
			pid = getpid();
			process_type = PROCESS_WORKER;	// init worker process info
			
			sigset_t set;
			sigemptyset(&set);
			if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
				printf( "sigprocmask() failed, %s", strerror(errno) );
			}
			
			char title[32];
			sprintf( title, "client:worker-%d", client_workers[worker].sockd_port);
			meteor_set_process_title(title);
			
	        start_client_process( &client_workers[worker] );
	        break;

	    default:
	        break;
    }

	printf( "client worker-%d started [pid:%d]", client_workers[worker].sockd_port, pid );

    processes[s].pid = pid;
    processes[s].status_exited= 0;
   	processes[s].status_exiting= 0;

    if (respawn >= 0) {
        return pid;
    }

	processes[s].to_respawn = 1;
    processes[s].worker = worker;
	sprintf( processes[s].name, "client:worker-%d", client_workers[worker].sockd_port );

    if (s == last_process) {
        last_process++;
    }
    return pid;
}

void wait_child_process_get_status(void)
{
    int              status;
    char            *pname;
    pid_t            pid;
    int              err;
    int              i;
    int              one;

    one = 0;
    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = errno;

            if (err == EINTR) {
                continue;
            }

            if (err == ECHILD && one) {
                return;
            }

            if (err == ECHILD) {
                printf( "ECHILD, waitpid() failed. %s\n", strerror(err) );
                return;
            }

            printf( "waitpid() failed. %d:%s\n", err, strerror(err) );
            return;
        }


        one = 1;
        pname = "unknown process";
        for (i = 0; i < last_process; i++) {
            if (processes[i].pid == pid) {
                processes[i].status = status;
                processes[i].status_exited = 1;
                processes[i].status_exiting= 0;
                pname = processes[i].name;
                break;
            }
        }

		int signo = WTERMSIG(status);
        if ( signo ) {
			printf( "%s [%d] exited on signal %s[%d]", pname, pid, get_name_of_signal(signo), signo );
        } 
		else {
			printf( "%s [%d] exited with code %d", pname, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && processes[i].to_respawn) {  
			printf( "%s [%d] exited with fatal code %d, cannot be respawned", pname, pid, WEXITSTATUS(status));
            processes[i].to_respawn = 0;
        }
    }
}

int reap_children()
{
    int n, i;
    int live = 0;

    for (i = 0; i < last_process; i++) {
        if (processes[i].pid == -1) {
            continue;
        }

        if (processes[i].status_exited) {
            
            if (processes[i].to_respawn && !processes[i].status_exiting && !to_terminate && !to_quit ) {
                if (spawn_process( processes[i].worker, i ) == INVALID_PID) {
					printf( "could not respawn %s", processes[i].name );
					continue;
                }

                live = 1;
                continue;
            }
            
            if (i == last_process - 1) {
                last_process--;

            }
			else {
                processes[i].pid = -1;
            }

        } 
		else if (processes[i].status_exiting ) {
            live = 1;
        }
    }

    return live;
}

char *get_name_of_signal( int signo )
{
    if( signo >= 1 && signo <= 64)   
        return _signal_name[signo-1];
    return "unknown signal";
}


void print_stack_of_signal( int signo )
{
    int err = errno;
    char *name = get_name_of_signal(signo);
	if( strcmp( "unknown signal", name ) !=0 )
		printf( "[%s] stack frames:", name );
    else
        printf( "[unknown sig: %d] stack frames:", signo);
    func_stack_dump(0);

    if( SIGPIPE != signo && SIGSYS != signo )
        exit(-1);
	errno = err;
}


void send_signal_to_worker_process(int signo) 
{
    //print_stack_of_signal(signo);
    int i = 0;

	socks_signal_t * sig;
	for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
	
    for( ; i< last_process; i++) {
		printf( "child process: %d %d exiting:%d exited:%d to_respawn:%d",
            i, processes[i].pid, processes[i].status_exiting, processes[i].status_exited, processes[i].to_respawn );
		
        if (processes[i].pid == -1) {
            continue;
        }
        
        if (processes[i].status_exiting  && signo == SIGQUIT) {
            continue;
        }

        processes[i].to_respawn = 0;
        if (kill( processes[i].pid, signo ) == -1) {      
            int err = errno;
            printf( "kill(%d, %s) failed, %s", processes[i].pid, sig->signame, strerror(err) );
            if (err == ESRCH) { // 没有指定进程号
                processes[i].status_exited = 1;
                processes[i].status_exiting = 0;
                to_reap = 1;
            }
            
            continue;
        }

		processes[i].status_exiting = 1;
		
    }
	
}


void  signal_handler(int signo)
{
    int err = errno;
	char *action = "";
	pid_t pid = getpid();
	
	socks_signal_t * sig;
	for (sig = signals; sig->signo != 0; sig++) {
        if (sig->signo == signo) {
            break;
        }
    }
	
    switch(process_type) {
    case PROCESS_SINGLE:
	case PROCESS_MASTER:
        switch (signo) {
	        case SIGQUIT:
				to_quit = 1;
           		action = "shutting down";
	            break;
				
	        case SIGTERM:
	            action = "exiting";
	            to_terminate = 1;
	            break;

	        case SIGHUP:
	            to_reload = 1;
				action = "reloading config";
				break;
				
	        case SIGCHLD:
	            to_reap = 1;
	            break;
        }   
    	printf( "client master process [pid:%d] received signal #%d(%s). %s", pid, signo, sig->name, action );
        break;
		
    case PROCESS_WORKER:
        switch (signo) {
	        case SIGQUIT:
	            action = "shutting down";
	            to_quit = 1;
	            break;
				
	        case SIGTERM:
			case SIGINT:
	            action = "exiting";
	            to_terminate = 1;
	            break;
				
			case SIGHUP:
			case SIGIO:
				action = ", ignoring";
				break;
		}
    	printf( "client worker process [pid:%d] received signal #%d(%s). %s", pid, signo, sig->name, action );
        break;
    }
	
    if (signo == SIGCHLD) {
        wait_child_process_get_status();
    }
	errno = err;
}

void socks_init_signals()
{
    socks_signal_t     *sig;
    struct sigaction   sa;

    for (sig = signals; sig->signo != 0; sig++) {
        memset(&sa, 0, sizeof(struct sigaction) );
        sa.sa_handler = sig->handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(sig->signo, &sa, NULL) == -1) {
            printf( "[%s:%d] sigaction failed, sig:%s", __func__, __LINE__, sig->signame );
			return;
        }
    }
}

int meteor_daemon()
{
    int  fd;

    switch (fork()) {
    case -1:
        printf( "fork() failed. %s", strerror(errno) );
        return -1;

    case 0:
        break;

    default:
        exit(0);
    }

    if (setsid() == -1) {
        printf( "setsid() failed. %s", strerror(errno) );
        return -1;
   }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        printf( "open(\"/dev/null\") failed. %s", strerror(errno) );
        return -1;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        printf( "dup2(STDIN) failed. %s", strerror(errno) );
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        printf( "dup2(STDOUT) failed. %s", strerror(errno) );
        return -1;
    }

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
			printf( "close() failed. %s", strerror(errno) );
			return -1;
        }
    }

    return 0;
}

u_char *meteor_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}


int meteor_save_argv( int argc, char *const *argv)
{

    size_t     len;
    int  i;

    g_os_argv = (char **) argv;
    g_argc = argc;

    g_argv = malloc((argc + 1) * sizeof(char *));
    if (g_argv == NULL) {
        return -1;
    }

    for (i = 0; i < argc; i++) {
        len = strlen(argv[i]) + 1;

        g_argv[i] = malloc(len);
        if (g_argv[i] == NULL) {
            return -1;
        }

        (void) meteor_cpystrn((u_char *) g_argv[i], (u_char *) argv[i], len);
    }

    g_argv[i] = NULL;

    return 0;
}

int meteor_init_set_proc_title()
{
    u_char      *p;
    size_t       size;
    int   i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    p = malloc(size);
    if (p == NULL) {
        return -1;
    }

    g_os_argv_last = g_os_argv[0];

    for (i = 0; g_os_argv[i]; i++) {
        if (g_os_argv_last == g_os_argv[i]) {
            g_os_argv_last = g_os_argv[i] + strlen(g_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (g_os_argv_last == environ[i]) {

            size = strlen(environ[i]) + 1;
            g_os_argv_last = environ[i] + size;

            meteor_cpystrn(p, (u_char *) environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    g_os_argv_last--;

    return 0;
}

void meteor_set_process_title(char *title)
{
    u_char     *p;
    g_os_argv[1] = NULL;
    
    p = meteor_cpystrn((u_char *) g_os_argv[0], (u_char *) title, g_os_argv_last-g_os_argv[0]);
    int len = g_os_argv_last - (char *) p;
    if (len>0) {
        memset( p, '\0', len );
    }
}

void meteor_set_master_process_title(int argc, char *const *argv)
{
	if( meteor_save_argv( argc,argv )< 0 )
		exit(1);
	
	if( meteor_init_set_proc_title() < 0 )
		exit(1);
	
    int size = sizeof(master_process);
	int i = 0;
    for ( ; i < g_argc; i++) {
        size += strlen(g_argv[i]) + 1;
    }

    char *title = malloc(size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    char *p = memcpy(title, master_process, sizeof(master_process) - 1);
	p += sizeof(master_process) - 1;
    for (i = 0; i < g_argc; i++) {
        *p++ = ' ';
        p = meteor_cpystrn(p, (u_char *) g_argv[i], size);
    }
	
    meteor_set_process_title(title);

}

void func_stack_dump(int err)
{
    void *stack_p[32];
    char **stack_info;

    int size = backtrace( stack_p, sizeof(stack_p));
    stack_info = (char **)backtrace_symbols( stack_p, size);
    if( stack_info == NULL )
        return;

    if( err )
        printf( "errno:%d:%s, %d stack frames:", err, strerror(err), size );
    int i = 0;
    for( ; i < size; i++)
        printf( "frame #%d:%s", i, stack_info[i]);

    free( stack_info);
    fflush(NULL);
}


