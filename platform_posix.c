#define _GNU_SOURCE
#include "platform.h"
#include <sys/mman.h>
#include <sys/resource.h>
#include <termios.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
static struct termios saved;
static int active;
static void (*emergency_cleanup)(void);
void platform_set_emergency_cleanup(void (*fn)(void)) { emergency_cleanup=fn; }
void wipe(void *p,size_t n) { volatile unsigned char *v=p; while(n--) *v++=0; }
void *locked_alloc(size_t n) {
    void *p=mmap(NULL,n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(p==MAP_FAILED) return NULL;
#if defined(TEST_LOCK_FAILURE)
    munmap(p,n); return NULL;
#endif
#if defined(TEST_ARENA_LOCK_FAILURE)
    if(n>STACK_BYTES) { munmap(p,n); return NULL; }
#endif
    if(mlock(p,n)) { munmap(p,n); return NULL; }
#ifdef __linux__
    if(madvise(p,n,MADV_DONTDUMP)) { wipe(p,n); munlock(p,n); munmap(p,n); return NULL; }
#endif
    return p;
}
void locked_free(void *p,size_t n) { if(p) { wipe(p,n); munlock(p,n); munmap(p,n); } }
struct secure_thread { pthread_t tid; void *stack; };
int secure_thread_create(secure_thread **out,void *(*fn)(void *),void *arg) {
    secure_thread *t=calloc(1,sizeof(*t)); if(!t) return -1;
    t->stack=locked_alloc(STACK_BYTES);
    if(!t->stack) { free(t); return -1; }
    pthread_attr_t attr; int rc=pthread_attr_init(&attr);
    if(!rc) { rc=pthread_attr_setstack(&attr,t->stack,STACK_BYTES);
        if(!rc) rc=pthread_create(&t->tid,&attr,fn,arg);
        pthread_attr_destroy(&attr); }
    if(rc) { locked_free(t->stack,STACK_BYTES); free(t); return -1; }
    *out=t; return 0;
}
int secure_thread_join(secure_thread *t,void **result) {
    if(pthread_join(t->tid,result)) return -1;
    locked_free(t->stack,STACK_BYTES); free(t); return 0;
}
int platform_init(size_t memory) {
    (void)memory; struct rlimit limit={0,0};
    if(setrlimit(RLIMIT_CORE,&limit)) return -1;
#ifdef __linux__
    if(prctl(PR_SET_DUMPABLE,0,0,0,0)) return -1;
#endif
    return 0;
}
int terminal_is_interactive(void) { return isatty(0)&&isatty(1)&&isatty(2); }
static void interrupted(int sig) { if(emergency_cleanup) emergency_cleanup(); terminal_leave(); _exit(128+sig); }
int terminal_enter(void) {
    if(tcgetattr(0,&saved)) return -1;
    struct termios hidden=saved; hidden.c_lflag |= ECHO|ICANON;
    if(tcsetattr(0,TCSAFLUSH,&hidden)) return -1;
    active=1; signal(SIGINT,interrupted); signal(SIGTERM,interrupted); signal(SIGHUP,interrupted);
    fputs("\033[?1049h\033[2J\033[H",stdout); return 0;
}
void terminal_leave(void) {
    if(active) { const char s[]="\033[2J\033[H\033[?1049l"; write(1,s,sizeof(s)-1); tcsetattr(0,TCSANOW,&saved); active=0; }
}
int terminal_readline(char *out,size_t cap,size_t *len) {
    *len=0;
    while(*len<cap-1) {
        ssize_t rc=read(0,out+*len,1);
        if(rc<0 && errno==EINTR) continue;
        if(rc!=1) return -1;
        if(out[*len]=='\n') { out[*len]=0; return 0; }
        ++*len;
    }
    return -1;
}
double monotonic_seconds(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
void platform_shutdown(void) { terminal_leave(); }
