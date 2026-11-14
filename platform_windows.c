#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "platform.h"
static HANDLE input_handle,output_handle;
static DWORD saved_input,saved_output;
static UINT saved_output_cp;
static int active;
static void (*emergency_cleanup)(void);
void platform_set_emergency_cleanup(void (*fn)(void)) { emergency_cleanup=fn; }
static WCHAR *wide_input;
void wipe(void *p,size_t n) { SecureZeroMemory(p,n); }
void *locked_alloc(size_t n) {
    void *p=VirtualAlloc(NULL,n,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!p) return NULL;
#ifdef TEST_LOCK_FAILURE
    VirtualFree(p,0,MEM_RELEASE); return NULL;
#endif
#ifdef TEST_ARENA_LOCK_FAILURE
    if(n>STACK_BYTES) { VirtualFree(p,0,MEM_RELEASE); return NULL; }
#endif
    if(!VirtualLock(p,n)) { VirtualFree(p,0,MEM_RELEASE); return NULL; }
    return p;
}
void locked_free(void *p,size_t n) { if(p) { wipe(p,n); VirtualUnlock(p,n); VirtualFree(p,0,MEM_RELEASE); } }
struct secure_thread {
    HANDLE handle,ready;
    void *supervisor,*fiber,*stack;
    size_t stack_size;
    void *(*fn)(void *);
    void *arg,*result;
    int startup_error;
};
static VOID WINAPI secure_fiber(void *arg) {
    secure_thread *t=arg;
    MEMORY_BASIC_INFORMATION region;
    unsigned char marker=0;
    SIZE_T queried=VirtualQuery(&marker,&region,sizeof(region));
    if(!queried || region.State!=MEM_COMMIT
       || (region.Protect & (PAGE_GUARD|PAGE_NOACCESS)) || region.RegionSize<STACK_BYTES/2) {
        fprintf(stderr,"Stack inspection failed: query=%zu state=0x%lx protection=0x%lx region=%zu required=%u error=%lu\n",
            (size_t)queried,(unsigned long)(queried?region.State:0),(unsigned long)(queried?region.Protect:0),
            (size_t)(queried?region.RegionSize:0),STACK_BYTES/2,(unsigned long)GetLastError());
        t->startup_error=1; SetEvent(t->ready); SwitchToFiber(t->supervisor); return;
    }
    if(!VirtualLock(region.BaseAddress,region.RegionSize)) {
        fprintf(stderr,"Stack VirtualLock failed: bytes=%zu Windows error=%lu\n",(size_t)region.RegionSize,(unsigned long)GetLastError());
        t->startup_error=1; SetEvent(t->ready); SwitchToFiber(t->supervisor); return;
    }
    t->stack=region.BaseAddress; t->stack_size=region.RegionSize;
    SetEvent(t->ready);
    t->result=t->fn(t->arg);
    SwitchToFiber(t->supervisor);
}
static DWORD WINAPI thread_entry(void *arg) {
    secure_thread *t=arg;
    t->supervisor=ConvertThreadToFiber(NULL);
    if(!t->supervisor) { t->startup_error=1; SetEvent(t->ready); return 1; }
    t->fiber=CreateFiberEx(STACK_BYTES,STACK_BYTES,FIBER_FLAG_FLOAT_SWITCH,secure_fiber,t);
    if(!t->fiber) { t->startup_error=1; SetEvent(t->ready); ConvertFiberToThread(); return 1; }
    SwitchToFiber(t->fiber);
    /* Fiber is now suspended; wipe its entire committed calculation stack. */
    if(t->stack) { wipe(t->stack,t->stack_size); VirtualUnlock(t->stack,t->stack_size); }
    DeleteFiber(t->fiber); ConvertFiberToThread(); return t->startup_error?1:0;
}
int secure_thread_create(secure_thread **out,void *(*fn)(void *),void *arg) {
    secure_thread *t=calloc(1,sizeof(*t)); if(!t) return -1;
    t->fn=fn; t->arg=arg; t->ready=CreateEventW(NULL,TRUE,FALSE,NULL);
    if(!t->ready) { free(t); return -1; }
    t->handle=CreateThread(NULL,0,thread_entry,t,0,NULL);
    if(!t->handle) { CloseHandle(t->ready); free(t); return -1; }
    if(WaitForSingleObject(t->ready,INFINITE)!=WAIT_OBJECT_0 || t->startup_error) {
        WaitForSingleObject(t->handle,INFINITE); CloseHandle(t->handle); CloseHandle(t->ready); free(t); return -1;
    }
    *out=t; return 0;
}
int secure_thread_join(secure_thread *t,void **result) {
    if(WaitForSingleObject(t->handle,INFINITE)!=WAIT_OBJECT_0) return -1;
    if(result) *result=t->result;
    CloseHandle(t->handle); CloseHandle(t->ready); wipe(t,sizeof(*t)); free(t); return 0;
}
int platform_init(size_t memory) {
    saved_output_cp=GetConsoleOutputCP();
    if(saved_output_cp) SetConsoleOutputCP(CP_UTF8);
    SetErrorMode(GetErrorMode()|SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    if(!(GetErrorMode()&SEM_NOGPFAULTERRORBOX)) return -1;
    /* VirtualLock is bounded by the working-set minimum; reserve headroom. */
    SIZE_T required=(SIZE_T)memory+64U*1024U*1024U,minimum,maximum;
    if(!GetProcessWorkingSetSize(GetCurrentProcess(),&minimum,&maximum)) return -1;
    if(minimum<required && !SetProcessWorkingSetSize(GetCurrentProcess(),required,required+16U*1024U*1024U)) return -1;
    wide_input=locked_alloc(INPUT_CAP*sizeof(WCHAR));
    return wide_input?0:-1;
}
int terminal_is_interactive(void) {
    DWORD mode;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),&mode)
        && GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE),&mode)
        && GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE),&mode);
}
static BOOL WINAPI control_handler(DWORD kind) {
    if(kind==CTRL_C_EVENT || kind==CTRL_BREAK_EVENT || kind==CTRL_CLOSE_EVENT || kind==CTRL_LOGOFF_EVENT || kind==CTRL_SHUTDOWN_EVENT) {
        if(emergency_cleanup) emergency_cleanup();
        if(wide_input) wipe(wide_input,INPUT_CAP*sizeof(WCHAR));
        terminal_leave(); TerminateProcess(GetCurrentProcess(),130); return TRUE;
    }
    return FALSE;
}
int terminal_enter(void) {
    input_handle=GetStdHandle(STD_INPUT_HANDLE); output_handle=GetStdHandle(STD_OUTPUT_HANDLE);
    if(!GetConsoleMode(input_handle,&saved_input) || !GetConsoleMode(output_handle,&saved_output)) return -1;
    if(!SetConsoleMode(input_handle,(saved_input|ENABLE_LINE_INPUT|ENABLE_PROCESSED_INPUT)&~ENABLE_ECHO_INPUT)) return -1;
    if(!SetConsoleMode(output_handle,saved_output|ENABLE_VIRTUAL_TERMINAL_PROCESSING)) { SetConsoleMode(input_handle,saved_input); return -1; }
    if(!SetConsoleCtrlHandler(control_handler,TRUE)) { SetConsoleMode(input_handle,saved_input); SetConsoleMode(output_handle,saved_output); return -1; }
    active=1; fputs("\033[?1049h\033[2J\033[H",stdout); return 0;
}
void terminal_leave(void) {
    if(active) {
        const char text[]="\033[2J\033[H\033[?1049l"; DWORD written;
        WriteFile(output_handle,text,sizeof(text)-1,&written,NULL);
        SetConsoleMode(input_handle,saved_input); SetConsoleMode(output_handle,saved_output); active=0;
    }
}
int terminal_readline(char *out,size_t cap,size_t *len) {
    size_t n=0; DWORD got;
    wipe(wide_input,INPUT_CAP*sizeof(WCHAR));
    while(n<INPUT_CAP-1) {
        if(!ReadConsoleW(input_handle,wide_input+n,1,&got,NULL) || got!=1) goto fail;
        if(wide_input[n]=='\n') break;
        ++n;
    }
    if(n==INPUT_CAP-1) goto fail;
    if(n && wide_input[n-1]=='\r') --n;
    int bytes=n?WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide_input,(int)n,out,(int)cap-1,NULL,NULL):0;
    if(n && !bytes) goto fail;
    *len=(size_t)bytes; out[bytes]=0; wipe(wide_input,INPUT_CAP*sizeof(WCHAR)); return 0;
fail:
    wipe(wide_input,INPUT_CAP*sizeof(WCHAR)); return -1;
}
double monotonic_seconds(void) { LARGE_INTEGER t,f; QueryPerformanceCounter(&t); QueryPerformanceFrequency(&f); return (double)t.QuadPart/f.QuadPart; }
void platform_shutdown(void) { terminal_leave(); locked_free(wide_input,INPUT_CAP*sizeof(WCHAR)); wide_input=NULL; if(saved_output_cp) SetConsoleOutputCP(saved_output_cp); }
