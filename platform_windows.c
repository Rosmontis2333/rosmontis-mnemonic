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
    SYSTEM_INFO system; GetSystemInfo(&system);
    unsigned char marker=0;
    const char *stage="VirtualQuery";
    DWORD error=0;
    if(!VirtualQuery(&marker,&region,sizeof(region))) goto fail;
    unsigned char *base=region.AllocationBase,*end=base;
    /* VirtualQuery returns one protection region, not the whole stack. */
    for(;;) {
        MEMORY_BASIC_INFORMATION part;
        if(!VirtualQuery(end,&part,sizeof(part))) goto fail;
        if(part.AllocationBase!=base) break;
        if(!part.RegionSize || part.RegionSize>64U*1024U*1024U
           || (size_t)(end-base)>64U*1024U*1024U-part.RegionSize) {
            error=ERROR_INVALID_ADDRESS; goto fail;
        }
        end=(unsigned char *)part.BaseAddress+part.RegionSize;
    }
    unsigned char *low=base+system.dwPageSize;
    size_t bytes=(size_t)(end-low);
    if(bytes<STACK_BYTES/2) { error=ERROR_BAD_LENGTH; goto fail; }
    /* Keep the lowest page inaccessible. Commit all usable pages before any
       secrets enter, so later stack growth cannot create unlocked pages. */
    stage="VirtualAlloc(stack commit)";
    if(!VirtualAlloc(low,bytes,MEM_COMMIT,PAGE_READWRITE)) goto fail;
    DWORD previous;
    stage="VirtualProtect(stack)";
    if(!VirtualProtect(low,bytes,PAGE_READWRITE,&previous)) goto fail;
    stage="VirtualLock(stack)";
    if(!VirtualLock(low,bytes)) goto fail;
    t->stack=low; t->stack_size=bytes;
    SetEvent(t->ready);
    t->result=t->fn(t->arg);
    SwitchToFiber(t->supervisor);
    return;
fail:
    if(!error) error=GetLastError();
    fprintf(stderr,"Secure stack initialization failed: %s, Windows error=%lu\n",stage,(unsigned long)error);
    t->startup_error=1; SetEvent(t->ready); SwitchToFiber(t->supervisor);
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
    if(!SetConsoleMode(input_handle,saved_input|ENABLE_LINE_INPUT|ENABLE_PROCESSED_INPUT|ENABLE_ECHO_INPUT)) return -1;
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
