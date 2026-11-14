#include "platform.h"
#include "sha2.h"
#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "words.h"
#ifndef MEMORY_KIB
#define MEMORY_KIB (8U * 1024U * 1024U)
#endif
#ifndef TIME_COST
#define TIME_COST 32
#endif
static unsigned char *arena;
static size_t arena_size;
static char *inputs[1];
static int arena_busy;
static void emergency_clear(void) {
    for(int i=0;i<1;i++) if(inputs[i]) wipe(inputs[i],INPUT_CAP);
}
static double argon_start;
void rosmontis_argon_progress(uint32_t completed,uint32_t total) {
    printf("\r\033[2KArgon2d：%u/%u 轮（%6.2f%%） | 已用 %.1f 秒",completed,total,
        total?100.0*completed/total:0.0,monotonic_seconds()-argon_start);
}
static int argon_alloc(uint8_t **p,size_t n) {
    if(arena_busy || n>arena_size) return -1;
    arena_busy=1; *p=arena; return 0;
}
static void argon_free(uint8_t *p,size_t n) { wipe(p,n); arena_busy=0; }
static char *read_secret(const char *prompt,size_t *n,int slot) {
    fputs(prompt,stdout);
    char *s=inputs[slot];
    wipe(s,INPUT_CAP); *n=0;
    int rc=terminal_readline(s,INPUT_CAP,n);
    /* Clear the entire alternate screen, including wrapped input lines. */
    fputs("\033[2J\033[H",stdout);
    if(rc) { wipe(s,INPUT_CAP); return NULL; }
    return s;
}
static void rounds(const void *input,size_t len,unsigned char out[32]) {
    unsigned char tmp[64],next[64];
    sha512(input,len,tmp);
    for(int i=1;i<233;i++) { sha512(tmp,64,next); memcpy(tmp,next,64); }
    sha256(tmp,64,next); memcpy(tmp,next,32);
    for(int i=1;i<233;i++) { sha256(tmp,32,next); memcpy(tmp,next,32); }
    memcpy(out,tmp,32); wipe(tmp,64); wipe(next,64);
}
static int application(int argc,char **argv) {
    (void)argv;
    if(argc!=1 || !terminal_is_interactive()) {
        fputs("请直接在交互式终端运行；不接受参数、管道或重定向。\n",stderr); return 2;
    }
    arena_size=(size_t)MEMORY_KIB*1024;
    arena=locked_alloc(arena_size);
    inputs[0]=locked_alloc(INPUT_CAP);
    if(!arena || !inputs[0]) {
        fputs("无法锁定所需内存以阻止交换；已停止，未读取秘密。\n",stderr);
        return 1;
    }
    if(terminal_enter()) { fputs("无法设置安全交互终端，已停止。\n",stderr); return 2; }
    puts("Rosmontis 助记词生成器\n");
    size_t n=0; int code=0;
    char *a=read_secret("请输入字符串：",&n,0);
    if(!a) return 130;
    {
        unsigned char pre[32],salt[32],derived[32],entropy[32],check[32];
        puts("阶段 1/3：SHA-512 × 233 → SHA-256 × 233"); fflush(stdout);
        rounds(a,n,pre); sha256("rosmontis",9,salt);
        wipe(a,n);
        puts("阶段 2/3：正在计算（Argon2d：8 GiB、32 次、并行度 8）……"); fflush(stdout);
        argon_start=monotonic_seconds();
        rosmontis_argon_progress(0, TIME_COST);
        argon2_context ctx={0};
        ctx.out=derived; ctx.outlen=32; ctx.pwd=pre; ctx.pwdlen=32;
        ctx.salt=salt; ctx.saltlen=32;
        ctx.t_cost=TIME_COST; ctx.m_cost=MEMORY_KIB; ctx.lanes=8; ctx.threads=8;
        ctx.version=ARGON2_VERSION_13;
        ctx.allocate_cbk=argon_alloc; ctx.free_cbk=argon_free;
        ctx.flags=ARGON2_FLAG_CLEAR_PASSWORD;
        int rc=argon2_ctx(&ctx,Argon2_d);
        putchar('\n'); fflush(stdout);
        wipe(pre,32);
        if(rc!=ARGON2_OK) { fprintf(stderr,"计算失败：%s\n",argon2_error_message(rc)); code=1; }
        else {
            puts("阶段 3/3：SHA-512 × 233 → SHA-256 × 233 → BIP39"); fflush(stdout);
            rounds(derived,32,entropy); sha256(entropy,32,check);
            puts("\n24 个 BIP39 英文助记词：\n");
            for(int i=0;i<24;i++) {
                unsigned int index=0;
                for(int j=0;j<11;j++) {
                    int bit=i*11+j;
                    unsigned char byte=bit<256?entropy[bit/8]:check[0];
                    index=(index<<1)|((byte>>(7-bit%8))&1);
                }
                printf("%02d. %-9s%s",i+1,words[index],i%4==3?"\n":"  ");
            }
            wipe(entropy,32); wipe(check,32);
        }
        wipe(derived,32); wipe(salt,32);
    }
    wipe(a,INPUT_CAP);
    size_t k; char *end=read_secret("\n按回车清除屏幕并退出……",&k,0);
    if(end) wipe(end,INPUT_CAP);
    return code;
}

struct app_args { int argc; char **argv; };
static void *application_thread(void *p) {
    struct app_args *args=p;
    return (void *)(intptr_t)application(args->argc,args->argv);
}
int main(int argc,char **argv) {
    /* No stdio output buffer can retain printed mnemonic fragments. */
    setvbuf(stdout,NULL,_IONBF,0); setvbuf(stderr,NULL,_IONBF,0);
    if(argc!=1 || !terminal_is_interactive()) {
        fputs("请在交互式终端直接运行，不接受参数或重定向。\n",stderr); return 2;
    }
    if(platform_init((size_t)MEMORY_KIB*1024)) {
        fputs("无法启用内存锁定或崩溃转储防护；已停止，未读取秘密。\n",stderr); platform_shutdown(); return 1;
    }
    platform_set_emergency_cleanup(emergency_clear);
    secure_thread *tid; struct app_args args={argc,argv}; void *result=NULL;
    int rc=secure_thread_create(&tid,application_thread,&args);
    if(rc) { fputs("无法建立锁定的计算栈；已停止，未读取秘密。\n",stderr); platform_shutdown(); return 1; }
    rc=secure_thread_join(tid,&result);
    terminal_leave();
    locked_free(inputs[0],INPUT_CAP);
    locked_free(arena,arena_size);
    platform_shutdown();
    return rc ? 1 : (int)(intptr_t)result;
}
