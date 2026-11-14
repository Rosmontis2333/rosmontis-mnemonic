#include "platform.h"
#include "sha2.h"
#include "wallet.h"
#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include "words.h"
#ifndef MEMORY_KIB
#define MEMORY_KIB (8U * 1024U * 1024U)
#endif
#ifndef TIME_COST
#define TIME_COST 32
#endif
static uint32_t memory_kib=MEMORY_KIB, iterations=TIME_COST, parallelism=8;
/* Settings are public, read before any secret or protected work is allocated. */
static int setting(const char *prompt,int fractional,double max,double *value) {
    char line[128];
    for(;;) {
        fputs(prompt,stdout);
        if(!fgets(line,sizeof(line),stdin))return 0;
        if(!strchr(line,'\n')) {
            int c;while((c=getchar())!='\n'&&c!=EOF){}
            if(c==EOF)return 0;
            puts("输入过长，请重新输入。");continue;
        }
        if(line[0]=='\n'||(line[0]=='\r'&&line[1]=='\n'))return 1;
        char *end;errno=0;double v=strtod(line,&end);
        while(*end==' '||*end=='\t'||*end=='\r'||*end=='\n')++end;
        if(errno||end==line||*end||!isfinite(v)||v<=0||v>max
           ||(!fractional&&v!=(double)(uint32_t)v)) {
            puts("请输入范围内的正数；次数和并行度必须是整数。");continue;
        }
        *value=v;return 1;
    }
}
static int configure(void) {
    puts("自定义 Argon2d 配置");
    for(;;) {
        double gb=(double)MEMORY_KIB/1048576.0,t=TIME_COST,p=8;
        if(!setting("内存大小 GB [8]（支持小数，最大 4095）：",1,4095,&gb)
           ||!setting("迭代次数 [32]（1～4294967295）：",0,4294967295.0,&t)
           ||!setting("并行度 [8]（1～256）：",0,256,&p))return 0;
        uint32_t m=(uint32_t)(gb*1048576.0);
        if(m<8*(uint32_t)p) {puts("内存不足：至少需要并行度 × 8 KiB，请重新设置。");continue;}
        memory_kib=m;iterations=(uint32_t)t;parallelism=(uint32_t)p;
        printf("实际配置：%.9g GiB（%u KiB），%u 次，并行度 %u。\n",
            (double)m/1048576.0,m,iterations,parallelism);
        return 1;
    }
}
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
    (void)argv; (void)argc;
    if(!terminal_is_interactive()) {
        fputs("请直接在交互式终端运行；不接受管道或重定向。\n",stderr); return 2;
    }
    arena_size=(size_t)memory_kib*1024;
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
        printf("阶段 2/3：Argon2d：%.9g GiB（%u KiB）、%u 次、并行度 %u\n",(double)memory_kib/1048576.0,memory_kib,iterations,parallelism); fflush(stdout);
        argon_start=monotonic_seconds();
        rosmontis_argon_progress(0, iterations);
        argon2_context ctx={0};
        ctx.out=derived; ctx.outlen=32; ctx.pwd=pre; ctx.pwdlen=32;
        ctx.salt=salt; ctx.saltlen=32;
        ctx.t_cost=iterations; ctx.m_cost=memory_kib; ctx.lanes=parallelism; ctx.threads=parallelism;
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
            wallet_public wallet;
            if(wallet_from_entropy(entropy,&wallet)) {
                puts("\nEVM 地址（m/44'/60'/0'/0/0）："); puts(wallet.evm);
                puts("\nBitcoin 主网 zpub（m/84'/0'/0'）："); puts(wallet.zpub);
                puts("\nBIP39 passphrase：空");
            } else { fputs("\n地址派生失败，未输出不完整结果。\n",stderr); code=1; }
            wipe(&wallet,sizeof(wallet));
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
    if(!terminal_is_interactive()) {
        fputs("请在交互式终端直接运行，不接受重定向。\n",stderr); return 2;
    }
    if(argc>1 && !configure())return 130;
    if(platform_init((size_t)memory_kib*1024)) {
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
